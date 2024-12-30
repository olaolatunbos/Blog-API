from datetime import datetime, timedelta, timezone
from typing import Annotated, List
import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select, Relationship


SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


#------------------------------------------------------------
#                  Database Configuration
#------------------------------------------------------------

class AuthorizedUser(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    full_name: str = Field(unique=True)
    email: str = Field(unique=True)
    hashed_password: str = Field()
    disabled: bool = Field(default=False)


class PostBase(SQLModel):
    title: str = Field(index=True, unique=True)
    content: str = Field()

class Post(PostBase, table=True):
    id: int = Field(default=None, primary_key=True)
    author_id: int = Field(index=True, foreign_key="authorizeduser.id") 
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"onupdate": datetime.utcnow})
    comments: List["Comment"] = Relationship(back_populates="post")

class PostUpdate(PostBase):
    title: str | None = None
    content: str | None = None

class PostPublic(PostBase):
    id: int

class CommentBase(SQLModel):
    content: str

class Comment(CommentBase, table=True):
    id: int = Field(default=None, primary_key=True)
    post_id: int = Field(foreign_key="post.id", index=True)
    author_id: int = Field(foreign_key="authorizeduser.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationship to the post
    post: Post = Relationship(back_populates="comments")

class CommentPublic(CommentBase):
    id: int

postgres_url = "postgresql://postgres:olaolat@localhost:5432/olaolatunbosun"

engine = create_engine(postgres_url)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


#------------------------------------------------------------
#                       Models
#------------------------------------------------------------

class User(BaseModel):
    id: int
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

#------------------------------------------------------------
#                       Auth Functions
#------------------------------------------------------------

def get_users_as_dict():
    with Session(engine) as session:
        users = session.exec(select(AuthorizedUser).offset(0).limit(10)).all()
        users_dict = {
            user.username: {
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name,
                "email": user.email,
                "hashed_password": user.hashed_password,
                "disabled": user.disabled,
            }
            for user in users
        }
        return users_dict


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
    token_data = TokenData(username=username)
    user = get_user(get_users_as_dict(), username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


#------------------------------------------------------------
#                  Authentication Endpoints
#------------------------------------------------------------
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(get_users_as_dict(), form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

#------------------------------------------------------------
#                   Blog Post Endpoints
#------------------------------------------------------------


#CREATE POST
@app.post("/posts", response_model=PostPublic)
def create_post(current_user: Annotated[User, Depends(get_current_active_user)], post: PostBase, session: SessionDep) -> Post:
    db_post = Post(**post.dict(), author_id=current_user.id)
    session.add(db_post)
    session.commit()
    session.refresh(db_post)
    return db_post

#READ ALL POSTS
@app.get("/posts",  response_model=list[PostPublic])
async def read_posts(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    posts = session.exec(select(Post).offset(offset).limit(limit)).all()
    return posts

#READ POST
@app.get("/posts/{post_id}", response_model=PostPublic)
async def read_post(current_user: Annotated[User, Depends(get_current_active_user)], post_id: int, session: SessionDep):
    post = session.get(Post, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return post


#UPDATE POST
@app.patch("/posts/{post_id}", response_model=PostPublic)
def update_post(post_id: int, hero: PostUpdate, session: SessionDep):
    post_db = session.get(Post, post_id)
    if not post_db:
        raise HTTPException(status_code=404, detail="Hero not found")
    post_data = hero.model_dump(exclude_unset=True)
    post_db.sqlmodel_update(post_data)
    session.add(post_db)
    session.commit()
    session.refresh(post_db)
    return post_db

#DELETE POST
@app.delete("/posts/{post_id}")
def delete_hero(post_id: int, session: SessionDep):
    post = session.get(Post, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Hero not found")
    session.delete(post)
    session.commit()
    return {"ok": True}

#CREATE POST COMMENT
@app.post("/posts/{post_id}/comments", response_model=CommentPublic)
async def create_comment(current_user: Annotated[User, Depends(get_current_active_user)], post_id: int, comment: CommentBase, session: SessionDep):
    post = session.exec(select(Post).where(Post.id == post_id)).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Create the comment
    db_comment = Comment(post_id=post_id, author_id=current_user.id, content=comment.content)
    session.add(db_comment)
    session.commit()
    session.refresh(db_comment)
    return db_comment

#READ POST COMMENTS
@app.get("/posts/{post_id}/comments/", response_model=List[CommentPublic])
async def get_comments(post_id: int, session: SessionDep):
    comments = session.exec(select(Comment).where(Comment.post_id == post_id)).all()
    return comments


import os
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship


DATABASE_URL = os.getenv("DATABASE_URL", "database_url_here")  # Replace with your actual database URL

SECRET_KEY = os.getenv("SECRET_KEY", "secret_key_here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Database Setup ---

# SQLAlchemy Engine
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Dependency to get database session
def get_db():
    """Provides a database session to API endpoints."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- SQLAlchemy Models ---

class User(Base):
    """SQLAlchemy model for the 'users' table."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    # Role can be 'admin' or 'regular'
    role = Column(String, default="regular")
    is_active = Column(Boolean, default=True)

    tasks = relationship("Task", back_populates="owner")

class Task(Base):
    """SQLAlchemy model for the 'tasks' table."""
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="tasks")

# Create database tables (run this once when setting up your database)
# Base.metadata.create_all(bind=engine)
# Note: For production, use database migrations (e.g., Alembic)

# --- Pydantic Schemas ---

class UserBase(BaseModel):
    """Base Pydantic model for User."""
    username: str

class UserCreate(UserBase):
    """Pydantic model for creating a User."""
    password: str
    # Role is typically not set by the user during creation in a real app,
    # but for this example, we'll allow it for demonstration.
    # In a production app, roles would be assigned by an admin.
    role: Optional[str] = "regular"

class UserInDB(UserBase):
    """Pydantic model for User data retrieved from the database."""
    id: int
    role: str
    is_active: bool

    class Config:
        orm_mode = True # Enable ORM mode for automatic mapping

class TaskBase(BaseModel):
    """Base Pydantic model for Task."""
    title: str
    description: Optional[str] = None

class TaskCreate(TaskBase):
    """Pydantic model for creating a Task."""
    pass

class TaskUpdate(TaskBase):
    """Pydantic model for updating a Task."""
    pass

class TaskInDB(TaskBase):
    """Pydantic model for Task data retrieved from the database."""
    id: int
    owner_id: int

    class Config:
        orm_mode = True

class Token(BaseModel):
    """Pydantic model for JWT token response."""
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    """Pydantic model for data contained within a JWT token."""
    username: Optional[str] = None
    role: Optional[str] = None

# --- Security/Authentication Utilities ---

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashes a plain password."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- CRUD Operations for Users ---

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Retrieves a user by username from the database."""
    return db.query(User).filter(User.username == username).first()

def create_user(db: Session, user: UserCreate) -> User:
    """Creates a new user in the database."""
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password, role=user.role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# --- CRUD Operations for Tasks ---

def get_task(db: Session, task_id: int) -> Optional[Task]:
    """Retrieves a single task by ID."""
    return db.query(Task).filter(Task.id == task_id).first()

def get_tasks(db: Session, owner_id: Optional[int] = None) -> List[Task]:
    """Retrieves a list of tasks, optionally filtered by owner_id."""
    query = db.query(Task)
    if owner_id:
        query = query.filter(Task.owner_id == owner_id)
    return query.all()

def create_user_task(db: Session, task: TaskCreate, owner_id: int) -> Task:
    """Creates a new task for a specific user."""
    db_task = Task(**task.dict(), owner_id=owner_id)
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

def update_task(db: Session, db_task: Task, task_update: TaskUpdate) -> Task:
    """Updates an existing task."""
    task_data = task_update.dict(exclude_unset=True)
    for key, value in task_data.items():
        setattr(db_task, key, value)
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

def delete_task(db: Session, db_task: Task):
    """Deletes a task from the database."""
    db.delete(db_task)
    db.commit()

# --- Authentication and Authorization Dependencies ---

async def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticates a user by username and password."""
    user = get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Retrieves the current authenticated user based on the JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_role: str = payload.get("role")
        if username is None or user_role is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=user_role)
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user

async def get_current_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to ensure the current user is an admin."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation forbidden for this role. Admin access required."
        )
    return current_user

async def get_current_owner_or_admin(task_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Task:
    """Dependency to ensure the current user is either the task owner or an admin."""
    task = get_task(db, task_id=task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    if current_user.role == "admin":
        return task # Admin can access any task

    if task.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action on this task. You are not the owner."
        )
    return task

# --- FastAPI Application ---

app = FastAPI(
    title="Task Management API",
    description="A simple Task Management API with Role-Based Access Control and JWT Authentication.",
    version="1.0.0",
)

# --- API Endpoints ---

@app.on_event("startup")
async def startup_event():
    """Event handler for application startup."""
    print("Creating database tables if they don't exist...")
    # This creates tables based on SQLAlchemy models.
    # In a real-world scenario, use Alembic for migrations.
    Base.metadata.create_all(bind=engine)
    print("Database tables created (if they didn't exist).")

@app.post("/token", response_model=Token, summary="Authenticate user and get JWT token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Authenticates a user with username and password, then returns a JWT access token.
    """
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/", response_model=UserInDB, status_code=status.HTTP_201_CREATED, summary="Register a new regular user")
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Registers a new user. Default role is 'regular'.
    """
    db_user = get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    # For a real application, role assignment should be managed by an admin or
    # have specific registration flows for different roles.
    # Here, we enforce 'regular' role for new registrations for simplicity.
    if user.role != "regular":
        print(f"Warning: User '{user.username}' attempted to register with role '{user.role}'. Forcing 'regular'.")
        user.role = "regular" # Enforce regular role for public registration
    return create_user(db=db, user=user)

@app.get("/users/me/", response_model=UserInDB, summary="Get current authenticated user's details")
async def read_users_me(current_user: User = Depends(get_current_user)):
    """
    Retrieves details of the currently authenticated user.
    """
    return current_user

@app.get("/tasks", response_model=List[TaskInDB], summary="Fetch a list of tasks")
async def read_tasks(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Fetches a list of tasks.
    - Admin users can see all tasks.
    - Regular users can only see tasks assigned to them.
    """
    if current_user.role == "admin":
        tasks = get_tasks(db)
    else:
        tasks = get_tasks(db, owner_id=current_user.id)
    return tasks

@app.post("/tasks", response_model=TaskInDB, status_code=status.HTTP_201_CREATED, summary="Create a new task (Admin only)")
async def create_task(task: TaskCreate, current_user: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    """
    Creates a new task. Only allowed for admin users.
    The task's owner will be the admin user who created it.
    """
    return create_user_task(db=db, task=task, owner_id=current_user.id)

@app.put("/tasks/{task_id}", response_model=TaskInDB, summary="Update an existing task (Owner or Admin)")
async def update_single_task(
    task_id: int,
    task_update: TaskUpdate,
    db_task: Task = Depends(get_current_owner_or_admin), # Dependency ensures ownership/admin status
    db: Session = Depends(get_db)
):
    """
    Updates an existing task. Only allowed for the user who created the task or an admin.
    """
    return update_task(db=db, db_task=db_task, task_update=task_update)

@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a task (Admin only)")
async def delete_single_task(
    task_id: int,
    current_user: User = Depends(get_current_admin_user), # Only admin can delete
    db: Session = Depends(get_db)
):
    """
    Deletes a task. Only allowed for admin users.
    """
    task_to_delete = get_task(db, task_id=task_id)
    if not task_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    delete_task(db=db, db_task=task_to_delete)
    # No content to return for 204
    return


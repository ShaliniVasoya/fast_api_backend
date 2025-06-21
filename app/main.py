from typing import List
from fastapi import Depends, FastAPI, HTTPException, status

from database import Base, engine, get_db_session
import crud
from schemas import UserCreateSchema, UserDBSchema, TokenSchema, TaskCreateSchema, TaskDBSchema, TaskUpdateSchema
from auth import simple_authenticate_user, get_current_active_user, require_admin_role, require_owner_or_admin_for_task
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from config import TOKEN_EXPIRE_MINUTES

app = FastAPI(
    title="Basic Task Manager API",
    description="A simplified FastAPI app for managing tasks with user roles and JWT.",
    version="0.0.1",
)

@app.on_event("startup")
async def startup_db_create_tables():
    print("Attempting to create database tables if they don't exist...")
    Base.metadata.create_all(bind=engine)
    print("Database tables creation process completed.")

@app.post("/token", response_model=TokenSchema, summary="Authenticate user and get JWT token")
async def handle_user_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db_session)):
    user = await simple_authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token_expiry = timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    access_token = crud.auth.make_access_token(
        data_for_token={"sub": user.username, "role": user.role}, expires_delta_val=token_expiry
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/", response_model=UserDBSchema, status_code=status.HTTP_201_CREATED, summary="Register a new regular user")
async def register_new_user(user_data_in: UserCreateSchema, db: Session = Depends(get_db_session)):
    existing_user = crud.get_user_by_name(db, username_str=user_data_in.username)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    user_data_in.role = "regular"
    created_user = crud.create_new_user(db=db, user_data=user_data_in)
    return created_user

@app.get("/users/me/", response_model=UserDBSchema, summary="Get current authenticated user's details")
async def get_my_user_details(current_logged_in_user: crud.auth.User = Depends(get_current_active_user)):
    return current_logged_in_user

@app.get("/tasks", response_model=List[TaskDBSchema], summary="Fetch tasks (admin sees all, regular users see own)")
async def fetch_tasks_list(current_logged_in_user: crud.auth.User = Depends(get_current_active_user), db: Session = Depends(get_db_session)):
    if current_logged_in_user.role == "admin":
        tasks = crud.get_all_tasks(db)
    else:
        tasks = crud.get_all_tasks(db, owner_id_num=current_logged_in_user.id)
    return tasks

@app.post("/tasks", response_model=TaskDBSchema, status_code=status.HTTP_201_CREATED, summary="Create a new task (Admin only)")
async def create_a_task(task_data_in: TaskCreateSchema, admin_user: crud.auth.User = Depends(require_admin_role), db: Session = Depends(get_db_session)):
    created_task = crud.create_task_for_user(db=db, task_data=task_data_in, user_id=admin_user.id)
    return created_task

@app.put("/tasks/{task_id}", response_model=TaskDBSchema, summary="Update an existing task (Owner or Admin)")
async def update_a_task(
    task_id: int,
    task_update_data: TaskUpdateSchema,
    task_to_update: crud.auth.Task = Depends(require_owner_or_admin_for_task),
    db: Session = Depends(get_db_session)
):
    updated_task = crud.update_existing_task(db=db, task_in_db=task_to_update, update_data=task_update_data)
    return updated_task

@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a task (Admin only)")
async def delete_a_task(
    task_id: int,
    admin_user: crud.auth.User = Depends(require_admin_role),
    db: Session = Depends(get_db_session)
):
    task_to_delete = crud.get_single_task(db, task_id_num=task_id)
    if not task_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found for deletion.")
    crud.delete_task_from_db(db=db, task_to_delete=task_to_delete)
    return

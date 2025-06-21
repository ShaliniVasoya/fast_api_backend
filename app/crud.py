from typing import List, Optional
from sqlalchemy.orm import Session

from models import User, Task
from schemas import UserCreateSchema, TaskCreateSchema, TaskUpdateSchema
from auth import hash_password

def get_user_by_name(db: Session, username_str: str) -> Optional[User]:
    return db.query(User).filter(User.username == username_str).first()

def create_new_user(db: Session, user_data: UserCreateSchema) -> User:
    hashed_pw = hash_password(user_data.password)
    new_user = User(username=user_data.username, hashed_password=hashed_pw, role=user_data.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def get_single_task(db: Session, task_id_num: int) -> Optional[Task]:
    return db.query(Task).filter(Task.id == task_id_num).first()

def get_all_tasks(db: Session, owner_id_num: Optional[int] = None) -> List[Task]:
    query_result = db.query(Task)
    if owner_id_num:
        query_result = query_result.filter(Task.owner_id == owner_id_num)
    return query_result.all()

def create_task_for_user(db: Session, task_data: TaskCreateSchema, user_id: int) -> Task:
    new_task = Task(**task_data.dict(), owner_id=user_id)
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    return new_task

def update_existing_task(db: Session, task_in_db: Task, update_data: TaskUpdateSchema) -> Task:
    for key, value in update_data.dict(exclude_unset=True).items():
        setattr(task_in_db, key, value)
    db.add(task_in_db)
    db.commit()
    db.refresh(task_in_db)
    return task_in_db

def delete_task_from_db(db: Session, task_to_delete: Task):
    db.delete(task_to_delete)
    db.commit()

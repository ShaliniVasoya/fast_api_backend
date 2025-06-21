# auth.py

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from config import SECRET_JWT_KEY, ALGORITHM_TYPE, TOKEN_EXPIRE_MINUTES
from database import get_db_session
from models import User, Task # Added Task here
from schemas import TokenDataSchema
import crud

pwd_context_basic = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme_basic = OAuth2PasswordBearer(tokenUrl="token")

def check_password(plain_pw: str, hashed_pw: str) -> bool:
    return pwd_context_basic.verify(plain_pw, hashed_pw)

def hash_password(pw: str) -> str:
    return pwd_context_basic.hash(pw)

def make_access_token(data_for_token: dict, expires_delta_val: Optional[timedelta] = None) -> str:
    data_to_encode = data_for_token.copy()

    if expires_delta_val:
        expire_time = datetime.utcnow() + expires_delta_val
    else:
        expire_time = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)

    data_to_encode.update({"exp": expire_time})

    encoded_jwt = jwt.encode(data_to_encode, SECRET_JWT_KEY, algorithm=ALGORITHM_TYPE)
    return encoded_jwt

async def simple_authenticate_user(db: Session, user_name: str, pw: str) -> Optional[User]:
    user = crud.get_user_by_name(db, user_name)
    if not user or not check_password(pw, user.hashed_password):
        return None
    return user

async def get_current_active_user(token_str: str = Depends(oauth2_scheme_basic), db_session: Session = Depends(get_db_session)) -> User:
    cred_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials for current user",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token_str, SECRET_JWT_KEY, algorithms=[ALGORITHM_TYPE])
        user_name_from_token: str = payload.get("sub")
        user_role_from_token: str = payload.get("role")
        if user_name_from_token is None or user_role_from_token is None:
            raise cred_exception
        token_info = TokenDataSchema(username=user_name_from_token, role=user_role_from_token)
    except JWTError:
        raise cred_exception

    user_from_db = crud.get_user_by_name(db_session, username_str=token_info.username)
    if user_from_db is None or not user_from_db.is_active:
        raise cred_exception
    return user_from_db

async def require_admin_role(current_user_obj: User = Depends(get_current_active_user)) -> User:
    if current_user_obj.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Only admin users can do this."
        )
    return current_user_obj

async def require_owner_or_admin_for_task(task_id_param: int, current_user_obj: User = Depends(get_current_active_user), db_session: Session = Depends(get_db_session)) -> Task:
    task_found = crud.get_single_task(db_session, task_id_num=task_id_param)
    if not task_found:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found.")

    if current_user_obj.role == "admin":
        return task_found

    if task_found.owner_id != current_user_obj.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only manage your own tasks."
        )
    return task_found

from typing import List, Optional
from pydantic import BaseModel, Field

class UserBaseSchema(BaseModel):
    username: str

class UserCreateSchema(UserBaseSchema):
    password: str
    role: Optional[str] = "regular"

class UserDBSchema(UserBaseSchema):
    id: int
    role: str
    is_active: bool

    class Config:
        from_attributes = True

class TaskBaseSchema(BaseModel):
    title: str
    description: Optional[str] = None

class TaskCreateSchema(TaskBaseSchema):
    pass

class TaskUpdateSchema(TaskBaseSchema):
    pass

class TaskDBSchema(TaskBaseSchema):
    id: int
    owner_id: int

    class Config:
        from_attributes = True

class TokenSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenDataSchema(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

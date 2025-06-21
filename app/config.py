# config.py
import os
DB_URL = os.getenv("DATABASE_URL", "database_url")
SECRET_JWT_KEY = os.getenv("SECRET_KEY", "secret_jwt_key")
ALGORITHM_TYPE = "HS256"
TOKEN_EXPIRE_MINUTES = 30

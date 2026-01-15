from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from typing import Optional, List
from jose import JWTError, jwt
from functools import lru_cache
import uvicorn
import bcrypt
import os
from dotenv import load_dotenv

  
# ENVIRONMENT
  
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./employees.db")

  
# DATABASE
  
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

  
# SECURITY
  
security = HTTPBearer()

  
# APP
  
app = FastAPI(title="Employee Management API")

  
# SCHEMAS
  
class User(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class EmployeeBase(BaseModel):
    name: str = Field(..., min_length=1)
    email: EmailStr
    department: Optional[str] = None
    role: Optional[str] = None

class EmployeeCreate(EmployeeBase):
    pass

class Employee(EmployeeBase):
    id: int
    date_joined: datetime

    class Config:
        from_attributes = True

class EmployeeUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1)
    email: Optional[EmailStr] = None
    department: Optional[str] = None
    role: Optional[str] = None

  
# DB MODELS
  
class DBEmployee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    department = Column(String)
    role = Column(String)
    date_joined = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

  
# UTILS
  
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    return bcrypt.hashpw(pwd_bytes, bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    pwd_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(pwd_bytes, hashed_bytes)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

  
# ADMIN USER (CREATED ONCE)
  
@lru_cache
def get_admin_user():
    return {
        "username": "admin",
        "hashed_password": get_password_hash("secret")
    }

  
# AUTH DEPENDENCY
  
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        username = payload.get("sub")
        if username != "admin":
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    return username

  
# AUTH ENDPOINT
  
@app.post("/api/auth/login", response_model=Token)
def login(user: User):
    admin = get_admin_user()

    if (
        user.username != admin["username"]
        or not verify_password(user.password, admin["hashed_password"])
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

  
# EMPLOYEE ENDPOINTS
  
@app.post("/api/employees/", response_model=Employee, status_code=201)
def create_employee(
    employee: EmployeeCreate,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if db.query(DBEmployee).filter(DBEmployee.email == employee.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    db_employee = DBEmployee(
        **employee.dict(),
        date_joined=datetime.utcnow()
    )
    db.add(db_employee)
    db.commit()
    db.refresh(db_employee)
    return db_employee

@app.get("/api/employees/", response_model=List[Employee])
def list_employees(
    department: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(DBEmployee)

    if department:
        query = query.filter(DBEmployee.department == department)
    if role:
        query = query.filter(DBEmployee.role == role)

    return query.offset((page - 1) * 10).limit(10).all()

@app.get("/api/employees/{id}/", response_model=Employee)
def get_employee(
    id: int,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    employee = db.query(DBEmployee).filter(DBEmployee.id == id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    return employee

@app.put("/api/employees/{id}/", response_model=Employee)
def update_employee(
    id: int,
    employee: EmployeeUpdate,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_employee = db.query(DBEmployee).filter(DBEmployee.id == id).first()
    if not db_employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    update_data = employee.dict(exclude_unset=True)

    if "email" in update_data:
        existing = db.query(DBEmployee).filter(
            DBEmployee.email == update_data["email"],
            DBEmployee.id != id
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")

    for key, value in update_data.items():
        setattr(db_employee, key, value)

    db.commit()
    db.refresh(db_employee)
    return db_employee

@app.delete("/api/employees/{id}/", status_code=204)
def delete_employee(
    id: int,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    employee = db.query(DBEmployee).filter(DBEmployee.id == id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    db.delete(employee)
    db.commit()
    return None

@app.get("/")
def root():
    return {"message": "Employee Management API", "docs": "/docs"}

# RUN 
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
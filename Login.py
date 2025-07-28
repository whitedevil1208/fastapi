import os
import uuid
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv

# Load env variables
load_dotenv()

# App & Middleware
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

# Config
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# Database
Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Models
class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_verified = Column(Boolean, default=False)
    verification_code = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# Schemas
class RegisterModel(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginModel(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class EmailVerifyModel(BaseModel):
    email: EmailStr
    code: str

class ResetPasswordModel(BaseModel):
    email: EmailStr
    new_password: str

# Utils
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)

def create_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(UserTable).filter(UserTable.username == username).first()
        if not user or not user.is_verified:
            raise HTTPException(status_code=403, detail="Account not verified")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def send_email_verification(email: str, code: str):
    message = EmailMessage()
    message["Subject"] = "LUVA Email Verification Code"
    message["From"] = SMTP_EMAIL
    message["To"] = email
    message.set_content(f"Your verification code is: {code}")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
        smtp.send_message(message)

# Routes
@app.post("/register")
def register(data: RegisterModel, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if db.query(UserTable).filter((UserTable.username == data.username) | (UserTable.email == data.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    hashed_password = get_password_hash(data.password)
    code = str(uuid.uuid4())[:6]
    user = UserTable(username=data.username, email=data.email, hashed_password=hashed_password, verification_code=code)
    db.add(user)
    db.commit()
    background_tasks.add_task(send_email_verification, data.email, code)
    return {"message": "User registered successfully. Check your email for the verification code."}

@app.post("/verify-email")
def verify_email(data: EmailVerifyModel, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.email == data.email).first()
    if not user or user.verification_code != data.code:
        raise HTTPException(status_code=400, detail="Invalid verification code")
    user.is_verified = True
    user.verification_code = None
    db.commit()
    return {"message": "Email verified successfully."}

@app.post("/login", response_model=Token)
def login(data: LoginModel, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.username == data.username).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Account not verified")
    token = create_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/reset-password")
def reset_password(data: ResetPasswordModel, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = get_password_hash(data.new_password)
    db.commit()
    return {"message": "Password reset successful."}

@app.get("/me")
def get_profile(current_user: UserTable = Depends(get_current_user)):
    return {"username": current_user.username, "email": current_user.email}

import os
import io
import base64
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from PIL import Image

# Minimal database and user setup for protected endpoints:
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta

load_dotenv()
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# FastAPI app and CORS
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

# Database (sqlite for testing)
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    stripe_customer_id = Column(String, unique=True, nullable=True)
    stripe_subscription_status = Column(String, default="inactive")
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def get_password_hash(password): return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db, email: str):
    return db.query(User).filter(User.email == email).first()

def get_current_user(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, email=email)
    if user is None:
        raise credentials_exception
    return user

@app.get("/")
def root():
    return {"message": "Pokanalyzer API is running."}

@app.get("/hello")
def hello():
    return {"hello": "world"}

# ====== TEST UPLOAD ENDPOINT FOR DEBUGGING ======
@app.post("/test-upload")
async def test_upload(file: UploadFile = File(...)):
    """Debug endpoint: Accepts a file and returns its name and size."""
    data = await file.read()
    return {"filename": file.filename, "size": len(data)}

# ====== (Optional) Your old /analyze endpoint for reference ======
# @app.post("/analyze")
# async def analyze(
#     file: UploadFile = File(...),
#     strategy: str = Form(...),
#     players: int = Form(...),
#     current_user: User = Depends(get_current_user)
# ):
#     image_data = await file.read()
#     try:
#         image = Image.open(io.BytesIO(image_data))
#     except Exception:
#         raise HTTPException(status_code=400, detail="Invalid image file.")
#     b64_image = base64.b64encode(image_data).decode()
#     # ... rest of your OpenAI code here ...
#     return {"advice": "OpenAI call would go here"}

# ====== Simple register/login endpoints for token testing ======
@app.post("/register")
def register(email: str = Form(...), password: str = Form(...), db: SessionLocal = Depends(get_db)):
    user = get_user(db, email)
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = get_password_hash(password)
    new_user = User(email=email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "User registered!"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)):
    user = get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}


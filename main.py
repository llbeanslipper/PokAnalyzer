import os
import openai
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from PIL import Image
import base64
import io

# === User Auth Imports ===
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta

# === ENV SETUP ===
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

# === FastAPI Setup ===
app = FastAPI()

# CORS (so your frontend can call this API from anywhere)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # For production, set to your frontend’s domain!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === DATABASE SETUP ===
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === PASSWORD & JWT SETUP ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "supersecretkey"  # CHANGE THIS to something random in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

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

# === USER ENDPOINTS ===

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

# === PROTECTED ANALYZE ENDPOINT ===

@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    strategy: str = Form(...),
    players: int = Form(...),
    current_user: User = Depends(get_current_user)
):
    image_data = await file.read()
    try:
        image = Image.open(io.BytesIO(image_data))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image file.")

    b64_image = base64.b64encode(image_data).decode()

    prompt = (
        "You are an expert poker assistant. "
        "Analyze the provided image of a poker table. Extract my hole cards, suits, community cards, stack sizes, bet amounts, and table situation. "import os
import openai
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from PIL import Image
import base64
import io

# === User Auth Imports ===
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta

# === ENV SETUP ===
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

# === FastAPI Setup ===
app = FastAPI()

# Add a root endpoint so "/" works!
@app.get("/")
def root():
    return {"message": "PokAnalyzer backend is running!"}

# CORS (so your frontend can call this API from anywhere)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # For production, set to your frontend’s domain!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === DATABASE SETUP ===
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === PASSWORD & JWT SETUP ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "supersecretkey"  # CHANGE THIS to something random in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

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

# === USER ENDPOINTS ===

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

# === PROTECTED ANALYZE ENDPOINT ===

@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    strategy: str = Form(...),
    players: int = Form(...),
    current_user: User = Depends(get_current_user)
):
    image_data = await file.read()
    try:
        image = Image.open(io.BytesIO(image_data))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image file.")

    b64_image = base64.b64encode(image_data).decode()

    prompt = (
        "You are an expert poker assistant. "
        "Analyze the provided image of a poker table. Extract my hole cards, suits, community cards, stack sizes, bet amounts, and table situation. "
        "Always respond in the following format:\n"
        "- Decision: [e.g., FOLD, BET $500, SHOVE ALL IN]\n"
        "- Win %: [Give your best estimate, always a number]\n"
        "- My Cards: [e.g., Ace of Spades, King of Diamonds, etc.]\n"
        "- Reasoning: [Concise explanation.]\n"
        f"Adjust advice based on the selected strategy: {strategy}. "
        f"Assume {players} players at the table. "
        "If the image is unclear, make your best guess and say so in the reasoning, but ALWAYS give a decision and win %."
    )

    try:
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": [
                    {"type": "text", "text": "What do I do here?"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64," + b64_image}}
                ]}
            ],
            max_tokens=512,
        )
        answer = response.choices[0].message.content.strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"advice": answer}

        "Always respond in the following format:\n"
        "- Decision: [e.g., FOLD, BET $500, SHOVE ALL IN]\n"
        "- Win %: [Give your best estimate, always a number]\n"
        "- My Cards: [e.g., Ace of Spades, King of Diamonds, etc.]\n"
        "- Reasoning: [Concise explanation.]\n"
        f"Adjust advice based on the selected strategy: {strategy}. "
        f"Assume {players} players at the table. "
        "If the image is unclear, make your best guess and say so in the reasoning, but ALWAYS give a decision and win %."
    )

    try:
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": [
                    {"type": "text", "text": "What do I do here?"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64," + b64_image}}
                ]}
            ],
            max_tokens=512,
        )
        answer = response.choices[0].message.content.strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"advice": answer}

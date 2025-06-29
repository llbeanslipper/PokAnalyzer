import os
from fastapi import FastAPI, Depends, HTTPException, status, Form, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta

# ---- In-memory "DB" for demo ----
fake_users_db = {}

# ---- Security Setup ----
SECRET_KEY = "your-very-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ---- FastAPI App ----
app = FastAPI(
    title="PokAnalyzer API",
    description="Demo API with working JWT OAuth2 in Swagger UI",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# ---- Models ----
class User(BaseModel):
    username: str
    hashed_password: str
    is_active: bool = True
    subscription_active: bool = True  # Simulate subscription

def get_user(username: str):
    return fake_users_db.get(username)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user['hashed_password']):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

def require_subscription(user: dict = Depends(get_current_user)):
    if not user.get('subscription_active'):
        raise HTTPException(status_code=402, detail="Active subscription required.")
    return user

# ---- Endpoints ----

@app.post("/register")
def register(username: str = Form(...), password: str = Form(...)):
    if username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    fake_users_db[username] = {
        "username": username,
        "hashed_password": get_password_hash(password),
        "is_active": True,
        "subscription_active": True,
    }
    return {"msg": "User registered!"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(
        data={"sub": user['username']},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/analyze")
def analyze(
    file: UploadFile = File(...),
    strategy: str = Form(...),
    players: int = Form(...),
    user: dict = Depends(require_subscription)
):
    # Dummy logic for demo
    return {
        "decision": "FOLD",
        "win_pct": 20.0,
        "my_cards": "Ace of Spades, King of Diamonds",
        "reasoning": f"Example advice for {players} players and strategy {strategy}.",
        "user": user['username']
    }

@app.get("/")
def root():
    return {"message": "API running"}

@app.get("/hello")
def hello():
    return {"hello": "world"}


import os
import stripe
import openai
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# === FastAPI Setup ===
app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    stripe_customer_id = Column(String, unique=True, nullable=True)
    stripe_subscription_status = Column(String, default="inactive")  # "active" or "inactive"

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === PASSWORD & JWT SETUP ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "supersecretkey"  # Change for production!
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

def get_user_by_customer_id(db, customer_id: str):
    return db.query(User).filter(User.stripe_customer_id == customer_id).first()

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

# === STRIPE PAYMENT ENDPOINTS ===

@app.post("/create-checkout-session")
def create_checkout_session(db: SessionLocal = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Create a customer in Stripe if not already present
    if not current_user.stripe_customer_id:
        customer = stripe.Customer.create(email=current_user.email)
        current_user.stripe_customer_id = customer["id"]
        db.commit()

    checkout_session = stripe.checkout.Session.create(
        customer=current_user.stripe_customer_id,
        payment_method_types=["card"],
        line_items=[{
            "price": STRIPE_PRICE_ID,
            "quantity": 1,
        }],
        mode="subscription",
        success_url="https://yourfrontend.com/success",  # Update these URLs
        cancel_url="https://yourfrontend.com/cancel",
    )
    return {"checkout_url": checkout_session.url}

@app.post("/webhook")
async def stripe_webhook(request: Request, db: SessionLocal = Depends(get_db)):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        # Invalid payload
        return JSONResponse(status_code=400, content={"error": "Invalid payload"})
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return JSONResponse(status_code=400, content={"error": "Invalid signature"})

    # Handle subscription events
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        customer_id = session.get("customer")
        if customer_id:
            user = get_user_by_customer_id(db, customer_id)
            if user:
                user.stripe_subscription_status = "active"
                db.commit()
    elif event["type"] == "customer.subscription.deleted":
        subscription = event["data"]["object"]
        customer_id = subscription.get("customer")
        if customer_id:
            user = get_user_by_customer_id(db, customer_id)
            if user:
                user.stripe_subscription_status = "inactive"
                db.commit()
    # Add other events as needed
    return {"status": "success"}

# === PAYWALL DECORATOR ===

def require_active_subscription(user: User = Depends(get_current_user)):
    if user.stripe_subscription_status != "active":
        raise HTTPException(status_code=402, detail="Active subscription required.")
    return user

# === PROTECTED ANALYZE ENDPOINT ===

@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    strategy: str = Form(...),
    players: str = Form(...),  # <-- CHANGED FROM int TO str
    current_user: User = Depends(require_active_subscription)
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

# === TEST ENDPOINTS ===

@app.get("/")
def root():
    return {"message": "Pokanalyzer API is running."}

@app.get("/hello")
def hello():
    return {"hello": "world"}

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

import qrcode

from auth import hash_password, verify_password
from database import Base, SessionLocal, engine
from jwl_token import create_token, verify_token
from models import User
from otp import generate_secret, get_qr_code_url, verify_otp

app = FastAPI()
bearer_scheme = HTTPBearer(auto_error=False)
app.mount("/static", StaticFiles(directory="static"), name="static")
pending_logins = set()

Base.metadata.create_all(bind=engine)


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.post("/register")
def register(username: str, password: str):
    db = SessionLocal()

    try:
        
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            return {"error": "User mavjud",
                    "username": existing.username
                    }

        secret = generate_secret()
        qr_url = get_qr_code_url(username, secret)
        hashed = hash_password(password)

        user = User(
            username=username,
            password=hashed,
            otp_secret=secret,
        )

        db.add(user)
        db.commit()

        return {
            "message": "User yaratildi",
            "qr_url": qr_url,
        }
        
    except Exception as exc:
        db.rollback()
        return {"error": str(exc)}
    finally:
        db.close()


@app.post("/login")
def login(username: str, password: str):
    db = SessionLocal()

    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password):
            return {"error": "Login xato"}

        pending_logins.add(username)
        return {"message": "OTP kiriting"}
    finally:
        db.close()


@app.post("/verify-otp")
def verify_otp_api(username: str, otp: str):
    if username not in pending_logins:
        return {"error": "Avval login qiling"}

    db = SessionLocal()

    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return {"error": "User topilmadi"}

        if not verify_otp(user.otp_secret, otp):
            return {"error": "OTP xato"}

        pending_logins.discard(username)
        token = create_token(user.id)
        return {"token": token}
    finally:
        db.close()


@app.get("/protected")
def protected(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    token: str | None = Query(default=None),
):
    raw_token = token

    if credentials:
        if credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Format xato")
        raw_token = credentials.credentials

    if not raw_token:
        raise HTTPException(status_code=401, detail="Token yo'q")

    try:
        data = verify_token(raw_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Token noto'g'ri")

    return {"message": f"Salom user {data['user_id']}"}


@app.get("/qr")
def get_qr(username: str):
    db = SessionLocal()

    try:
        user = db.query(User).filter(
            User.username == username
        ).first()

        if not user:
            raise HTTPException(
                status_code=404,
                detail="User topilmadi"
            )

        uri = get_qr_code_url(
            username,
            user.otp_secret
        )

        img = qrcode.make(uri)

        file_path = f"qr_{username}.png"
        img.save(file_path)

        return FileResponse(
            file_path,
            media_type="image/png"
        )

    finally:
        db.close()

    

import base64
import datetime
import hashlib
import hmac
import json

SECRET_KEY = "SECRET"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(message: bytes) -> str:
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        message,
        hashlib.sha256,
    ).digest()
    return _b64url_encode(signature)


def create_token(user_id):
    if ALGORITHM != "HS256":
        raise ValueError("Only HS256 is supported")

    header = {
        "alg": ALGORITHM,
        "typ": "JWT",
    }
    payload = {
        "user_id": user_id,
        "exp": int(
            (
                datetime.datetime.utcnow()
                + datetime.timedelta(minutes=TOKEN_EXPIRE_MINUTES)
            ).timestamp()
        ),
    }

    header_part = _b64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_part = _b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature_part = _sign(signing_input)
    return f"{header_part}.{payload_part}.{signature_part}"


def verify_token(token):
    try:
        header_part, payload_part, signature_part = token.split(".")
    except ValueError as exc:
        raise ValueError("Invalid token format") from exc

    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    expected_signature = _sign(signing_input)

    if not hmac.compare_digest(signature_part, expected_signature):
        raise ValueError("Invalid token signature")

    header = json.loads(_b64url_decode(header_part))
    if header.get("alg") != ALGORITHM:
        raise ValueError("Invalid token algorithm")

    payload = json.loads(_b64url_decode(payload_part))
    exp = payload.get("exp")
    if exp is None:
        raise ValueError("Token missing expiration")

    if datetime.datetime.utcnow().timestamp() > exp:
        raise ValueError("Token expired")

    return payload

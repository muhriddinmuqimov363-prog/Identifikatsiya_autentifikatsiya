import pyotp

OTP_INTERVAL_SECONDS = 30
OTP_FALLBACK_INTERVALS = (30,)
OTP_VALID_WINDOW = 1


def generate_secret():
    return pyotp.random_base32()


def verify_otp(secret, otp):
    normalized_otp = str(otp).strip()

    for interval in OTP_FALLBACK_INTERVALS:
        totp = pyotp.TOTP(secret, interval=interval)
        if totp.verify(normalized_otp, valid_window=OTP_VALID_WINDOW):
            return True

    return False


def get_qr_code_url(username, secret):
    totp = pyotp.TOTP(secret, interval=OTP_INTERVAL_SECONDS)
    return totp.provisioning_uri(
        name=username,
        issuer_name="AuthSystem",
    )

"""
QonnaGPT Auth Service - SMS/Notification Utilities
Sends OTP via Ethio Telecom, Africa's Talking, or Twilio.
"""

from __future__ import annotations

import structlog
from app.core.config import settings

logger = structlog.get_logger(__name__)

OTP_MESSAGES = {
    "phone_verify": {
        "om": "QonnaGPT: Lakkoofsi mirkaneessaa kee {code}. Daqiiqaa 5 keessatti fayyadami.",
        "am": "QonnaGPT: የማረጋገጫ ኮዶ {code} ነው። በ5 ደቂቃ ውስጥ ይጠቀሙ።",
        "en": "QonnaGPT: Your verification code is {code}. Valid for 5 minutes.",
    },
    "password_reset": {
        "om": "QonnaGPT: Jecha darbii haaromsuuf koodii {code} fayyadami. Daqiiqaa 5.",
        "am": "QonnaGPT: የይለፍ ቃልዎን ዳግም ለማስጀመር ኮዱ {code} ነው። ለ5 ደቂቃ ብቻ።",
        "en": "QonnaGPT: Your password reset code is {code}. Valid for 5 minutes.",
    },
    "login_otp": {
        "en": "QonnaGPT: Your login code is {code}. Do not share this code.",
    },
}


async def dispatch_otp_sms(
    phone: str,
    otp_code: str,
    purpose: str,
    language: str = "en",
) -> bool:
    """
    Dispatch OTP via the configured SMS provider.
    Returns True on success, False on failure (non-blocking background task).
    """
    try:
        messages = OTP_MESSAGES.get(purpose, OTP_MESSAGES["login_otp"])
        template = messages.get(language, messages.get("en", "Your code: {code}"))
        message = template.format(code=otp_code)

        provider = settings.SMS_PROVIDER

        if provider == "ethio_telecom":
            success = await _send_ethio_telecom(phone, message)
        elif provider == "africa_talking":
            success = await _send_africa_talking(phone, message)
        elif provider == "twilio":
            success = await _send_twilio(phone, message)
        else:
            logger.error("unknown_sms_provider", provider=provider)
            return False

        if success:
            logger.info("sms_sent", phone=phone[-4:], purpose=purpose, provider=provider)
        else:
            logger.error("sms_failed", phone=phone[-4:], purpose=purpose, provider=provider)

        return success

    except Exception as e:
        logger.exception("sms_dispatch_error", error=str(e), phone=phone[-4:])
        return False


async def _send_ethio_telecom(phone: str, message: str) -> bool:
    """Ethio Telecom SMS API integration."""
    if not settings.SMS_API_KEY:
        # Development fallback - log the OTP (never do this in production!)
        if settings.APP_ENV == "development":
            logger.warning("DEV_OTP_SMS", message=message, phone=phone)
            return True
        return False

    import httpx
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(
                "https://api.ethiotelecom.et/sms/send",  # Placeholder URL
                json={
                    "to": phone,
                    "from": settings.SMS_SENDER_ID,
                    "message": message,
                    "api_key": settings.SMS_API_KEY,
                },
            )
            return response.status_code == 200
        except httpx.RequestError:
            return False


async def _send_africa_talking(phone: str, message: str) -> bool:
    """Africa's Talking SMS API."""
    if not settings.SMS_API_KEY:
        if settings.APP_ENV == "development":
            logger.warning("DEV_OTP_SMS", message=message, phone=phone)
            return True
        return False

    import httpx
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(
                "https://api.africastalking.com/version1/messaging",
                data={
                    "username": "qonnagpt",
                    "to": phone,
                    "message": message,
                    "from": settings.SMS_SENDER_ID,
                },
                headers={
                    "apiKey": settings.SMS_API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            return response.status_code == 201
        except httpx.RequestError:
            return False


async def _send_twilio(phone: str, message: str) -> bool:
    """Twilio SMS fallback."""
    if not settings.SMS_API_KEY:
        if settings.APP_ENV == "development":
            logger.warning("DEV_OTP_SMS", message=message, phone=phone)
            return True
        return False

    try:
        from twilio.rest import Client
        client = Client(settings.SMS_API_KEY, settings.SMS_API_SECRET)
        msg = client.messages.create(
            body=message,
            from_=settings.SMS_SENDER_ID,
            to=phone,
        )
        return msg.sid is not None
    except Exception:
        return False

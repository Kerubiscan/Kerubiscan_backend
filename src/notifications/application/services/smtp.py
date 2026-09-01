import smtplib
from email.message import EmailMessage
import logging
import os

logger = logging.getLogger(__name__)

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.example.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")

def send_alert_email(to_email: str, subject: str, content: str):
    try:
        msg = EmailMessage()
        msg.set_content(content)
        msg['Subject'] = subject
        msg['From'] = "alerts@kerubiscan.com"
        msg['To'] = to_email

        if not SMTP_USER:
            # Mocking SMTP connection if no credentials to avoid crashing in dev
            logger.info(f"Mock SMTP: Sent email to {to_email} with subject '{subject}'")
            return True

        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        logger.info(f"Successfully sent email to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False

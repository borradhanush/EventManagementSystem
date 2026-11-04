"""Reusable Gmail SMTP email sender with safe configuration and delivery errors."""

from email.message import EmailMessage
from email.utils import parseaddr
import os
import re
import smtplib


class EmailConfigurationError(RuntimeError):
    """Raised when required Gmail SMTP settings are missing or invalid."""


class EmailDeliveryError(RuntimeError):
    """Raised when an SMTP server rejects or cannot deliver a message."""


_EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+\Z")


def _valid_address(value):
    """Accept a plain email address, not a display-name/header fragment."""
    if not isinstance(value, str):
        return False
    address = value.strip()
    display_name, parsed_address = parseaddr(address)
    return not display_name and parsed_address == address and bool(_EMAIL_PATTERN.fullmatch(address))


def send_email(subject, body, recipients, *, bcc=None):
    """Send through Gmail SMTP over SSL.

    Recipient addresses are carried in BCC/envelope recipients and never
    displayed in the visible To header. Sender is filtered from all recipients.
    """
    sender = os.environ.get("SENDER_EMAIL", "").strip()
    password = os.environ.get("APP_PASSWORD", "")
    if not sender or not password:
        raise EmailConfigurationError("Email sending is not configured. Set SENDER_EMAIL and APP_PASSWORD in .env.")
    if not _valid_address(sender):
        raise EmailConfigurationError("SENDER_EMAIL must be a valid email address.")
    if isinstance(recipients, str):
        recipients = [recipients]
    if isinstance(bcc, str):
        bcc = [bcc]
    all_recipients = list(recipients or []) + list(bcc or [])
    unique = []
    seen = set()
    for address in all_recipients:
        address = address.strip() if isinstance(address, str) else ""
        if not _valid_address(address):
            continue
        key = address.casefold()
        if address and key not in seen and key != sender.casefold():
            unique.append(address)
            seen.add(key)
    if not unique:
        raise ValueError("No valid participant email recipients were found.")
    message = EmailMessage()
    message["Subject"] = str(subject)
    message["From"] = sender
    message["To"] = "undisclosed-recipients:;"
    message.set_content(str(body))
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as smtp:
            smtp.login(sender, password)
            smtp.send_message(message, from_addr=sender, to_addrs=unique)
    except (OSError, smtplib.SMTPException) as error:
        raise EmailDeliveryError("The email could not be sent. Check the SMTP configuration and try again.") from error
    return {"recipient_count": len(unique)}

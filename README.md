# Event Management Website Prototype

## Email verification

Create a local `.env` file in the project directory yourself. The app loads it at startup with `python-dotenv`, without overriding values already supplied by the operating system. Gmail SMTP over SSL is the only email implementation. The same `email_service.py` sends registration OTPs and meeting invitations; meeting recipients remain private through BCC/envelope delivery.

Use this structure and replace each placeholder locally. Do not commit or share the file:

```dotenv
SENDER_EMAIL=YOUR_GMAIL_ADDRESS
APP_PASSWORD=YOUR_GMAIL_APP_PASSWORD
FLASK_SECRET_KEY=YOUR_LONG_RANDOM_SECRET
FLASK_COOKIE_SECURE=0
FLASK_DEBUG=0
```

The first three values are required and have no application defaults. `FLASK_COOKIE_SECURE=1` should be used when serving over HTTPS. `.env` and `.env.*` are ignored by Git. Do not create or commit real credentials in source, tests, or documentation.

New registrations ask only for full name, email, and password. Registration details are held as a short-lived pending registration, and the actual user account is created only after the six-digit OTP is verified. Codes are HMAC-protected, expire after 10 minutes, allow at most five attempts, and cannot be reused. Resends have a 60-second cooldown and are limited to five generated codes per pending registration per hour. Automated tests replace the SMTP connection with a test double and never send real email.

When `init_db()` upgrades an older database, existing accounts remain verified and are treated as profile-complete. New OTP-created accounts start with an incomplete profile. After login, users must add phone, institute/university, and internal/external affiliation on their profile before they can register for programs.

To run the app, install dependencies and start Flask after creating `.env` with your own values:

```powershell
python -m pip install -r requirements.txt
python app.py
```

To manually verify delivery, register with a new test address, check the inbox/spam folder, enter the OTP, then log in. The account is created only after successful verification. Never share your App Password.

## Local test data reset

`reset_test_data.py` is a **LOCAL TEST DATA RESET utility**. From the project directory, run:

```powershell
python reset_test_data.py
```

It permanently deletes all application data from the SQLite database configured by the project. It asks you to type `RESET` exactly before proceeding. The utility clears table rows and applicable AUTOINCREMENT counters; it does not delete or recreate the database file, tables, schema, indexes, constraints, or migration history. It does not create a Root account. Create one separately with `python app.py create-root` if needed.

**Do not run this utility against a production database.** It is intended only for manually resetting local test data.

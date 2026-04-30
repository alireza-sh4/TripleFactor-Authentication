# Security Project - 3FA Web App

Hi! This is my security project demonstrating a secure login system. It implements a 3-Factor Authentication (3FA) flow to keep user accounts safe from unauthorized access.

## Features

* **Factor 1: Password** - Uses Argon2 for secure password hashing.
* **Factor 2: Authenticator App** - Generates and verifies TOTP codes (like Google Authenticator). 
* **Factor 3: Telegram Push Approval** - Sends a notification to a Telegram bot asking to "Approve" or "Deny" the login attempt.
* **Brute Force Protection** - Temporarily locks the account if there are 5 failed login attempts.

## How to Run

1. Make sure you have Python installed.

2. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python app.py
   ```
4. Open your browser and go to `http://localhost:5050`.

### Demo Account
When you run the app for the first time, it creates a demo account automatically:
- **Username:** demo
- **Password:** Password123!

## Tech Stack
- Python / Flask
- PyOTP (for TOTP)
- Argon2 (for password hashing)
- Telegram Bot API
- HTML/CSS (Templates)

import os
import json
import time
import uuid
import struct
import base64
import hmac
import hashlib
import datetime
from flask import Flask, request, session, redirect, render_template, jsonify
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
import requests

app = Flask(__name__)
app.secret_key = os.urandom(32)

PORT = 5050
DB_FILE = "users.json"
JWT_SECRET = "enterprise_jwt_super_secret_778899"
TELEGRAM_BOT_TOKEN = "8589261968:AAGiUVVNvB3nKEV-iZoPkTeTLDMmD2gTauQ"
TELEGRAM_CHAT_ID = "80663049"
USED_TOTP_INTERVALS = set()
USED_JTIS = set()
LOGIN_REQUESTS = {}
TELEGRAM_UPDATE_OFFSET = 0


ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)


def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_db(db):
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=4)

def init_db():
    db = load_db()
    if "demo" not in db:
        secret = pyotp.random_base32()
        db["demo"] = {
            "password_hash": ph.hash("Password123!"),
            "totp_secret": secret,
            "failed_attempts": 0,
            "lockout_until": 0,
            "login_history": []
        }
        save_db(db)
        print("\n" + "="*50)
        print("&#9888; DEMO ACCOUNT CREATED")
        print("Username: demo")
        print("Password: Password123!")
        print("="*50 + "\n")
    return db


def get_totp_token(secret, interval):
    key = base64.b32decode(secret, casefold=True) 
    msg = struct.pack(">Q", interval)
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0f
    binary = struct.unpack(">I", mac[offset:offset+4])[0] & 0x7fffffff
    return str(binary % 1000000).zfill(6)

def verify_totp(secret, user_code, username):
    current_interval = int(time.time()) // 30
    
    for i in range(-1, 2):
        check_interval = current_interval + i
        expected_code = get_totp_token(secret, check_interval)
        
        if hmac.compare_digest(expected_code, user_code):  
            # Replay attack prevention
            if (username, check_interval) in USED_TOTP_INTERVALS: 
                
            USED_TOTP_INTERVALS.add((username, check_interval))
            return True
    return False

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    db = load_db()
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_data = db.get(username)
        current_time = time.time()
        
        
        if user_data and user_data.get("lockout_until", 0) > current_time:
            remaining = int((user_data["lockout_until"] - current_time) / 60)
            print(f"Error: Account locked. Try again in {remaining} minutes.")
            return render_template('login.html')
            
        try:
            if user_data:
                ph.verify(user_data["password_hash"], password)
                # Success
                user_data["failed_attempts"] = 0
                user_data["lockout_until"] = 0
                save_db(db)
                
                session['user'] = username
                session['step'] = 1
                return redirect('/totp')
            else:
                
                ph.verify(ph.hash("dummy_password"), password)
                raise VerifyMismatchError()
                
        except VerifyMismatchError:
            if user_data:
                user_data["failed_attempts"] = user_data.get("failed_attempts", 0) + 1
                if user_data["failed_attempts"] >= 5:
                    user_data["lockout_until"] = current_time + (15 * 60)
                save_db(db)
            error = "Invalid credentials."

    if error:
        print(f"Error: {error}")
    return render_template('login.html') 

@app.route('/totp', methods=['GET', 'POST'])
def totp_step():
    if session.get('step') != 1: 
        return redirect('/login')
        
    db = load_db()
    username = session['user']
    secret = db[username]["totp_secret"] 
    error = None
    
    if request.method == 'POST':
        code = request.form.get('code')
        if verify_totp(secret, code, username):
            login_request_id = str(uuid.uuid4())
            LOGIN_REQUESTS[login_request_id] = "pending"
            
            # Send to Telegram via Bot API
            try:
                url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
                message_text = f"Secure Login Attempt\nUser: {username}\n\nDo you approve this login?"
                
                keyboard = {
                    "inline_keyboard": [
                        [
                            {"text": "Approve", "callback_data": f"approve_{login_request_id}"},
                            {"text": "Deny", "callback_data": f"deny_{login_request_id}"}
                        ]
                    ]
                }
                
                payload = {
                    "chat_id": TELEGRAM_CHAT_ID, 
                    "text": message_text,
                    "reply_markup": keyboard
                }
                
                resp = requests.post(url, json=payload, timeout=5)
                if resp.status_code == 200:
                    print(f"Approval request sent to Telegram ID {TELEGRAM_CHAT_ID}")
                else:
                    print(f"Failed to send Telegram message: {resp.text}")
            except Exception as e:
                print(f"Error sending Telegram message: {e}")
                
            session['step'] = 2
            session['login_request_id'] = login_request_id
            return redirect('/telegram')
        else:
            error = "Invalid or reused TOTP code."
            
    
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureEdge")
    if error:
        print(f"Error: {error}")
    return render_template('totp.html', totp_uri=totp_uri, secret=secret)

@app.route('/telegram', methods=['GET'])
def telegram_step():
    if session.get('step') != 2:
        return redirect('/login')
    return render_template('telegram.html')

@app.route('/api/telegram_status')
def telegram_status():
    if session.get('step') != 2:
        return jsonify({"error": "Invalid session state"})
        
    req_id = session.get('login_request_id')
    if not req_id:
        return jsonify({"error": "No pending request"})
        
    global TELEGRAM_UPDATE_OFFSET 
    
  
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
        resp = requests.get(url, params={"offset": TELEGRAM_UPDATE_OFFSET, "timeout": 2})
        if resp.status_code == 200:
            data = resp.json()
            for update in data.get("result", []):
                TELEGRAM_UPDATE_OFFSET = update["update_id"] + 1
                
                if "callback_query" in update:
                    cq = update["callback_query"]
                    cb_data = cq.get("data", "") 
                    cb_id = cq.get("id")
                    
                    if cb_data.startswith("approve_"):
                        cid = cb_data.split("approve_")[1]
                        if cid in LOGIN_REQUESTS:
                            LOGIN_REQUESTS[cid] = "approved"
                            requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery", json={"callback_query_id": cb_id, "text": "Login Approved!"})
                            
                    elif cb_data.startswith("deny_"):
                        cid = cb_data.split("deny_")[1]
                        if cid in LOGIN_REQUESTS:
                            LOGIN_REQUESTS[cid] = "denied"
                            requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery", json={"callback_query_id": cb_id, "text": "Login Denied!"})
                            
    except Exception as e:
        print(f"Polling error: {e}")

   
    status = LOGIN_REQUESTS.get(req_id, "pending")
    if status == "approved":
        session['step'] = 3
        session['auth'] = True
       
        db = load_db()
        username = session['user']
        history = db[username].get("login_history", [])
        history.insert(0, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        db[username]["login_history"] = history[:10]
        save_db(db)
        
    elif status == "denied":
        session.clear()
        
    return jsonify({"status": status})

@app.route('/dashboard')
def dashboard():
    if not session.get('auth'):
        return redirect('/login')
    db = load_db()
    history = db[session['user']].get("login_history", [])
    return render_template('dashboard.html', username=session['user'], history=history)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=PORT, debug=True)

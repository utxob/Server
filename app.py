import os import csv import time from datetime import datetime, timedelta from functools import wraps from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, make_response from werkzeug.utils import secure_filename from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(name) app.secret_key = 'your_secret_key_here' app.config['SESSION_COOKIE_HTTPONLY'] = True app.config['SESSION_COOKIE_SECURE'] = True  # Use True when using HTTPS UPLOAD_FOLDER = 'uploads' TRASH_FOLDER = 'trash' ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4'}

Security trackers

login_attempts = {}

Ensure directories exist

os.makedirs(UPLOAD_FOLDER, exist_ok=True) os.makedirs(TRASH_FOLDER, exist_ok=True)

File paths

USER_CSV = 'users.csv' LOG_CSV = 'logs.csv' SHARE_CSV = 'shared_links.csv'

Auto-create CSV files if not exists

if not os.path.exists(USER_CSV): with open(USER_CSV, 'w', newline='') as f: writer = csv.writer(f) writer.writerow(['email', 'password']) writer.writerow(['admin@example.com', generate_password_hash('admin123')])

for csv_file in [LOG_CSV, SHARE_CSV]: if not os.path.exists(csv_file): with open(csv_file, 'w', newline='') as f: writer = csv.writer(f) if csv_file == LOG_CSV: writer.writerow(['email', 'action', 'file', 'timestamp']) elif csv_file == SHARE_CSV: writer.writerow(['file', 'link_id', 'expires_at'])

Utility functions

def allowed_file(filename): return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_action(email, action, filename): with open(LOG_CSV, 'a', newline='') as f: writer = csv.writer(f) writer.writerow([email, action, filename, datetime.now().strftime('%Y-%m-%d %H:%M:%S')])

def login_required(f): @wraps(f) def decorated_function(*args, **kwargs): if 'email' not in session: return redirect(url_for('login')) return f(*args, **kwargs) return decorated_function

Routes

@app.route('/') @login_required def index(): files = os.listdir(UPLOAD_FOLDER) return render_template('file_manager.html', files=files)

@app.route('/login', methods=['GET', 'POST']) def login(): ip = request.remote_addr if request.method == 'POST': email = request.form['email'] password = request.form['password']

# Brute force protection
    if ip in login_attempts and login_attempts[ip]['count'] >= 5:
        if datetime.now() < login_attempts[ip]['until']:
            flash('Too many failed attempts. Try again later.')
            return render_template('login.html')
        else:
            login_attempts[ip] = {'count': 0, 'until': None}

    with open(USER_CSV) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['email'] == email and check_password_hash(row['password'], password):
                session['email'] = email
                login_attempts[ip] = {'count': 0, 'until': None}
                return redirect(url_for('index'))

    # Failed login
    if ip not in login_attempts:
        login_attempts[ip] = {'count': 1, 'until': None}
    else:
        login_attempts[ip]['count'] += 1
        if login_attempts[ip]['count'] >= 5:
            login_attempts[ip]['until'] = datetime.now() + timedelta(minutes=5)

    flash('Invalid credentials')
return render_template('login.html')

@app.route('/logout') @login_required def logout(): session.clear() return redirect(url_for('login'))

@app.route('/upload', methods=['POST']) @login_required def upload(): file = request.files['file'] if file and allowed_file(file.filename): filename = secure_filename(file.filename) path = os.path.join(UPLOAD_FOLDER, filename) file.save(path) log_action(session['email'], 'upload', filename) return redirect(url_for('index'))

@app.route('/delete/<filename>') @login_required def delete(filename): filename = secure_filename(filename) src = os.path.join(UPLOAD_FOLDER, filename) dst = os.path.join(TRASH_FOLDER, filename) if os.path.exists(src): os.rename(src, dst) log_action(session['email'], 'delete', filename) return redirect(url_for('index'))

@app.route('/restore/<filename>') @login_required def restore(filename): filename = secure_filename(filename) src = os.path.join(TRASH_FOLDER, filename) dst = os.path.join(UPLOAD_FOLDER, filename) if os.path.exists(src): os.rename(src, dst) log_action(session['email'], 'restore', filename) return redirect(url_for('index'))

@app.route('/download/<filename>') @login_required def download(filename): filename = secure_filename(filename) return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route('/dashboard') @login_required def dashboard(): with open(LOG_CSV) as f: logs = list(csv.DictReader(f)) return render_template('dashboard.html', logs=logs)

if name == 'main': app.run(debug=True)


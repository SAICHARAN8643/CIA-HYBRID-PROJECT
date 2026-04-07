from flask import Flask, render_template, request, redirect, session, flash
from database import connect_db
from encryption import encrypt_data, decrypt_data
from datetime import datetime
import hashlib   # ✅ ADDED FOR PASSWORD HASHING

app = Flask(__name__)

# 🔐 Session Secret Key
app.secret_key = "secret123"

# ✅ File size limit (2MB)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024


# 📜 Logging Function
def log_action(action):
    db = connect_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO logs (action) VALUES (%s)", (action,))
    db.commit()


# 🔐 Login Page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ✅ HASH PASSWORD BEFORE CHECK
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        db = connect_db()
        cursor = db.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=%s AND password=%s",
            (username, hashed_password)
        )
        user = cursor.fetchone()

        if user:
            session['user'] = username
            session['user_id'] = user[0]
            log_action(f"User {username} logged in")
            return redirect('/dashboard')
        else:
            return "Invalid Login"

    return render_template('login.html')


# 🆕 Signup Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ✅ HASH PASSWORD BEFORE STORE
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        db = connect_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return render_template('signup.html', error_message="⚠️ User already exists! Please login.")

        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hashed_password)
        )
        db.commit()

        log_action(f"New user registered: {username}")

        return render_template('signup.html', success_message="✅ Account created successfully! Go to login.")

    return render_template('signup.html')


# 📊 Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')

    db = connect_db()
    cursor = db.cursor()
    user_id = session.get('user_id')

    # Fetch recent files
    cursor.execute("SELECT id, encrypted_data FROM files WHERE user_id=%s ORDER BY id DESC LIMIT 5", (user_id,))
    recent_files = cursor.fetchall()

    dashboard_files = []
    for row in recent_files:
        try:
            decrypted = decrypt_data(row[1].encode())
        except:
            decrypted = "[Encrypted Content]"
        dashboard_files.append({"id": row[0], "data": decrypted})

    return render_template('dashboard.html', recent_files=dashboard_files, username=session.get('user'))


# 📤 Upload Data
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return redirect('/')

    if request.method == 'POST':
        text_data = request.form.get('data')
        file = request.files.get('file')

        combined_data = ""

        if text_data and text_data.strip() != "":
            combined_data += text_data

        if file and file.filename != "":
            file.seek(0, 2)
            size = file.tell()
            file.seek(0)

            if size > 2 * 1024 * 1024:
                flash("❌ File too large! Max 2MB allowed", "error")
                return redirect('/dashboard')

            file_data = file.read()
            file_text = file_data.hex()
            combined_data += "\n" + file_text

        if combined_data.strip() == "":
            flash("⚠️ Please enter text or upload file", "error")
            return redirect('/dashboard')

        encrypted, hash_value = encrypt_data(combined_data)

        db = connect_db()
        cursor = db.cursor()

        user_id = session.get('user_id')

        cursor.execute(
            "INSERT INTO files (filename, encrypted_data, hash_value, user_id) VALUES (%s, %s, %s, %s)",
            ("data.txt", encrypted.decode(), hash_value, user_id)
        )
        db.commit()

        # ✅ USER-WISE BACKUP + TIMESTAMP
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(f"backup_{session['user_id']}.txt", "a") as f:
            f.write(f"[{timestamp}] {encrypted.decode()}\n")

        log_action(f"User {session['user']} uploaded data")

        flash("✅ Data Stored Securely!", "success")
        return redirect('/dashboard')

    return render_template('upload.html')


# 📥 View Data
@app.route('/view')
def view():
    if 'user' not in session:
        return redirect('/')

    db = connect_db()
    cursor = db.cursor()

    user_id = session.get('user_id')

    cursor.execute("SELECT * FROM files WHERE user_id=%s", (user_id,))
    records = cursor.fetchall()

    result = []

    for row in records:
        file_id, filename, encrypted_data, stored_hash, user_id = row

        try:
            decrypted = decrypt_data(encrypted_data.encode())
        except:
            decrypted = "[Error decrypting]"

        recalculated_hash = hashlib.sha256(encrypted_data.encode()).hexdigest()

        if recalculated_hash == stored_hash:
            status = "✅ Safe"
        else:
            status = "⚠️ Tampered"

        result.append({
            "id": file_id,
            "data": decrypted,
            "status": status
        })

    log_action(f"User {session['user']} viewed their data")

    return render_template("view.html", data=result)


# 📂 Recover Backup
@app.route('/recover')
def recover():
    if 'user' not in session:
        return redirect('/')

    try:
        with open(f"backup_{session['user_id']}.txt", "r") as f:
            data = f.readlines()

        log_action(f"User {session['user']} recovered backup")

        return "<h2>Recovered Backup Data</h2><br><pre>" + "".join(data) + "</pre>"

    except:
        return "⚠️ No backup file found!"


# 🔓 Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
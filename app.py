from flask import Flask, render_template, request, redirect, url_for, session, jsonify,flash
import mysql.connector
import hashlib
from werkzeug.security import generate_password_hash,check_password_hash
import re


app = Flask(__name__)
app.secret_key = 'prashanth'

# MySQL config
db_config = {
    'host': '192.168.0.174',
    'user': 'evadminserve',
    'password': 'MGTev007',
    'database': 'EV_STATION',
    'port':3306,
}

# Helper: Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# 👉 Add this route to fix the issue
@app.route('/')
def index():
    return render_template('index.html')
# @app.route('/')
# def home():
#     return redirect(url_for('index'))
@app.route('/admin')
def admin():
    if 'admin_id' not in session:
        flash("Admin access only. Please log in as admin.")
        return redirect(url_for('login'))

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    cursor.execute("SELECT * FROM devices")
    devices = cursor.fetchall()

    cursor.execute("""
        SELECT ud.id, u.name AS username, u.email, d.device_id 
        FROM user_devices ud
        JOIN users u ON ud.user_id = u.id
        JOIN devices d ON ud.device_id = d.id
    """)
    assignments = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin.html', users=users, devices=devices, assignments=assignments)

@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    hashed_password = generate_password_hash(password)

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                   (username, email, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()
    flash('User added successfully!', 'success')
    return redirect(url_for('admin'))


@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash('User deleted!', 'info')
    return redirect(url_for('admin'))


@app.route('/add_device', methods=['POST'])
def add_device():
    device_id = request.form['device_id']
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM devices WHERE device_id = %s", (device_id,))
    if cursor.fetchone():
        flash("Device already exists!", "warning")
    else:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO devices (device_id) VALUES (%s)", (device_id,))
        conn.commit()
        flash("Device added!", "success")

    cursor.close()
    conn.close()
    return redirect(url_for('admin'))


@app.route('/assign_device', methods=['POST'])
def assign_device():
    user_id = request.form['user_id']
    device_id = request.form['device_id']
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM user_devices WHERE user_id = %s AND device_id = %s", (user_id, device_id))
    if cursor.fetchone():
        flash("Device already assigned to this user.", "warning")
    else:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user_devices (user_id, device_id) VALUES (%s, %s)", (user_id, device_id))
        conn.commit()
        flash("Device assigned to user!", "success")

    cursor.close()
    conn.close()
    return redirect(url_for('admin'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        phone = request.form['phone']
        address = request.form['address']
        role = request.form['role']

        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email address.")
            return redirect(url_for('register'))

        # Enforce strong password (min 8 characters, with uppercase, lowercase, number)
        if len(password) < 8 or not re.search(r"[A-Z]", password) \
                or not re.search(r"[a-z]", password) or not re.search(r"\d", password):
            flash("Password must be at least 8 characters long and contain uppercase, lowercase, and numbers.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()

            # Check if email already exists
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing_user = cursor.fetchone()
            if existing_user:
                flash("Email already registered.")
                return redirect(url_for('register'))

            # Insert new user
            cursor.execute("""
                INSERT INTO users (name, email, password, phone, address, role)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, email, hashed_password, phone, address, role))
            conn.commit()
            flash("Registration successful! Please login.")
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f"Database error: {err}")
        finally:
            if cursor: cursor.close()
            if conn: conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    conn = None
    cursor = None
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)

            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['user_name'] = user['name']

                # Admin login check
                if email == 'admin@example.com' and check_password_hash(user['password'], 'Admin@1234'):
                    session['admin_id'] = user['id']
                    return redirect(url_for('admin'))
                else:
                    flash("Logged in successfully!")
                    return redirect(url_for('dashboard'))
            else:
                flash("Invalid email or password.")
                return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f"Database error: {err}")
            return redirect(url_for('login'))
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('profile.html', user=user)
    
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access the dashboard.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Fetch devices and their status
    cursor.execute("""
       SELECT d.device_id, d.status FROM devices d
       JOIN user_devices ud ON d.id = ud.device_id
       WHERE ud.user_id = %s
    """, (user_id,))
    devices = cursor.fetchall()

    pump_devices = [d['device_id'] for d in devices if d['device_id'].lower().startswith('pump')]
    cam_devices = [d['device_id'] for d in devices if d['device_id'].lower().startswith('cam')]
    device_status = {d['device_id']: d['status'] for d in devices}

    cursor.close()
    conn.close()

    return render_template('dashboard.html',
                           user_name=session.get('user_name'),
                           pump_devices=pump_devices,
                           cam_devices=cam_devices,
                           device_status=device_status)

@app.route('/set_device_status', methods=['POST'])
def set_device_status():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    data = request.get_json()
    device_id = data.get('device_id')
    status = data.get('status')

    if not device_id or status not in ['ON', 'OFF']:
        return jsonify({'status': 'error', 'message': 'Invalid request'}), 400

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Check if the device is assigned to the user
        cursor.execute("""
            SELECT d.id FROM devices d
            JOIN user_devices ud ON d.id = ud.device_id
            WHERE ud.user_id = %s AND d.device_id = %s
        """, (session['user_id'], device_id))
        device = cursor.fetchone()

        if not device:
            return jsonify({'status': 'error', 'message': 'Device not found or unauthorized'}), 403

        # Update the device status
        cursor.execute("UPDATE devices SET status = %s WHERE device_id = %s", (status, device_id))
        conn.commit()

        return jsonify({'status': 'success', 'message': f'{device_id} set to {status}'})

    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'Server error'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)


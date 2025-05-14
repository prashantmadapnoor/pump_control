from flask import Flask, render_template, request, redirect, url_for, session, jsonify,flash
import mysql.connector
import hashlib
from werkzeug.security import generate_password_hash,check_password_hash
import re

app = Flask(__name__)
app.secret_key = 'prashanth'

# MySQL config
# db_config = {
#     'host': 'localhost',
#     'user': 'flaskuser',
#     'password': 'root',
#     'database': 'MGT_Remote_Ccontrol'  
# }
db_config = {
    'host': '117.247.0.204',
    'user': 'remote_user',
    'password': 'Remote_control',
    'database': 'remote_control',
    'port':3306
}
# try:
#     connection = mysql.connector.connect(**db_config)
#     cursor = connection.cursor()
#     cursor.execute("SELECT DATABASE();")
#     result = cursor.fetchone()
#     print("Connected to database:", result)
# except mysql.connector.Error as err:
#     print("Database error:", err)

# # Helper: Hash password
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
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # All users
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    # All unassigned devices
    cursor.execute("SELECT * FROM devices WHERE id NOT IN (SELECT device_id FROM user_devices)")
    unassigned_devices = cursor.fetchall()

    # All assigned devices for reference
    cursor.execute("SELECT users.name, devices.device_id FROM user_devices JOIN users ON user_devices.user_id = users.id JOIN devices ON user_devices.device_id = devices.id")
    assignments = cursor.fetchall()

    # All devices (for pump/camera attachment)
    cursor.execute("SELECT * FROM devices")
    devices = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin.html", users=users, devices=devices, assignments=assignments, unassigned_devices=unassigned_devices)

@app.route('/add_user', methods=['POST'])
def add_user():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    phone = request.form['phone']
    address = request.form['address']
    role = request.form['role']

    hashed_password = generate_password_hash(password)
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (name, email, password, phone, address, role) 
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (name, email, hashed_password, phone, address, role))
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
    user_id = request.form['user_id']

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Check if device already exists
    cursor.execute("SELECT * FROM devices WHERE device_id = %s", (device_id,))
    existing = cursor.fetchone()

    if existing:
        flash("Device already exists!", "warning")
    else:
        cursor.execute("INSERT INTO devices (device_id) VALUES (%s)", (device_id,))
        conn.commit()
        new_device_id = cursor.lastrowid

        # Assign device to user
        cursor.execute("INSERT INTO user_devices (user_id, device_id) VALUES (%s, %s)", (user_id, new_device_id))
        conn.commit()
        flash("Device added and assigned to user!", "success")

    cursor.close()
    conn.close()
    return redirect(url_for('admin'))
@app.route('/add_pump', methods=['POST'])
def add_pump():
    pump_id = request.form['pump_id']
    device_id = request.form['device_id']
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO pumps (pump_id, device_id) VALUES (%s, %s)", (pump_id, device_id))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Pump added!", "success")
    return redirect(url_for('admin'))
@app.route('/add_camera', methods=['POST'])
def add_camera():
    camera_id = request.form['camera_id']
    device_id = request.form['device_id']
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO cameras (camera_id, device_id) VALUES (%s, %s)", (camera_id, device_id))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Camera added!", "success")
    return redirect(url_for('admin'))
@app.route('/assign_device', methods=['POST'])
def assign_device():
    flash("Device assignment must be done during device creation. Use 'Add Device' form.", "info")
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

        # Enforce strong password
        if len(password) < 8 or not re.search(r"[A-Z]", password) \
                or not re.search(r"[a-z]", password) or not re.search(r"\d", password):
            flash("Password must be at least 8 characters long and contain uppercase, lowercase, and numbers.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        conn = None
        cursor = None

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)

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
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

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
    print(f"[DEBUG] Logged in user_id: {user_id}")

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT d.id AS device_db_id
        FROM devices d
        JOIN user_devices ud ON d.id = ud.device_id
        WHERE ud.user_id = %s
    """, (user_id,))
    assigned_devices = cursor.fetchall()
    device_ids = [d['device_db_id'] for d in assigned_devices]
    print(f"[DEBUG] Assigned device DB IDs: {device_ids}")

    pump_devices = []
    cam_devices = []
    device_status = {}

    for device_id in device_ids:
        print(f"[DEBUG] Processing device_id: {device_id}")

        # Pumps
        cursor.execute("SELECT pump_id, status FROM pumps WHERE device_id = %s", (device_id,))
        pumps = cursor.fetchall()
        print(f"[DEBUG] Pumps found: {pumps}")
        for pump in pumps:
            pump_devices.append({
                'device_id': device_id,
                'pump_id': pump['pump_id'],
                'status': pump['status']
            })
            device_status[pump['pump_id']] = pump['status']

        # Cameras
        cursor.execute("SELECT camera_id, status FROM cameras WHERE device_id = %s", (device_id,))
        cams = cursor.fetchall()
        print(f"[DEBUG] Cameras found: {cams}")
        for cam in cams:
            cam_devices.append({
                'device_id': device_id,
                'camera_id': cam['camera_id'],
                'status': cam['status']
            })
            device_status[cam['camera_id']] = cam['status']

    cursor.close()
    conn.close()

    print(f"[DEBUG] Final pump_devices: {pump_devices}")
    print(f"[DEBUG] Final cam_devices: {cam_devices}")
    print(f"[DEBUG] Final device_status: {device_status}")

    return render_template('dashboard.html',
                           user_name=session.get('user_name'),
                           pump_devices=pump_devices,
                           cam_devices=cam_devices,
                           device_status=device_status)

@app.route('/update_status', methods=['POST'])
def update_status():
    data = request.get_json()
    print(f"[DEBUG] Received data: {data}")

    status = data.get('status')               # "ON" / "OFF"
    pump_id = data.get('pump_id')             # pump_id
    device_id = data.get('device_id')         # DeviceX
    component_type = data.get('type')         # 'pump'
    duration = data.get('duration')           # in minutes (if ON)

    print(f"[DEBUG] Parsed values - Status: {status}, Pump ID: {pump_id}, Device ID: {device_id}, Type: {component_type}, Duration: {duration}")

    user_id = session.get('user_id')
    print(f"[DEBUG] Current user ID from session: {user_id}")

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    if component_type == 'pump':
        print(f"[DEBUG] Updating pump status in database...")
        cursor.execute("""
            UPDATE pumps 
            SET status=%s 
            WHERE pump_id=%s AND device_id=(SELECT id FROM devices WHERE device_id=%s)
        """, (status, pump_id, device_id))

        print(f"[DEBUG] Inserting pump log...")
        cursor.execute("""
            INSERT INTO pump_logs (user_id, device_id, pump_id, action, duration_minutes)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, device_id, pump_id, status, duration if status == "ON" else 0))

    conn.commit()
    cursor.close()
    conn.close()

    print("[DEBUG] Pump status updated and log saved successfully.")
    return jsonify({'success': True})


# @app.route('/update_device_status', methods=['POST'])
# def update_device_status():
#     data = request.get_json()
#     device_id = data.get('device_id')
#     status = data.get('status')

#     if not device_id or not status:
#         return jsonify({'message': 'Missing data'}), 400

#     try:
#         cursor = mysql.connection.cursor()
#         cursor.execute("UPDATE devices SET status = %s WHERE device_id = %s", (status, device_id))
#         mysql.connection.commit()
#         cursor.close()
#         return jsonify({'message': 'Status updated successfully'}), 200
#     except Exception as e:
#         return jsonify({'message': 'Database error', 'error': str(e)}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


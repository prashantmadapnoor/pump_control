import MySQLdb

db_config = {
    'host': '0.tcp.ngrok.io',  # Or your VPS if using custom tunnel
    'user': 'remote_user',
    'password': 'Remote_control',
    'database': 'remote_control',
    'port': 16243              # Replace with Ngrok/VPS tunnel port
}

try:
    conn = MySQLdb.connect(**db_config)
    print("Database connection successful")
except Exception as e:
    print("Database connection failed:", e)

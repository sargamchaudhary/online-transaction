import sqlite3
from flask import Flask, g, render_template, request, redirect, session
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import secrets

app = Flask(__name__, static_url_path='/static')  # Include static_url_path parameter
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

DATABASE = 'users.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    cursor = db.cursor()  # Define the cursor here
    return db, cursor

def close_db(e=None):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.teardown_appcontext
def teardown_db(e=None):
    close_db()

# Create SQLite database
def init_db():
    with app.app_context():
        db = get_db()[0]
        cursor = get_db()[1]
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password BLOB,
                private_key BLOB
            )
        ''')
        db.commit()

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_data(data, public_key):
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def decrypt_data(encrypted_data, private_key):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode()

def generate_otp():
    # Generate a random 6-digit OTP
    return str(secrets.randbelow(1000000)).zfill(6)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db, cursor = get_db()  # Get the database connection and cursor
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            return "Username already exists. Please choose another one."
        
        private_key, public_key = generate_rsa_keypair()
        encrypted_password = encrypt_data(password, public_key)
        
        # Insert user data into database
        cursor.execute('''
            INSERT INTO users (username, password, private_key) VALUES (?, ?, ?)
        ''', (username, encrypted_password, private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())))
        db.commit()
        
        return redirect('/login')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db, cursor = get_db()  # Get the database connection and cursor
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            return "Username not found. Please register."
        
        private_key = serialization.load_pem_private_key(user[3], password=None, backend=default_backend())
        decrypted_password = decrypt_data(user[2], private_key)
        
        if password == decrypted_password:
            # Generate and send OTP
            generated_otp = generate_otp()
            # For now, just print OTP to console
            print(f"Generated OTP for {username}: {generated_otp}")
            
            # Store generated OTP in session
            session['generated_otp'] = generated_otp
            
            # Prompt user to input OTP
            return render_template('otp_verification.html', username=username)
        else:
            return "Incorrect username or password. Please try again."
        
    return render_template('login.html')

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if request.method == 'POST':
        username = request.form['username']
        otp_value = request.form['otp']
        
        # Retrieve generated OTP from session
        generated_otp = session.get('generated_otp')
        if not generated_otp:
            return "OTP session expired. Please try again."
        
        # Compare input OTP with generated OTP
        if otp_value == generated_otp:
            # OTP verification successful
            session.pop('generated_otp')  # Remove generated OTP from session
            session['username'] = username
            
            # Redirect to dashboard
            return redirect('/dashboard')
        else:
            return "Incorrect OTP. Please try again."

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True)

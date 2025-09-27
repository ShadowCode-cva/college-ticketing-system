from flask import Flask, request, flash, get_flashed_messages, session, render_template, redirect, url_for
from datetime import datetime, timedelta, timezone
import jwt
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)   # For sessions and flash messages
SECRET_KEY = secrets.token_hex(16)       # For ticket JWT

# Mock databases
users = {}      # {"username": "password"}
tickets = {}    # {"username": "jwt_token"}
admins = {"admin1": "adminpw1", "admin2": "adminpw2"}

# ------------------- Student Routes -------------------

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html', messages=get_flashed_messages())

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Enter valid data!")
        return render_template('register.html', messages=get_flashed_messages())

    if username in users:
        flash("You are already registered! Please login.")
        return redirect(url_for('login'))

    users[username] = password
    flash("Registration successful! Please login to continue.")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', messages=get_flashed_messages())

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Enter valid data!")
        return render_template('login.html', messages=get_flashed_messages())

    if username not in users:
        flash("No such user exists! Please register first.")
        return redirect(url_for('register'))

    if users[username] != password:
        flash("Wrong password! Try again.")
        return render_template('login.html', messages=get_flashed_messages())

    session['user'] = username
    flash("Login successful!")
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please login first!")
        return redirect(url_for('login'))

    return render_template('dashboard.html', user=session['user'], messages=get_flashed_messages())

@app.route('/generate_ticket')
def generate_ticket():
    if 'user' not in session:
        flash("Please login first!")
        return redirect(url_for('login'))

    username = session['user']
    expiration = datetime.now(timezone.utc) + timedelta(minutes=10)
    token = jwt.encode({"user": username, "exp": expiration}, SECRET_KEY, algorithm="HS256")
    tickets[username] = token

    return render_template('ticket.html', token=token, expiration=expiration, user=username)

# ------------------- Admin Routes -------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html', messages=get_flashed_messages())

    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("Enter valid credentials!")
        return render_template('admin_login.html', messages=get_flashed_messages())

    if username not in admins or admins[username] != password:
        flash("Invalid credentials!")
        return render_template('admin_login.html', messages=get_flashed_messages())

    session['admin'] = username
    flash("Admin logged in successfully!")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin' not in session:
        flash("Please login as admin!")
        return redirect(url_for('admin_login'))

    messages = []
    if request.method == 'POST':
        token = request.form.get("token")
        if not token:
            messages.append("Please enter a ticket token!")
        else:
            try:
                decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                messages.append(f"✅ Valid ticket for {decoded['user']}")
            except jwt.ExpiredSignatureError:
                messages.append("❌ Ticket expired!")
            except jwt.InvalidTokenError:
                messages.append("❌ Invalid token!")

    return render_template('admin_dashboard.html', messages=messages, admin=session['admin'])

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash("Admin logged out successfully!")
    return redirect(url_for('admin_login'))

# ------------------- Run App -------------------

if __name__ == "__main__":
    app.run(debug=True)

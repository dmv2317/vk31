import os
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField, FileField, SubmitField, SelectField
from wtforms.validators import DataRequired
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message  # Email
from authlib.integrations.flask_client import OAuth  # Google Auth

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "supersecretkey"
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'elibrary2371@gmail.com'  # Admin email
app.config['MAIL_PASSWORD'] = 'your_app_password'  # Use an app-specific password

mail = Mail(app)

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
CORS(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# Google OAuth Setup
oauth = OAuth(app)
app.config["GOOGLE_CLIENT_ID"] = "YOUR_GOOGLE_CLIENT_ID"
app.config["GOOGLE_CLIENT_SECRET"] = "YOUR_GOOGLE_CLIENT_SECRET"
app.config["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Remove in production

google = oauth.register(
    name="google",
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    client_kwargs={"scope": "openid email profile"},
)

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)  # Allow empty password for Google users

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Google Login Route
@app.route("/google-login")
def google_login():
    return google.authorize_redirect(url_for("google_callback", _external=True))

# Google Callback Route
@app.route("/google-callback")
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = google.get("https://www.googleapis.com/oauth2/v2/userinfo").json()

        email = user_info["email"]
        username = user_info.get("name", email.split("@")[0])  # Use name or extract from email

        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if not user:
            # Create a new user
            user = User(username=username, email=email, password_hash=None)
            db.session.add(user)
            db.session.commit()

        login_user(user)
        flash("Google Login Successful!", "success")
        return redirect(url_for("home"))
    except Exception as e:
        flash("Error during Google login: " + str(e), "danger")
        return redirect(url_for("login"))

# Traditional Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user:
            # Google users do not have a password_hash
            if user.password_hash and bcrypt.check_password_hash(user.password_hash, password):
                login_user(user)
                flash("Login successful!", "success")
                return redirect(url_for('home'))
            elif user.password_hash is None:
                flash("Please log in with Google instead!", "danger")
                return redirect(url_for("google_login"))
            else:
                flash("Invalid password!", "danger")
                return redirect(url_for('login'))
        else:
            flash("User not found!", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

# Home Route
@app.route('/home')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

import os
from flask import Flask, abort, render_template, redirect, send_file, send_from_directory, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, SubmitField, SelectField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "supersecretkey"
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Extensions
csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

# Book Model
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(500), nullable=True)  # New field for book cover image
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Book Upload Form
class BookUploadForm(FlaskForm):
    book_name = StringField("Book Name", validators=[DataRequired()])
    author = StringField("Author", validators=[DataRequired()])
    category = SelectField("Category", choices=[
        ('Biographies', 'Biographies'),
        ('Comics', 'Comics'),
        ('Fantasy', 'Fantasy'),
        ('Science', 'Science'),
        ('Technology', 'Technology'),
        ('History','History'),
        ('Mystery', 'Mystery'),
        ('Edu Vault', 'Edu Vault')
    ], validators=[DataRequired()])
    description = TextAreaField("Description")
    image_url = StringField("Book Cover URL")  # New field for book cover image
    book = FileField("Book", validators=[DataRequired()])
    submit = SubmitField("Upload")

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            flash("All fields are required!", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password_hash=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash("Account created! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials!", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

@app.route('/about')
@login_required
def about():
    return render_template('about.html', username=current_user.username)

@app.route('/feedback')
@login_required
def feedback():
    return render_template('feedback.html', username=current_user.username)

@app.route('/contact')
@login_required
def contact():
    return render_template('contact.html', username=current_user.username)

@app.route('/my-library', methods=['GET', 'POST'])
@login_required
def my_library():
    form = BookUploadForm()
    books = Book.query.filter_by(uploaded_by=current_user.id).all()

    if form.validate_on_submit():
        book_file = form.book.data
        filename = secure_filename(book_file.filename)  # Secure the filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Save the file to the uploads folder
        book_file.save(file_path)

        # Save book details to the database
        new_book = Book(
            title=form.book_name.data,
            author=form.author.data,
            category=form.category.data,
            description=form.description.data,
            image_url=form.image_url.data,  # Save the image URL
            filename=filename,
            file_path=file_path,
            uploaded_by=current_user.id
        )
        db.session.add(new_book)
        db.session.commit()
        flash("Book uploaded successfully!", "success")

        return redirect(url_for('my_library'))

    return render_template('my-library.html', username=current_user.username, uploaded_books=books, form=form)

@app.route('/fantasy')
@login_required
def fantasy():
    books = Book.query.filter_by(category="Fantasy").all()
    return render_template('fantasy.html', username=current_user.username, books=books)

@app.route('/science')
@login_required
def science():
    books = Book.query.filter_by(category="Science").all()
    return render_template('science.html', username=current_user.username, books=books)

@app.route('/biographies')
@login_required
def biographies():
    books = Book.query.filter_by(category="Biographies").all()
    return render_template('biographies.html', username=current_user.username, books=books)

@app.route('/technology')
@login_required
def technology():
    books = Book.query.filter_by(category="Technology").all()
    return render_template('technology.html', username=current_user.username, books=books)

@app.route('/eduvault')
@login_required
def eduvault():
    books = Book.query.filter_by(category="Edu Vault").all()
    return render_template('eduvault.html', username=current_user.username, books=books)

@app.route('/comics')
@login_required
def comics():
    books = Book.query.filter_by(category="Comics").all()
    return render_template('comics.html', username=current_user.username, books=books)

@app.route('/fiction')
@login_required
def fiction():
    books = Book.query.filter_by(category="Fiction").all()
    return render_template('fiction.html', username=current_user.username, books=books)

@app.route('/History')
@login_required
def history():
    books = Book.query.filter_by(category="History").all()
    return render_template('history.html', username=current_user.username, books=books)

@app.route('/mystery')
@login_required
def mystery():
    books = Book.query.filter_by(category="Mystery").all()
    return render_template('mystery.html', username=current_user.username, books=books)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

@app.route('/science-books', methods=['GET'])
def get_science_books():
    science_books = Book.query.filter_by(category="Science").all()
    
    books_list = [
        {
            "title": book.title,
            "author": book.author,
            "image": book.image_url if hasattr(book, 'image_url') else None,
            "file": book.file_path
        }
        for book in science_books
    ]

    return jsonify(books_list)

@app.route('/edit-book', methods=['POST'])
@login_required
def edit_book():
    book_id = request.form.get('book_id')
    book = Book.query.get(book_id)
    
    # Check if book exists and belongs to current user
    if not book or book.uploaded_by != current_user.id:
        flash("Book not found or you don't have permission to edit it.", "danger")
        return redirect(url_for('my_library'))
    
    # Update book details
    book.title = request.form.get('book_name')
    book.author = request.form.get('author')
    book.category = request.form.get('category')
    book.description = request.form.get('description')
    
    # Only update image_url if the column exists
    if hasattr(book, 'image_url'):
        book.image_url = request.form.get('image_url')
    
    db.session.commit()
    flash("Book details updated successfully!", "success")
    return redirect(url_for('my_library'))

@app.route('/delete-book', methods=['POST'])
@login_required
def delete_book():
    book_id = request.form.get('book_id')
    book = Book.query.get(book_id)
    
    # Check if book exists and belongs to current user
    if not book or book.uploaded_by != current_user.id:
        flash("Book not found or you don't have permission to delete it.", "danger")
        return redirect(url_for('my_library'))
    
    # Get the file path
    file_path = book.file_path
    
    # Delete from database
    db.session.delete(book)
    db.session.commit()
    
    # Delete the file if it exists
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except:
            # Log error but continue if file deletion fails
            print(f"Could not delete file: {file_path}")
    
    flash("Book deleted successfully!", "success")
    return redirect(url_for('my_library'))

@app.route('/category/<category_name>')
def get_books(category_name):
    books = Book.query.filter_by(category=category_name).all()

    if not books:
        return jsonify([])  # Return an empty list if no books are found

    books_data = [
        {
            "id": book.id,
            "title": book.title,
            "author": book.author,
            "filename": book.filename,
            "image_url": book.image_url if hasattr(book, 'image_url') else None  # Safely access image_url
        }
        for book in books
    ]
    return jsonify(books_data)

UPLOAD_FOLDER = "static/uploads"  # Ensure this folder exists

@app.route('/download/<int:book_id>')
def download_book(book_id):
    book = Book.query.get(book_id)

    if not book:
        return abort(404, description="Book not found")

    file_path = os.path.join(UPLOAD_FOLDER, book.filename)

    if not os.path.exists(file_path):
        return abort(404, description="File not found")

    return send_from_directory(UPLOAD_FOLDER, book.filename, as_attachment=True)

# Database migration function to add the missing column
def migrate_database():
    with app.app_context():
        # Check if the column exists
        import sqlite3
        try:
            conn = sqlite3.connect('instance/users.db')
            cursor = conn.cursor()
            cursor.execute('PRAGMA table_info(book)')
            columns = [column[1] for column in cursor.fetchall()]
            
            # If image_url column doesn't exist, add it
            if 'image_url' not in columns:
                cursor.execute('ALTER TABLE book ADD COLUMN image_url TEXT')
                conn.commit()
                print("Added image_url column to book table")
            
            conn.close()
        except Exception as e:
            print(f"Migration error: {e}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
        migrate_database()  # Add the missing column
    app.run(debug=True)
from flask_wtf.csrf import CSRFProtect, generate_csrf
from wtforms.csrf.session import SessionCSRF
from flask_apscheduler import APScheduler
import datetime
from flask import Flask, render_template, redirect, send_file, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import nbformat
from nbformat.v4 import new_notebook, new_code_cell
from flask import make_response, request
import os
from flask_wtf import FlaskForm

from nbformat import write
from datetime import timedelta

app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_RELATIVE_PATH = "mynewdata.db"
DB_PATH = os.path.join(BASE_DIR, DB_RELATIVE_PATH)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisis'
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, "notebooks")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

class CustomCSRFProtect(CSRFProtect):
    def generate_csrf_token(self, form):
        expiration_time = datetime.utcnow() + timedelta(seconds=self.time_limit)
        expiration_timestamp = int(expiration_time.timestamp())
        return generate_csrf(form, self.csrf_secret, self.csrf_time_limit, expiration_timestamp)

csrf = CustomCSRFProtect(app)


@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        session = db.session
        return session.query(User).get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

with app.app_context():
    # Access Flask-SQLAlchemy within the application context
    db.create_all()

class RegisterForm(FlaskForm):
    class Meta:
        csrf = True
        csrf_class = SessionCSRF
        csrf_secret = app.config['SECRET_KEY']

    email = StringField(validators=[InputRequired(), Length(min=4, max=50)],
                       render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                            render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("An account with this email already exists. Please choose a different email.")

class LoginForm(FlaskForm):
    class Meta:
        csrf = True
        csrf_class = SessionCSRF
        csrf_secret = app.config['SECRET_KEY']

    email = StringField(validators=[InputRequired(), Length(min=4, max=50)],
                       render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                            render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

def save_nb(notebook_content, notebook_path):
    try:
        with open(notebook_path, 'w', encoding='utf-8') as f:
            write(notebook_content, f, version=4)
        return True
    except Exception as e:
        print(f"Error saving notebook: {e}")
        return False

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template(('dashboard.html'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        email = form.email.data
        existing_user_email = User.query.filter_by(email=email).first()

        if existing_user_email:
            flash("An account with this email already exists. Please choose a different email.", "error")
            return redirect(url_for('already_registered'))

        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registration completed successfully.", "success")
        return redirect(url_for('registration_completed'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            username = current_user.email.split('@')[0]
            create_notebook_for_user(username)
            return redirect(url_for('embed_notebook', username=username))

    return render_template('login.html', form=form)

def create_notebook_for_user(username):
    nb = new_notebook()
    code = "print('Hello, world!')"
    cell = new_code_cell(code)
    nb.cells.append(cell)
    notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")

    with open(notebook_path, 'w', encoding='utf-8') as f:
        nbformat.write(nb, f)

def get_expiration_time(username):
    expiration_minutes = 2

    # Get the current datetime
    current_time = datetime.now()

    # Create a timedelta object representing the duration of expiration_minutes
    expiration_duration = timedelta(minutes=expiration_minutes)

    # Add the expiration duration to the current time to get the expiration time
    expiration_time = current_time + expiration_duration

    return expiration_time

@app.route('/embed_notebook/<username>')
@login_required
def embed_notebook(username):
    notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")

    if not os.path.exists(notebook_path):
        return render_template('notebook_not_found.html', username=username)

    expiration_time = get_expiration_time(username)
    current_time = datetime.now()

    notebook_expired = session.get(f"{username}_expired", False)

    if notebook_expired or current_time > expiration_time:
        return render_template('notebook_expired.html', username=username)

    session[f"{username}_expired"] = True

    return render_template('embed_notebook.html', username=username)

@app.route('/notebook/<username>')
@login_required
def serve_notebook(username):
    notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")
    response = make_response(send_file(notebook_path, as_attachment=True))
    response.headers["Content-Disposition"] = f"attachment; filename={username}.ipynb"
    return response

@app.route('/save_notebook/<username>', methods=['PUT', 'POST'])
@csrf.exempt
def save_notebook_route(username):
    notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")

    # Load the existing notebook content
    existing_content = {}
    if os.path.exists(notebook_path):
        with open(notebook_path, 'r', encoding='utf-8') as f:
            existing_content = nbformat.read(f, as_version=4)

    # Update the notebook content with new changes
    existing_content['metadata']['last_saved'] = datetime.now().isoformat()

    # Save the updated content back to the file using the save_notebook function
    save_success = save_nb(existing_content, notebook_path)

    if save_success:
        return "Notebook saved successfully."
    else:
        return "Failed to save the notebook."


@app.route('/registration_completed')
def registration_completed():
    registration_completed = True
    return render_template('registration_completed.html', registration_completed=registration_completed)

@app.route('/already_registered')
def already_registered():
    already_registered = True
    return render_template('already_registered.html', already_registered=already_registered)

@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

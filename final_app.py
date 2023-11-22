from flask import Flask, render_template, url_for, redirect, send_file, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import nbformat
from nbformat.v4 import new_notebook, new_code_cell
from flask import make_response
import requests
import os
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
import datetime

app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_RELATIVE_PATH = "mynewdata.db"
DB_PATH = os.path.join(BASE_DIR, DB_RELATIVE_PATH)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisis'
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, "notebooks")
JUPYTER_SERVER_URL = "http://10.80.2.117:8892"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# CSRF protection
csrf = CSRFProtect(app)

# Global dictionary to track notebook submissions
notebook_submissions = {}

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
    email = StringField(validators=[InputRequired(), Length(min=4, max=50)],
                       render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                            render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    # Check if the form is submitted and the request method is POST
    if form.is_submitted() and request.method == 'POST':
        email = form.email.data

        # Check if an account with this email already exists
        existing_user_email = User.query.filter_by(email=email).first()

        if existing_user_email:
            flash("An account with this email already exists. Please choose a different email.", "error")
            return redirect(url_for('already_registered'))

    # If the form is not submitted or the email is unique, proceed with form validation
    if form.validate_on_submit():
        # Create a new user with the provided email and hashed password
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)

        # Add the new user to the database
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

            # Check if the user has an existing notebook
            notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")
            if os.path.exists(notebook_path):
                # Load the existing notebook content
                with open(notebook_path, 'r', encoding='utf-8') as f:
                    existing_content = nbformat.read(f, as_version=4)
            else:
                # If no existing notebook, create a new one
                create_notebook_for_user(username)
                existing_content = None

            # Check if notebook has been submitted
            if notebook_submissions.get(username, False):
                return render_template('submission_success.html')

            return render_template('embed_notebook.html', username=username, existing_content=existing_content)

    return render_template('login.html', form=form)

def create_notebook_for_user(username):
    nb = new_notebook()
    code = "print('Hello, world!')"
    cell = new_code_cell(code)
    nb.cells.append(cell)
    notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")

    with open(notebook_path, 'w', encoding='utf-8') as f:
        nbformat.write(nb, f)

@app.route('/submit_notebook/<username>', methods=['POST'])
# def submit_notebook(username):
#     notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")
#
#     try:
#         content = request.json.get('content', '')
#
#         with open(notebook_path, 'w', encoding='utf-8') as f:
#             f.write(content)
#
#         # Set the notebook_submitted status for the current user in the session
#         session['notebook_submitted'] = True
#
#         return jsonify({"status": "success", "message": "Notebook submitted successfully."})
#     except Exception as e:
#         print(f"Error submitting notebook: {e}")
#         return jsonify({"status": "error", "message": "Failed to submit the notebook."})




def submit_notebook(username):
    notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")

    try:
        content = request.json.get('content', '')

        with open(notebook_path, 'w', encoding='utf-8') as f:
            f.write(content)

        # Set the notebook_submitted status for the current user in the session
        session['notebook_submitted'] = True

        return redirect(url_for('submission_success'))

    except Exception as e:
        print(f"Error submitting notebook: {e}")
        return jsonify({"status": "error", "message": "Failed to submit the notebook."})

@app.route('/embed_notebook/<username>')
@login_required
def embed_notebook(username):
    # Check if the notebook has been submitted using the session variable
    if session.get('notebook_submitted'):
        return render_template('submission_success.html')

    notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")
    jupyter_server_info_url = f"{JUPYTER_SERVER_URL}/api"

    if not os.path.exists(notebook_path):
        return render_template('notebook_not_found.html', username=username)

    try:
        response = requests.get(jupyter_server_info_url)
        if response.status_code == 200:
            jupyter_port = response.json().get("port")
        else:
            return "Failed to retrieve Jupyter server information. Is the Jupyter server running?"
    except requests.exceptions.RequestException:
        return "Unable to connect to Jupyter server. Is the Jupyter server running?"

    return render_template('embed_notebook.html', username=username)

@app.route('/notebook/<username>')
@login_required
def serve_notebook(username):
    notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")
    response = make_response(send_file(notebook_path, as_attachment=True))
    response.headers["Content-Disposition"] = f"attachment; filename={username}.ipynb"
    return response

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
# def logout():
#     logout_user()
#     return redirect(url_for('login'))
def logout():
    session.pop('notebook_submitted', None)
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

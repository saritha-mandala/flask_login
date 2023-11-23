from flask import Flask, render_template, url_for, redirect, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import nbformat
from nbformat.v4 import new_notebook, new_code_cell
from flask import make_response, flash, request
import requests
import os
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import exists


from flask import jsonify

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

# CSRF protection
csrf = CSRFProtect(app)

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
class AdminRegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=50)],
                       render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                            render_kw={"placeholder": "Password"})
    submit = SubmitField("Register as Admin")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("An account with this email already exists. Please choose a different email.")


class UserRegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=50)],
                       render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                            render_kw={"placeholder": "Password"})
    submit = SubmitField("Register as User")

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
@app.route('/user_home')
def user_home():
    return render_template('user_home.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template(('dashboard.html'))





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

@app.route('/embed_notebook/<username>')
@login_required
def embed_notebook(username):
    notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")

    if not os.path.exists(notebook_path):
        return render_template('notebook_not_found.html', username=username)

    return render_template('embed_notebook.html', username=username)

@app.route('/notebook/<username>')
@login_required
def serve_notebook(username):
    notebook_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{username}.ipynb")
    response = make_response(send_file(notebook_path, as_attachment=True))
    response.headers["Content-Disposition"] = f"attachment; filename={username}.ipynb"
    return response

@app.route('/save_notebook/<username>', methods=['PUT', 'POST'])
@csrf.exempt  # Exempt this route from CSRF protection
def save_notebook(username):
    notebook_server_url = "http://10.80.1.111:5000"
    notebook_path = f"/notebooks/{username}.ipynb"
    save_url = f"{notebook_server_url}/api/contents{notebook_path}"

    # Ensure that the 'content' key is present in the JSON payload
    if 'content' not in request.json:
        return jsonify({"error": "Missing 'content' key in the request payload"}), 400

    # Extract the content from the request payload
    content = request.json['content']

    # Create the params dictionary with the provided content
    params = {
        "path": notebook_path,
        "type": "notebook",
        "format": "json",
        "content": content,
    }

    # Send the request to the Jupyter Notebook server
    response = None
    if request.method == 'PUT':
        response = requests.put(save_url, json=params)
    elif request.method == 'POST':
        response = requests.post(save_url, json=params)
    else:
        return jsonify({"error": "Unsupported method"}), 405

    # Check the response status
    if response.status_code == 201:
        return jsonify({"message": "Notebook saved successfully."}), 200
    else:
        return jsonify({"error": f"Failed to save the notebook. Status: {response.status_code}"}), response.status_code

@app.route('/registration_completed')
def registration_completed():
    registration_completed = True
    return render_template('registration_completed.html', registration_completed=registration_completed)

@app.route('/already_registered')
def already_registered():
    already_registered = True
    return render_template('already_registered.html', already_registered=already_registered)
@app.route('/register/admin', methods=['GET', 'POST'])
def admin_register():
    form = AdminRegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        # You can use a specific password for admin users
        # For example, 'admin_password_hash' can be a predefined hash for admin users
        if form.password.data == 'admin_password':
            hashed_password = 'admin_password_hash'

        new_admin = User(email=form.email.data, password=hashed_password)

        db.session.add(new_admin)
        db.session.commit()

        flash("Admin registration completed successfully.", "success")
        return redirect(url_for('registration_completed'))

    return render_template('admin_register.html', form=form)


@app.route('/register/user', methods=['GET', 'POST'])
def user_register():
    form = UserRegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash("User registration completed successfully.", "success")
        return redirect(url_for('registration_completed'))

    return render_template('user_register.html', form=form)
@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

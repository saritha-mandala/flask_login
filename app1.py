from flask import Flask, render_template, flash, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import nbformat
from nbformat.v4 import new_notebook, new_code_cell
from flask import make_response
import os
import requests

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C://Users//saritha.mandala//Desktop//flask_login//mynewdata.db'
app.config['SECRET_KEY'] = 'thisis'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

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

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        existing_user_email = User.query.filter_by(email=email).first()
        if existing_user_email:
            flash("An account with this email already exists. Please choose a different email.", "error")
            return redirect(url_for('already_registered'))

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
    try:
        nb = new_notebook()
        code = "print('Hello, world!')"
        cell = new_code_cell(code)
        nb.cells.append(cell)
        notebook_path = f"notebooks/{username}.ipynb"
        notebook_full_path = os.path.join(os.getcwd(), notebook_path)
        print("notebook full path",notebook_full_path)
        with open(notebook_full_path, 'w', encoding='utf-8') as f:
            nbformat.write(nb, f)
    except Exception as e:
        print(f"Error creating notebook for {username}: {str(e)}")

@app.route('/embed_notebook/<username>')
@login_required
def embed_notebook(username):
    notebook_path = f"notebooks/{username}.ipynb"
    if not os.path.exists(notebook_path):
        return render_template('notebook_not_found.html', username=username)

    # Query the Jupyter server's API to get the current port (replace this with your actual API URL)
    jupyter_server_info_url = "http://127.0.0.1:8888/api"
    try:
        response = requests.get(jupyter_server_info_url)
        if response.status_code == 200:
            jupyter_port = response.json().get("port")
        else:
            return "Failed to retrieve Jupyter server information"
    except requests.exceptions.RequestException:
        return "Unable to connect to Jupyter server"

    # Pass the jupyter_port as a context variable to the template
    return render_template('embed_notebook.html', username=username, jupyter_port=jupyter_port)

@app.route('/notebook/<username>')
@login_required
def serve_notebook(username):
    notebook_path = f"notebooks/{username}.ipynb"
    response = make_response(send_file(notebook_path, as_attachment=True))
    response.headers["Content-Disposition"] = f"attachment; filename={username}.ipynb"
    return response

@app.route('/save_notebook/<username>', methods=['POST'])
def save_notebook(username):
    notebook_server_url = f"http://127.0.0.1:{{ jupyter_port }}"
    notebook_path = f"/notebooks/{username}.ipynb"
    save_url = f"{notebook_server_url}/api/contents{notebook_path}"

    params = {
        "path": notebook_path,
        "type": "notebook",
        "format": "json",
        "content": {
            "name": f"{username}.ipynb",
            "path": notebook_path,
            "format": "json",
            "type": "notebook",
            "content": {
                "cells": [],
                "metadata": {},
                "nbformat": 4,
                "nbformat_minor": 2,
            },
            "writable": True,
            "name": f"{username}.ipynb",
            "mimetype": None,
            "format": "json",
            "type": "notebook",
            "content": {},
        }
    }

    response = requests.put(save_url, json=params)

    if response.status_code == 201:
        return "Notebook saved successfully."
    else:
        return "Failed to save the notebook"

@app.route('/registration_completed')
def registration_completed():
    registration_completed = True
    form = RegisterForm()
    return render_template('register.html', registration_completed=registration_completed, form=form)

@app.route('/already_registered')
def already_registered():
    already_registered = True
    form = RegisterForm()
    return render_template('register.html', already_registered=already_registered, form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)

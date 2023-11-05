from flask import Flask, render_template, url_for, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_wtf import form, FlaskForm

from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt
import nbformat
from nbformat.v4 import new_notebook, new_code_cell
from flask import make_response
import os
import requests



app=Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///C://Users//saritha.mandala//Desktop//flask_login//mynewdata.db'
app.config['SECRET_KEY']='thisis'
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
login_manager= LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(30),nullable=False,unique=True)
    password = db.Column(db.String(80),nullable=False)

with app.app_context():
    # Access Flask-SQLAlchemy within the application context
    db.create_all()
class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=50)],
                       render_kw={"placeholder": "Email"})  # Change the field name to 'email'
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                            render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("An account with this email already exists. Please choose a different email.")
class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(),Length(min=4,max=20)],
                         render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],
                             render_kw={"placeholder":"Password"})
    submit=SubmitField("Login")

@app.route('/')
def home():
    return render_template('home.html')

# @app.route('/login',methods=['GET','POST'])
# def login():
#     form= LoginForm()
#     if form.validate_on_submit():
#         user=User.query.filter_by(username=form.username.data).first()
#         if user:
#             if bcrypt.check_password_hash(user.password,form.password.data):
#                 login_user(user)
#                 return redirect(url_for('embed_notebook', username=current_user.username))
#     return render_template('login.html',form=form)




@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template(('dashboard.html'))
# @app.route('/embed_notebook/<username>')
# @login_required  # This route requires the user to be logged in
# def embed_notebook(username):
#     return render_template('embed_notebook.html', username=username)
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
# @app.route('/register',methods=['GET','POST'])
# def register():
#     form=RegisterForm()
#     if form.validate_on_submit():
#         hashed_password = bcrypt.generate_password_hash(form.password.data)
#         new_user=User(username=form.username.data,password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
#     return render_template('register.html',form=form)
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data  # Get the provided email
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        # Use the email as the username and store it in the 'username' field
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

    return render_template('register.html', form=form)



# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(username=form.username.data).first()
#         if user and bcrypt.check_password_hash(user.password, form.password.data):
#             login_user(user)
#
#             # Retrieve the username of the logged-in user
#             username = current_user.username
#
#             # Create a new notebook and save it in the user's directory
#             create_notebook_for_user(username)
#
#             return redirect(url_for('embed_notebook', username=username))
#
#     return render_template('login.html', form=form)
class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=50)],
                       render_kw={"placeholder": "Email"})  # Add an 'email' field
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                            render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

# Update the login route to use the email for username
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data  # Get the provided email
         # Extract the username from the email

        user = User.query.filter_by(email=email).first()
        username = email.split('@')[0]
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)

            # Retrieve the username of the logged-in user
            username = current_user.email.split('@')[0]

            # Create a new notebook and save it in the user's directory
            create_notebook_for_user(username)

            return redirect(url_for('embed_notebook', username=username))

    return render_template('login.html', form=form)


def create_notebook_for_user(username):


    # Create a new notebook
    nb = new_notebook()
    code = "print('Hello, world!')"
    cell = new_code_cell(code)

    # Add the code cell to the notebook
    nb.cells.append(cell)

    # Define the path for the notebook file in the user's workspace directory
    notebook_path = f"C://Users//saritha.mandala//Desktop//notebook//{username}.ipynb"

    # Save the notebook to the specified path
    with open(notebook_path, 'w', encoding='utf-8') as f:
        nbformat.write(nb, f)
# Update the /embed_notebook route
@app.route('/embed_notebook/<username>')
@login_required
def embed_notebook(username):
    # Define the path to the user's notebook
    notebook_path = f"C://Users//saritha.mandala//Desktop//notebook//{username}.ipynb"

    # Check if the notebook file exists
    if not os.path.exists(notebook_path):
        # Handle the case where the notebook doesn't exist
        return render_template('notebook_not_found.html', username=username)

    return render_template('embed_notebook.html', username=username)

# Create a new route to serve the notebook file
@app.route('/notebook/<username>')
@login_required
def serve_notebook(username):
    # Define the path to the user's notebook
    notebook_path = f"C://Users//saritha.mandala//Desktop//notebook//{username}.ipynb"

    # Serve the notebook as a file attachment
    response = make_response(send_file(notebook_path, as_attachment=True))
    response.headers["Content-Disposition"] = f"attachment; filename={username}.ipynb"
    return response

@app.route('/save_notebook/<username>', methods=['POST'])
def save_notebook(username):
    notebook_server_url = "http://127.0.0.1:8891"
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
        },
    }

    response = requests.put(save_url, json=params)

    if response.status_code == 201:
        return "Notebook saved successfully."
    else:
        return "Failed to save the notebook."





if __name__=='__main__':
    app.run(host='0.0.0.0', debug=True)

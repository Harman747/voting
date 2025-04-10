from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin, LoginManager, login_required, login_user,
    current_user, logout_user
)
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Build the SQLite database URI using the current working directory.
dbdir = "sqlite:///" + os.path.join(os.path.abspath(os.getcwd()), "database.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = "SomeSecret"
app.config["SQLALCHEMY_DATABASE_URI"] = dbdir
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# User model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# Updated user loader using Session.get to avoid legacy warning
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, int(user_id))

# Registration Form
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=50)])
    email = StringField("Email", validators=[InputRequired(), Length(min=5, max=50), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    submit = SubmitField("Sign Up")

# Login Form
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Log In")

# Home Page (protected)
@app.route("/")
@login_required
def index():
    return render_template("index.html")

# Signup Route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data, method="pbkdf2:sha256")
        new_user = Users(username=form.username.data, email=form.email.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("You've been registered successfully, now you can log in.")
        return redirect(url_for("login"))
    return render_template("signup.html", form=form)

# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for("index"))
        flash("Your credentials are invalid.")
    return render_template("login.html", form=form)

# Logout Route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You were logged out. See you soon!")
    return redirect(url_for("login"))

# Additional Pages (for demonstration)
@app.route("/vote")
@login_required
def vote_page():
    return render_template("vote.html")

@app.route("/where_to_vote")
def where_to_vote_page():
    return render_template("where_to_vote.html")

@app.route("/news")
def news_page():
    return render_template("news.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True)

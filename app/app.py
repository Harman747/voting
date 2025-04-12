from flask import Flask, render_template, redirect, url_for, flash , request , session
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin, LoginManager, login_required, login_user,
    current_user, logout_user
)
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from blockchain.blockchain import blockchain
from database.connect import connect_to_database
import json
import mysql.connector
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

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


class Party(db.Model):
    __tablename__ = 'party'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)



class ValidAadhar(db.Model):
    __tablename__ = 'valid_aadhar'
    id = db.Column(db.Integer, primary_key=True)
    aadhar = db.Column(db.String(12), unique=True, nullable=False)
    voter_id = db.Column(db.String(10), unique=True, nullable=False)
    voted = db.Column(db.Boolean, default=False)



def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Harman@5056",
        database="elixir"
    )

my_database = get_db_connection()
my_chain = blockchain()
my_cursor = my_database.cursor()



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
    if current_user.is_authenticated:
        return redirect(url_for("vote_page"))  # Already logged in

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
    return redirect(url_for("login"))

# Voting route
@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote_page():
    if request.method == 'POST':
        aadhar = request.form['aadhar']
        voter_id = request.form['voter_id']
        name = request.form['name']
        phone = request.form['phone']
        party = request.form['party']

        if len(aadhar) != 12 or not aadhar.isdigit():
            flash("Aadhar number must be 12 digits.", "error")
            return redirect(url_for('vote_page'))

        if len(voter_id) != 10 or not voter_id.isdigit():
            flash("Voter ID must be 10 digits.", "error")
            return redirect(url_for('vote_page'))

        db = connect_to_database()
        cursor = db.cursor()

        cursor.execute("SELECT voted FROM valid_aadhar WHERE aadhar = %s AND voter_id = %s", (aadhar, voter_id))
        result = cursor.fetchone()

        if not result:
            flash("Invalid Aadhar/Voter ID combination.", "error")
            return redirect(url_for('vote_page'))

        if result[0]:  # Already voted
            flash("You have already voted.", "error")
            return redirect(url_for('vote_page'))

        data = {
            "aadhar": aadhar,
            "voter_id": voter_id,
            "name": name,
            "phone": phone
        }
        my_chain.add_to_blockchain(data, party)

        cursor.execute("UPDATE valid_aadhar SET voted = TRUE WHERE aadhar = %s AND voter_id = %s", (aadhar, voter_id))
        db.commit()
        db.close()

        flash("Vote successfully recorded!", "success")
        return redirect(url_for('result_page'))

    else:
        # ✅ This part handles GET: fetch fresh party list
        db = connect_to_database()
        cursor = db.cursor()
        cursor.execute("SELECT name FROM Party")
        rows = cursor.fetchall()
        parties = [row[0] for row in rows]  # ['BJP', 'INC'] etc.
        db.close()

        return render_template("vote.html", parties=parties)


@app.route("/results")
@login_required
def result_page():
    my_chain.my_blockchain.clear()
    my_chain.load_chain_from_db()
    chain = my_chain.my_blockchain

    counts = {}
    for block in chain[1:]:  # skip genesis block
        party = block[2]
        if party != "NULL":
            counts[party] = counts.get(party, 0) + 1

    return render_template("results.html", results=counts)


@app.route("/register_party", methods=["GET", "POST"])
@login_required
def register_party():
    if request.method == "POST":
        name = request.form["name"]
        president = request.form["president"]
        vice_president = request.form["vice_president"]
        secretary = request.form["secretary"]
        email = request.form["email"]
        phone = request.form["phone"]

        try:
            db = get_db_connection()
            cursor = db.cursor()

            query = """
                INSERT INTO party (name, president, vice_president, secretary, email, phone)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            values = (name, president, vice_president, secretary, email, phone)
            cursor.execute(query, values)
            db.commit()

            cursor.close()
            db.close()

            flash("Party registered successfully!", "success")
            return redirect(url_for("register_party"))
        except Exception as e:
            print("Error:", e)
            flash("Error registering party. Please try again.", "danger")

    return render_template("register_party.html")

@app.route('/details')
def details():
    db = connect_to_database()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM Party")
    parties = cursor.fetchall()
    db.close()

    return render_template('details.html', parties=parties)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True)

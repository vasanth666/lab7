from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re

zephyr_app = Flask(__name__)
zephyr_app.config['SECRET_KEY'] = 'vasanth_nova_key'
zephyr_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nova_users.db'
zephyr_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

nebula_db = SQLAlchemy(zephyr_app)

class CosmosUser(nebula_db.Model):
    quasar_id = nebula_db.Column(nebula_db.Integer, primary_key=True)
    nova_firstname = nebula_db.Column(nebula_db.String(80), nullable=False)
    nova_lastname = nebula_db.Column(nebula_db.String(80), nullable=False)
    nova_email = nebula_db.Column(nebula_db.String(120), unique=True, nullable=False)
    nova_password = nebula_db.Column(nebula_db.String(120), nullable=False)

def orion_auth_required(f):
    @wraps(f)
    def stellar_decorated_function(*args, **kwargs):
        if 'nova_user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('andromeda_signin'))
        return f(*args, **kwargs)
    return stellar_decorated_function

@zephyr_app.route('/')
def homepage():
    return render_template('firstpage.html')

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'\d$', password):  
        return False
    return True

@zephyr_app.route('/nebula_register', methods=['GET', 'POST'])
def nebula_register():
    if request.method == 'POST':
        nova_firstname = request.form['firstname']
        nova_lastname = request.form['lastname']
        nova_email = request.form['email']
        nova_password = request.form['password']
        nova_confirm_password = request.form['confirm_password']
        
        if not all([nova_firstname, nova_lastname, nova_email, nova_password, nova_confirm_password]):
            flash('Please fill out all fields.', 'error')
            return redirect(url_for('nebula_register'))
        
        if nova_password != nova_confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('nebula_register'))
        
        if not validate_password(nova_password):
            flash('Password must be at least 8 characters long, contain a lowercase letter, an uppercase letter, and end with a number.', 'error')
            return redirect(url_for('nebula_register'))
        
        existing_cosmos_user = CosmosUser.query.filter_by(nova_email=nova_email).first()
        if existing_cosmos_user:
            flash('Email already registered. Please use a different email.', 'error')
            return redirect(url_for('nebula_register'))
        
        new_cosmos_user = CosmosUser(nova_firstname=nova_firstname,
                                     nova_lastname=nova_lastname,
                                     nova_email=nova_email,
                                     nova_password=generate_password_hash(nova_password))
        nebula_db.session.add(new_cosmos_user)
        nebula_db.session.commit()
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('pulsar_thankyou'))
    
    return render_template('signUp.html')

@zephyr_app.route('/pulsar_thankyou')
def pulsar_thankyou():
    return render_template('thankyou.html')

@zephyr_app.route('/andromeda_signin', methods=['GET', 'POST'])
def andromeda_signin():
    if request.method == 'POST':
        nova_email = request.form['email']
        nova_password = request.form['password']
        
        cosmos_user = CosmosUser.query.filter_by(nova_email=nova_email).first()
        if cosmos_user and check_password_hash(cosmos_user.nova_password, nova_password):
            session['nova_user_id'] = cosmos_user.quasar_id
            flash('Logged in successfully.', 'success')
            return redirect(url_for('secretpage'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('signIn.html')

@zephyr_app.route('/secretpage')
@orion_auth_required
def secretpage():
    return render_template('secretpage.html')

@zephyr_app.route('/blackhole_signout')
def blackhole_signout():
    session.pop('nova_user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('homepage'))

def initialize_database(app):
    with app.app_context():
        nebula_db.create_all()
        
if __name__ == '__main__':
    initialize_database(zephyr_app)
    zephyr_app.run(debug=True)

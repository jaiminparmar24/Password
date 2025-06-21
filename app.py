from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from key_manager import load_key

app = Flask(__name__)
app.secret_key = 'CahD5aq9mMSterLCqIZp0cbBPiSyoA4JNQYzPdpEyjM='

# DB Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# 🔐 Load encryption key
fernet = Fernet(load_key())

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password_encrypted = db.Column(db.LargeBinary)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Routes
@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        db.session.add(User(email=email, password=password))
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect('/dashboard')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']
    if request.method == 'POST':
        site = request.form['site']
        username = request.form['username']
        password = fernet.encrypt(request.form['password'].encode())
        db.session.add(Password(site=site, username=username, password_encrypted=password, user_id=user_id))
        db.session.commit()
    passwords = Password.query.filter_by(user_id=user_id).all()
    return render_template('dashboard.html', passwords=passwords, fernet=fernet)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/login')
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        old_pass = request.form['old_password']
        new_pass = request.form['new_password']

        if bcrypt.check_password_hash(user.password, old_pass):
            user.password = bcrypt.generate_password_hash(new_pass).decode('utf-8')
            db.session.commit()
            return "Password changed successfully! <a href='/dashboard'>Go back</a>"
        else:
            return "Old password incorrect. <a href='/change_password'>Try again</a>"

    return render_template('change_password.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()


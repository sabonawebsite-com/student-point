from flask import Flask, render_template, redirect, url_for, request, flash  
from flask_sqlalchemy import SQLAlchemy  
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user  
from werkzeug.security import generate_password_hash, check_password_hash  

app = Flask(__name__)  
app.config['SECRET_KEY'] = 'your_secret_key'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'  
db = SQLAlchemy(app)  
login_manager = LoginManager()  
login_manager.init_app(app)  

# User Model  
class User(UserMixin, db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    username = db.Column(db.String(150), unique=True, nullable=False)  
    password = db.Column(db.String(15), nullable=False)  

# Student Points Model  
class StudentPoints(db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    math = db.Column(db.Integer, nullable=False)  
    english = db.Column(db.Integer, nullable=False)  
    physics = db.Column(db.Integer, nullable=False)  
    chemistry = db.Column(db.Integer, nullable=False)  
    biology = db.Column(db.Integer, nullable=False)  

@login_manager.user_loader  
def load_user(user_id):  
    return User.query.get(int(user_id))  

@app.route('/')  
def home():  
    return render_template('login.html')  
@app.route('/update_points', methods=['POST'])  
@login_required  
def update_points():  
    math = request.form['math']  
    english = request.form['english']  
    physics = request.form['physics']  
    chemistry = request.form['chemistry']  
    biology = request.form['biology']  

    # Check if the user already has points recorded  
    points = StudentPoints.query.filter_by(user_id=current_user.id).first()  

    if points:  
        # Update existing points  
        points.math = math  
        points.english = english  
        points.physics = physics  
        points.chemistry = chemistry  
        points.biology = biology  
    else:  
        # Create new points entry  
        points = StudentPoints(  
            user_id=current_user.id,  
            math=math,  
            english=english,  
            physics=physics,  
            chemistry=chemistry,  
            biology=biology  
        )  
        db.session.add(points)  

    db.session.commit()  
    flash('Points updated successfully!')  
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])  
def login():  
    if request.method == 'POST':  
        username = request.form['username']  
        password = request.form['password']  
        user = User.query.filter_by(username=username).first()  
        if user and check_password_hash(user.password, password):  # Use hashed password check  
            login_user(user)  
            return redirect(url_for('dashboard'))  
        flash('Invalid credentials. Please try again❌👎.')
           
    return render_template('login.html')

@app.route('/dashboard')  
@login_required  
def dashboard():  
    points = StudentPoints.query.filter_by(user_id=current_user.id).first()  
    return render_template('dashboard.html', points=points)  

@app.route('/logout')  
@login_required  
def logout():  
    logout_user()  
    return redirect(url_for('home'))  

@app.route('/register', methods=['GET', 'POST'])  
def register():  
    if request.method == 'POST':  
        username = request.form['username']  
        password = request.form['password']  
        if User.query.filter_by(username=username).first():  # Check if username exists  
            flash('Username already exists. Please choose a different one.')  
            return redirect(url_for('register'))  
        hashed_password = generate_password_hash(password)  
        new_user = User(username=username, password=hashed_password)  
        db.session.add(new_user)  
        db.session.commit()  
        return redirect(url_for('login'))  
    return render_template('register.html')  

# Create the database tables if they don't exist  
with app.app_context():  
    db.create_all()  

if __name__ == '__main__':  
    app.run(debug=True)
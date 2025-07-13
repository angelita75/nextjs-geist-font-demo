import os
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-placeholder')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///travel_diary.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class DiaryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    country = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class IncidentReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    country = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    moderated = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    diaries = DiaryEntry.query.order_by(DiaryEntry.timestamp.desc()).all()
    incidents = IncidentReport.query.filter_by(moderated=True).all()
    return render_template('home.html', diaries=diaries, incidents=incidents)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/diary', methods=['GET', 'POST'])
@login_required
def diary():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        country = request.form['country']
        new_entry = DiaryEntry(title=title, content=content, country=country, user_id=current_user.id)
        db.session.add(new_entry)
        db.session.commit()
        flash('Diary entry added.')
        return redirect(url_for('home'))
    return render_template('diary.html')

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        description = request.form['description']
        country = request.form['country']
        latitude = request.form['latitude']
        longitude = request.form['longitude']
        try:
            lat = float(latitude)
            lng = float(longitude)
        except ValueError:
            flash('Invalid latitude or longitude.')
            return redirect(url_for('report'))
        new_report = IncidentReport(description=description, country=country, latitude=lat, longitude=lng, user_id=current_user.id)
        db.session.add(new_report)
        db.session.commit()
        flash('Incident report submitted.')
        return redirect(url_for('home'))
    return render_template('report.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    incidents = IncidentReport.query.order_by(IncidentReport.timestamp.desc()).all()
    return render_template('admin.html', incidents=incidents)

@app.route('/admin/moderate/<int:incident_id>', methods=['POST'])
@login_required
def moderate_incident(incident_id):
    if not current_user.is_admin:
        abort(403)
    incident = IncidentReport.query.get_or_404(incident_id)
    action = request.form.get('action')
    if action == 'approve':
        incident.moderated = True
    elif action == 'reject':
        db.session.delete(incident)
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    if User.query.filter_by(is_admin=True).first():
        flash('Admin user already exists.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        new_admin = User(username=username, is_admin=True)
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()
        flash('Admin user created. Please log in.')
        return redirect(url_for('login'))
    return render_template('create_admin.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import DataRequired, Email, Length
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import whois, requests, os
import exifread

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scam_reports.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_password'

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)

class ScamReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.String(300), nullable=True)
    scam_website = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='report', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    report_id = db.Column(db.Integer, db.ForeignKey('scam_report.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                 print("Logged in as admin")
                 return redirect(url_for('admin_dashboard'))
            else:
                 print("Logged in as admin")
                 return redirect(url_for('dashboard'))
        flash('Username or password is incorrect', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    reports = ScamReport.query.all()
    return render_template('dashboard.html', reports=reports)

@app.route('/report/<int:report_id>/vote/<vote_type>', methods=['POST'])
@login_required
def vote_report(report_id, vote_type):
    report = ScamReport.query.get_or_404(report_id)
    if vote_type == 'upvote':
        report.upvotes += 1
    elif vote_type == 'downvote':
        report.downvotes += 1
    db.session.commit()
    flash('Your vote has been recorded', 'success')
    return redirect(url_for('view_report', report_id=report_id))

@app.route('/report/<int:report_id>', methods=['GET', 'POST'])
@login_required
def view_report(report_id):
    report = ScamReport.query.get_or_404(report_id)
    if request.method == 'POST':
        text = request.form['comment']
        new_comment = Comment(text=text, user_id=current_user.id, report_id=report.id)
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully', 'success')
    return render_template('view_report.html', report=report, upvotes=report.upvotes, downvotes=report.downvotes)

@app.route('/submit_report', methods=['GET', 'POST'])
@login_required
def submit_report():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        scam_website = request.form['scam_website']
        evidence = None
        if 'evidence' in request.files:
            file = request.files['evidence']
            if file.filename:
                upload_folder = 'static/uploads'
                os.makedirs(upload_folder, exist_ok=True)
                evidence = os.path.join(upload_folder, file.filename)
                file.save(evidence)
        new_report = ScamReport(title=title, description=description, scam_website=scam_website, evidence=evidence, user_id=current_user.id)
        db.session.add(new_report)
        db.session.commit()
        flash('Scam report submitted successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('submit_report.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    print("🛠 current_user:", current_user.email)
    print("🛠 current_user.is_admin:", current_user.is_admin)

    if not current_user.is_admin:
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    users = User.query.all()
    reports = ScamReport.query.all()
    return render_template('admin_dashboard.html', users=users, reports=reports)

@app.route('/flag_report/<int:report_id>')
@login_required
def flag_report(report_id):
    if not current_user.is_admin:
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    report = ScamReport.query.get_or_404(report_id)
    report.flagged = True
    db.session.commit()
    flash('Report flagged successfully.', 'warning')
    return redirect(url_for('admin_dashboard'))
    
@app.route('/approve_report/<int:report_id>')
@login_required
def approve_report(report_id):
    if not current_user.is_admin:
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    report = ScamReport.query.get_or_404(report_id)
    report.approved = True
    db.session.commit()
    flash('Report approved successfully.', 'success')
    return redirect(url_for('admin_dashboard'))
    


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

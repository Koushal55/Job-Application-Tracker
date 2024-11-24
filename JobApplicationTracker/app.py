from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///applications.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'

db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if not authenticated

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    date_applied = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='Applied')
    notes = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('applications', lazy=True))

    def __repr__(self):
        return f'<Application {self.company} - {self.position}>'

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Context Processor to inject current year and user
@app.context_processor
def inject_globals():
    return {'current_year': datetime.now().year, 'current_user': current_user}

# Routes

## Home Page
@app.route('/')
@login_required
def index():
    applications = Application.query.filter_by(user_id=current_user.id).order_by(Application.date_applied.desc()).all()
    return render_template('index.html', applications=applications)

## Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Input validation
        if not username or not password or not confirm_password:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error creating user: {e}', 'danger')
            return redirect(url_for('register'))
    else:
        return render_template('register.html')

## Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input validation
        if not username or not password:
            flash('Please enter both username and password.', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')

## Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

## Add Application
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_application():
    if request.method == 'POST':
        company = request.form['company']
        position = request.form['position']
        date_applied = datetime.strptime(request.form['date_applied'], '%Y-%m-%d')
        status = request.form['status']
        notes = request.form['notes']

        new_application = Application(
            company=company,
            position=position,
            date_applied=date_applied,
            status=status,
            notes=notes,
            user_id=current_user.id
        )

        try:
            db.session.add(new_application)
            db.session.commit()
            flash('Application added successfully.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"There was an issue adding your application: {e}", 'danger')
            return redirect(url_for('add_application'))
    else:
        return render_template('add_application.html')

## Edit Application
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_application(id):
    application = Application.query.get_or_404(id)
    if application.user_id != current_user.id:
        flash('You do not have permission to edit this application.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        application.company = request.form['company']
        application.position = request.form['position']
        application.date_applied = datetime.strptime(request.form['date_applied'], '%Y-%m-%d')
        application.status = request.form['status']
        application.notes = request.form['notes']

        try:
            db.session.commit()
            flash('Application updated successfully.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"There was an issue updating your application: {e}", 'danger')
            return redirect(url_for('edit_application'))
    else:
        return render_template('edit_application.html', application=application)

## Delete Application
@app.route('/delete/<int:id>')
@login_required
def delete_application(id):
    application = Application.query.get_or_404(id)
    if application.user_id != current_user.id:
        flash('You do not have permission to delete this application.', 'danger')
        return redirect(url_for('index'))

    try:
        db.session.delete(application)
        db.session.commit()
        flash('Application deleted successfully.', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f"There was an issue deleting your application: {e}", 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
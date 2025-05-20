import os
import bcrypt
from datetime import datetime as dt # Renamed to dt to avoid conflict with datetime objects
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy import desc # Import desc for ordering

# Initialize Flask app
app = Flask(__name__)

# Configure SQLite database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_very_secret_key_here'  # Ensure this is strong and unique

# Initialize Flask-SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to 'login' view if user not authenticated
login_manager.login_message_category = 'info' # Flash message category

# User model updated for Flask-Login and password hashing
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Relationship to WalkingSession
    walking_sessions = db.relationship('WalkingSession', backref='walker', lazy='dynamic', order_by="desc(WalkingSession.date)")


    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def __repr__(self):
        return f'<User {self.username}>'

# WalkingSession Model Definition
class WalkingSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, default=lambda: dt.utcnow().date()) 
    start_time = db.Column(db.Time, nullable=True)
    end_time = db.Column(db.Time, nullable=True)
    duration_minutes = db.Column(db.Integer, nullable=False) # Total duration
    distance_km = db.Column(db.Float, nullable=True)
    walk_type = db.Column(db.String(50), nullable=False, default="Normal") 
    notes = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # New fields for IWT intervals
    fast_duration_minutes = db.Column(db.Integer, nullable=True)
    slow_duration_minutes = db.Column(db.Integer, nullable=True)


    def __repr__(self):
        return f"<WalkingSession {self.id} on {self.date} by User {self.user_id}>"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', title='Home')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password') 

        if not username or not email or not password or not confirm_password: 
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password: 
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        existing_user_email = User.query.filter_by(email=email).first()
        if existing_user_email:
            flash('Email address already registered. Please login or use a different email.', 'warning')
            return redirect(url_for('register'))
        
        existing_user_username = User.query.filter_by(username=username).first()
        if existing_user_username:
            flash('Username already taken. Please choose a different username.', 'warning')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash(f'Account created for {username}! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Both email and password are required.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user) 
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard')) 
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', title='Login')

@app.route('/logout')
@login_required 
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard') 
@login_required
def dashboard():
    # Query sessions for the current user, ordered by date descending
    # sessions = WalkingSession.query.filter_by(user_id=current_user.id).order_by(desc(WalkingSession.date)).all()
    # Using the relationship with lazy='dynamic' and order_by specified in the relationship:
    sessions = current_user.walking_sessions.all() 
    return render_template('dashboard.html', title='Dashboard', sessions=sessions)

@app.route('/add_session', methods=['GET', 'POST'])
@login_required
def add_session():
    if request.method == 'POST':
        date_str = request.form.get('date')
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')
        duration_minutes_str = request.form.get('duration_minutes')
        distance_km_str = request.form.get('distance_km')
        walk_type = request.form.get('walk_type')
        notes = request.form.get('notes')
        
        fast_duration_minutes_str = request.form.get('fast_duration_minutes')
        slow_duration_minutes_str = request.form.get('slow_duration_minutes')

        # Basic Validation
        if not date_str or not duration_minutes_str:
            flash('Date and Total Duration are required.', 'danger')
            return render_template('add_session.html', title='Add Walking Session', form_data=request.form)


        try:
            date_obj = dt.strptime(date_str, '%Y-%m-%d').date()
            duration_minutes = int(duration_minutes_str)
            if duration_minutes <= 0:
                flash('Total Duration must be a positive number.', 'danger')
                return render_template('add_session.html', title='Add Walking Session', form_data=request.form)
        except ValueError:
            flash('Invalid date or total duration format.', 'danger')
            return render_template('add_session.html', title='Add Walking Session', form_data=request.form)

        start_time_obj = None
        if start_time_str:
            try:
                start_time_obj = dt.strptime(start_time_str, '%H:%M').time()
            except ValueError:
                flash('Invalid start time format. Use HH:MM.', 'warning') # Not critical, proceed
        
        end_time_obj = None
        if end_time_str:
            try:
                end_time_obj = dt.strptime(end_time_str, '%H:%M').time()
            except ValueError:
                flash('Invalid end time format. Use HH:MM.', 'warning') # Not critical, proceed

        distance_km = None
        if distance_km_str:
            try:
                distance_km = float(distance_km_str)
                if distance_km < 0:
                    flash('Distance cannot be negative.', 'danger')
                    return render_template('add_session.html', title='Add Walking Session', form_data=request.form)
            except ValueError:
                flash('Invalid distance format.', 'danger')
                return render_template('add_session.html', title='Add Walking Session', form_data=request.form)

        fast_duration_minutes = None
        slow_duration_minutes = None

        if walk_type == 'IWT':
            if fast_duration_minutes_str:
                try:
                    fast_duration_minutes = int(fast_duration_minutes_str)
                    if fast_duration_minutes < 0:
                        flash('Fast duration minutes cannot be negative.', 'danger')
                        return render_template('add_session.html', title='Add Walking Session', form_data=request.form)
                except ValueError:
                    flash('Invalid format for fast duration minutes.', 'danger')
                    return render_template('add_session.html', title='Add Walking Session', form_data=request.form)
            
            if slow_duration_minutes_str:
                try:
                    slow_duration_minutes = int(slow_duration_minutes_str)
                    if slow_duration_minutes < 0:
                        flash('Slow duration minutes cannot be negative.', 'danger')
                        return render_template('add_session.html', title='Add Walking Session', form_data=request.form)
                except ValueError:
                    flash('Invalid format for slow duration minutes.', 'danger')
                    return render_template('add_session.html', title='Add Walking Session', form_data=request.form)
            

        new_session = WalkingSession(
            date=date_obj,
            start_time=start_time_obj,
            end_time=end_time_obj,
            duration_minutes=duration_minutes,
            distance_km=distance_km,
            walk_type=walk_type,
            notes=notes,
            fast_duration_minutes=fast_duration_minutes if walk_type == 'IWT' else None,
            slow_duration_minutes=slow_duration_minutes if walk_type == 'IWT' else None,
            user_id=current_user.id
        )
        db.session.add(new_session)
        db.session.commit()
        flash('Walking session added successfully!', 'success')
        return redirect(url_for('dashboard')) 

    return render_template('add_session.html', title='Add Walking Session', form_data=request.form if request.method == 'POST' else {})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)

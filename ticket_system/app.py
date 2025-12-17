from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from models import db, User, Ticket, Reply, TicketHistory
from seed import seed_data
from flask_mail import Mail, Message
import random
import string

import os
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler

from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from wtforms.fields import PasswordField

load_dotenv() # Load environment variables from .env file

app = Flask(__name__)

# Ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass
app.config['SECRET_KEY'] = 'jhdgfhgsdGFYEWBFEY764TRGEWG73G78GBEWBYGRFQYG4UYRFEB784gr87fb4fc87'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail configuration - REPLACE WITH YOUR CREDENTIALS
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ishantsingh559@gmail.com'  
app.config['MAIL_PASSWORD'] = 'fxrf ljjt pghv llnt'  
app.config['MAIL_DEFAULT_SENDER'] = 'ishantsingh@gmail.com' 

# Configure logging AFTER app is created
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

handler = RotatingFileHandler(os.path.join(log_dir, 'app.log'), maxBytes=10000, backupCount=1)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
handler.setFormatter(formatter)
app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)

if os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 't'):
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    app.logger.addHandler(console_handler)

db.init_app(app)
mail = Mail(app)


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login', next=request.url))

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'
    
    def inaccessible_callback(self, name, **kwargs):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login', next=request.url))
    
    # Hide the "Home" link from the admin panel's navigation if needed, or point it elsewhere
    # We set is_visible to True to make this main "Overview" link appear in the menu
    def is_visible(self):
        return True 

class UserAdminView(MyModelView):
    column_list = ('id', 'username', 'email', 'role', 'is_active', 'email_verified')
    column_searchable_list = ('username', 'email')
    column_filters = ('role', 'is_active', 'email_verified')
    form_columns = ('username', 'email', 'role', 'is_active', 'email_verified', 'password')
    form_overrides = {
        'password': PasswordField
    }
    form_widget_args = {
        'password': {
            'placeholder': 'Enter new password'
        }
    }

    def on_model_change(self, form, model, is_created):
        if form.password.data:
            model.password = generate_password_hash(form.password.data)

class TicketAdminView(MyModelView):
    column_list = ('id', 'title', 'author', 'status', 'priority', 'created_at')
    column_searchable_list = ('title', 'description')
    column_filters = ('status', 'priority')
    form_columns = ('title', 'description', 'status', 'priority', 'author')

class ReplyAdminView(MyModelView):
    column_list = ('id', 'ticket', 'commentor_name', 'role', 'created_at')
    column_searchable_list = ('message',)

class TicketHistoryAdminView(MyModelView):
    column_list = ('id', 'ticket', 'field_changed', 'old_value', 'new_value', 'changed_at', 'changed_by')
    can_edit = False
    can_create = False
    can_delete = False

admin = Admin(app, name='Support Ticket Admin', url='/admin_panel', 
              index_view=MyAdminIndexView(name='Overview', url='/admin_panel'))

admin.add_view(UserAdminView(User, db.session))
admin.add_view(TicketAdminView(Ticket, db.session))
admin.add_view(ReplyAdminView(Reply, db.session))
admin.add_view(TicketHistoryAdminView(TicketHistory, db.session))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        if current_user.role != 'admin':
            flash('You do not have permission to access this page.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Both email and password are required.", "danger")
            app.logger.warning('Login attempt with missing email or password.')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.', 'danger')
            app.logger.info(f'Failed login attempt for email: {email}')
            return redirect(url_for('login'))
        
        if not user.is_active:
            if user.email_verified:
                flash('Your account is pending administrator approval.', 'warning')
                app.logger.warning(f'Login attempt for unapproved user: {user.username}')
                return redirect(url_for('login'))
            else:
                otp = ''.join(random.choices(string.digits, k=6))
                user.otp = otp
                db.session.commit()
                try:
                    msg = Message('Your OTP for Account Activation', recipients=[user.email])
                    msg.body = f'Your new OTP is: {otp}'
                    mail.send(msg)
                    flash('Your account is not active. A new OTP has been sent to your email for verification.', 'warning')
                    app.logger.info(f'Resent OTP for unverified email user: {user.username}')
                    return redirect(url_for('verify_email', user_id=user.id))
                except Exception as e:
                    app.logger.error(f'Failed to send OTP to {user.email}: {e}')
                    flash('Failed to send OTP. Please check your email configuration.', 'danger')
                    return redirect(url_for('login'))

        login_user(user)
        app.logger.info(f'User {user.username} logged in successfully.')
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    app.logger.info(f'User {current_user.username} logged out.')
    logout_user()
    return redirect(url_for('login'))

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    try:
        mail.send(msg)
        app.logger.info(f'Password reset email sent to {user.email}.')
    except Exception as e:
        app.logger.error(f'Failed to send password reset email to {user.email}: {e}')

@app.route("/reset_password_request", methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash("Email address is required.", "danger")
            app.logger.warning('Password reset request with missing email.')
            return redirect(url_for('reset_password_request'))
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            app.logger.info(f'Password reset requested for {email}.')
        else:
            app.logger.info(f'Password reset requested for non-existent email: {email}.')
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html')

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        app.logger.warning(f'Invalid or expired password reset token received: {token}')
        return redirect(url_for('reset_password_request'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or not confirm_password:
            flash('Both password fields are required.', "danger")
            app.logger.warning(f'Password reset attempt with missing fields for user: {user.username}')
            return redirect(url_for('reset_password', token=token))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', "danger")
            app.logger.warning(f'Password reset attempt with too short password for user: {user.username}')
            return redirect(url_for('reset_password', token=token))

        if password != confirm_password:
            flash('Passwords do not match.', "danger")
            app.logger.warning(f'Password reset attempt with non-matching passwords for user: {user.username}')
            return redirect(url_for('reset_password', token=token))
        
        hashed_password = generate_password_hash(password)
        user.password = hashed_password
        db.session.commit()
        app.logger.info(f'Password successfully reset for user: {user.username}')
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            flash("All fields are required!", "danger")
            app.logger.warning('Registration attempt with missing fields.')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            app.logger.warning('Registration attempt with non-matching passwords.')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            app.logger.warning('Registration attempt with too short password.')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            app.logger.warning(f'Registration attempt with existing username: {username}')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            app.logger.warning(f'Registration attempt with existing email: {email}')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        otp = ''.join(random.choices(string.digits, k=6))
        
        new_user = User(
            username=username,
            email=email,
            password=hashed_pw,
            otp=otp
        )
        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f'New user registered: {new_user.username} ({new_user.email})')

        try:
            msg = Message('Your OTP for Registration', recipients=[email])
            msg.body = f'Your OTP is: {otp}'
            mail.send(msg)
            app.logger.info(f'OTP sent to {email} for registration.')
            flash('An OTP has been sent to your email. Please verify to activate your account.', 'info')
            return redirect(url_for('verify_email', user_id=new_user.id))
        except Exception as e:
            app.logger.error(f'Failed to send OTP to {email} during registration: {e}')
            flash('Failed to send OTP. Please check your email configuration.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/verify_email/<int:user_id>', methods=['GET', 'POST'])
def verify_email(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_active:
        flash('Account already verified. Please log in.', 'info')
        app.logger.info(f'Attempt to verify already active account for user: {user.username}')
        return redirect(url_for('login'))

    if request.method == 'POST':
        submitted_otp = request.form.get('otp')
        if not submitted_otp:
            flash("OTP cannot be empty.", "danger")
            app.logger.warning(f'OTP verification attempt with empty OTP for user: {user.username}')
            return redirect(url_for('verify_email', user_id=user_id))
        
        if submitted_otp == user.otp:
            user.email_verified = True
            user.otp = None  # Clear OTP after successful verification
            db.session.commit()
            app.logger.info(f'Email successfully verified for user: {user.username}')
            flash('Your email has been verified. Your account is now pending administrator approval.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', "danger")
            app.logger.warning(f'Invalid OTP attempt for user: {user.username}')

    return render_template('verify_email.html', user_id=user_id)



@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 10 # Number of tickets per page

    tickets_query = Ticket.query.filter_by(user_id=current_user.id)
    tickets = tickets_query.paginate(page=page, per_page=per_page, error_out=False)

    total_tickets = tickets_query.count()
    open_tickets = tickets_query.filter(Ticket.status != 'Resolved').count()
    resolved_tickets = tickets_query.filter_by(status='Resolved').count()
    app.logger.info(f'User {current_user.username} accessed dashboard.')
    return render_template('dashboard.html', tickets=tickets, total_tickets=total_tickets, open_tickets=open_tickets, resolved_tickets=resolved_tickets)

@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        priority = request.form.get('priority')

        if not title or not description:
            flash("Title and Description cannot be empty.", "danger")
            app.logger.warning(f'Ticket creation attempt with missing title or description by user: {current_user.username}')
            return redirect(url_for('create_ticket'))

        new_ticket = Ticket(title=title, description=description, category=category, priority=priority, user_id=current_user.id)
        db.session.add(new_ticket)
        db.session.commit()
        app.logger.info(f'Ticket {new_ticket.id} created by user: {current_user.username}')
        flash('Ticket created successfully!')
        return redirect(url_for('dashboard'))
    return render_template('create_ticket.html')

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    # Access control: regular user can only view their own tickets
    if current_user.role != 'admin' and ticket.user_id != current_user.id:
        flash("You are not authorized to view this ticket.", "danger")
        app.logger.warning(f'Unauthorized access attempt to ticket {ticket_id} by user: {current_user.username}')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        message = request.form.get('message')

        if not message:
            flash("Reply message cannot be empty.", "danger")
            app.logger.warning(f'Reply attempt with empty message for ticket {ticket_id} by user: {current_user.username}')
            return redirect(url_for('ticket_detail', ticket_id=ticket_id))

        reply = Reply(message=message, ticket_id=ticket_id, commentor_name=current_user.username, role=current_user.role)
        db.session.add(reply)
        db.session.commit()
        app.logger.info(f'Reply added to ticket {ticket_id} by user: {current_user.username}')
        flash('Reply added successfully!')
        return redirect(url_for('ticket_detail', ticket_id=ticket_id))
    replies = Reply.query.filter_by(ticket_id=ticket_id).all()
    history = TicketHistory.query.filter_by(ticket_id=ticket_id).order_by(TicketHistory.changed_at.asc()).all()
    app.logger.info(f'User {current_user.username} viewed ticket {ticket_id}.')
    return render_template('ticket_detail.html', ticket=ticket, replies=replies, history=history)

@app.route('/ticket/<int:ticket_id>/update_status', methods=['POST'])
@login_required
@admin_required
def update_ticket_status(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    new_status = request.form.get('status')
    new_priority = request.form.get('priority')

    if new_status and ticket.status != new_status:
        app.logger.info(f'Admin {current_user.username} changed status of ticket {ticket_id} from {ticket.status} to {new_status}.')
        history_log = TicketHistory(
            ticket_id=ticket.id,
            field_changed='Status',
            old_value=ticket.status,
            new_value=new_status,
            changed_by_id=current_user.id
        )
        db.session.add(history_log)
        ticket.status = new_status

    if new_priority and ticket.priority != new_priority:
        app.logger.info(f'Admin {current_user.username} changed priority of ticket {ticket_id} from {ticket.priority} to {new_priority}.')
        history_log = TicketHistory(
            ticket_id=ticket.id,
            field_changed='Priority',
            old_value=ticket.priority,
            new_value=new_priority,
            changed_by_id=current_user.id
        )
        db.session.add(history_log)
        ticket.priority = new_priority
    
    db.session.commit()
    flash('Ticket has been updated successfully!', 'success')
    return redirect(url_for('ticket_detail', ticket_id=ticket.id))


@app.route('/admin')
@login_required
@admin_required
def admin():
    page = request.args.get('page', 1, type=int)
    per_page = 10 # Number of tickets per page

    status_filter = request.args.get('status')
    priority_filter = request.args.get('priority')
    search_query = request.args.get('search_query')

    tickets_query = Ticket.query

    if status_filter:
        tickets_query = tickets_query.filter_by(status=status_filter)
    if priority_filter:
        tickets_query = tickets_query.filter_by(priority=priority_filter)
    if search_query:
        tickets_query = tickets_query.filter(
            (Ticket.title.ilike(f'%{search_query}%')) |
            (Ticket.description.ilike(f'%{search_query}%'))
        )
    
    tickets = tickets_query.paginate(page=page, per_page=per_page, error_out=False)

    total_tickets = Ticket.query.count()
    open_tickets = Ticket.query.filter_by(status='Open').count()
    resolved_tickets = Ticket.query.filter_by(status='Resolved').count()
    high_priority_tickets = Ticket.query.filter_by(priority='High').count()
    app.logger.info(f'Admin {current_user.username} accessed admin dashboard with filters: status={status_filter}, priority={priority_filter}, search="{search_query}".')
    return render_template('admin.html', tickets=tickets, total_tickets=total_tickets, open_tickets=open_tickets, 
                           resolved_tickets=resolved_tickets, high_priority_tickets=high_priority_tickets,
                           selected_status=status_filter, selected_priority=priority_filter, search_query=search_query)

@app.route('/admin/pending_users')
@login_required
@admin_required
def pending_users():
    users_to_approve = User.query.filter_by(email_verified=True, is_active=False).all()
    app.logger.info(f'Admin {current_user.username} viewed pending user approvals.')
    return render_template('pending_users.html', users=users_to_approve)

@app.route('/admin/approve_user/<int:user_id>')
@login_required
@admin_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = True
    db.session.commit()
    app.logger.info(f'Admin {current_user.username} approved user: {user.username}.')
    flash(f"User '{user.username}' has been approved and can now log in.", 'success')
    return redirect(url_for('pending_users'))

@app.cli.command('seed')
def seed_command():
    """Seeds the database with initial data."""
    seed_data(app)
    print("Database seeded!")

@app.cli.command('create-admin')
def create_admin_command():
    """Creates a new admin user."""
    with app.app_context():
        username = input("Enter username for new admin: ")
        email = input("Enter email for new admin: ")
        password = input("Enter password for new admin: ")

        if not username or not email or not password:
            print("Username, email, and password cannot be empty.")
            return

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User with username '{username}' already exists.")
            return

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            print(f"User with email '{email}' already exists.")
            return

        hashed_password = generate_password_hash(password)
        new_admin = User(
            username=username,
            email=email,
            password=hashed_password,
            role='admin',
            is_active=True,
            email_verified=True
        )
        db.session.add(new_admin)
        db.session.commit()
        print(f"Admin user '{username}' created successfully!")

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True,port=7000)

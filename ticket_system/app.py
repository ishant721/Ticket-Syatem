from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from models import db, User, Ticket, Reply
from flask_mail import Mail, Message
import random
import string

import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'jhdgfhgsdGFYEWBFEY764TRGEWG73G78GBEWBYGRFQYG4UYRFEB784gr87fb4fc87'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail configuration - REPLACE WITH YOUR CREDENTIALS
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ishantsingh559@gmail.com'  
app.config['MAIL_PASSWORD'] = 'yikr xawd pqeo ydwu'  
app.config['MAIL_DEFAULT_SENDER'] = 'ishantsingh@gmail.com' 

db.init_app(app)
mail = Mail(app)


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

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
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))
        
        if not user.is_active:
            if user.email_verified:
                flash('Your account is pending administrator approval.', 'warning')
                return redirect(url_for('login'))
            else:
                # User has not verified their email yet, resend OTP
                otp = ''.join(random.choices(string.digits, k=6))
                user.otp = otp
                db.session.commit()
                try:
                    msg = Message('Your OTP for Account Activation', recipients=[user.email])
                    msg.body = f'Your new OTP is: {otp}'
                    mail.send(msg)
                    flash('Your account is not active. A new OTP has been sent to your email for verification.', 'warning')
                    return redirect(url_for('verify_email', user_id=user.id))
                except Exception as e:
                    # print(e)
                    flash('Failed to send OTP. Please check your email configuration.', 'danger')
                    return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
def logout():
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
    mail.send(msg)

@app.route("/reset_password_request", methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
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
        return redirect(url_for('reset_password_request'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        hashed_password = generate_password_hash(password)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash("Username already Exists!")
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash("Email already Exists!")
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

        try:
            msg = Message('Your OTP for Registration', recipients=[email])
            msg.body = f'Your OTP is: {otp}'
            mail.send(msg)
            flash('An OTP has been sent to your email. Please verify to activate your account.', 'info')
            return redirect(url_for('verify_email', user_id=new_user.id))
        except Exception as e:
            # For debugging, you might want to log this
            # print(e)
            flash('Failed to send OTP. Please check your email configuration.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/verify_email/<int:user_id>', methods=['GET', 'POST'])
def verify_email(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_active:
        flash('Account already verified. Please log in.', 'info')
        return redirect(url_for('login'))

    if request.method == 'POST':
        submitted_otp = request.form.get('otp')
        if submitted_otp == user.otp:
            user.email_verified = True
            user.otp = None  # Clear OTP after successful verification
            db.session.commit()
            flash('Your email has been verified. Your account is now pending administrator approval.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_email.html', user_id=user_id)



@app.route('/dashboard')
@login_required
def dashboard():
    tickets = Ticket.query.filter_by(user_id=current_user.id).all()
    total_tickets = len(tickets)
    open_tickets = len([t for t in tickets if t.status != 'Resolved'])
    resolved_tickets = len([t for t in tickets if t.status == 'Resolved'])
    return render_template('dashboard.html', tickets=tickets, total_tickets=total_tickets, open_tickets=open_tickets, resolved_tickets=resolved_tickets)

@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        priority = request.form.get('priority')
        new_ticket = Ticket(title=title, description=description, category=category, priority=priority, user_id=current_user.id)
        db.session.add(new_ticket)
        db.session.commit()
        flash('Ticket created successfully!')
        return redirect(url_for('dashboard'))
    return render_template('create_ticket.html')

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if request.method == 'POST':
        message = request.form.get('message')
        reply = Reply(message=message, ticket_id=ticket_id, commentor_name=current_user.username, role=current_user.role)
        db.session.add(reply)
        db.session.commit()
        flash('Reply added successfully!')
        return redirect(url_for('ticket_detail', ticket_id=ticket_id))
    replies = Reply.query.filter_by(ticket_id=ticket_id).all()
    return render_template('ticket_detail.html', ticket=ticket, replies=replies)

@app.route('/ticket/<int:ticket_id>/update_status', methods=['POST'])
@login_required
@admin_required
def update_ticket_status(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    new_status = request.form.get('status')
    new_priority = request.form.get('priority')

    if new_status:
        ticket.status = new_status
    if new_priority:
        ticket.priority = new_priority
    
    db.session.commit()
    flash('Ticket has been updated successfully!', 'success')
    return redirect(url_for('ticket_detail', ticket_id=ticket.id))


@app.route('/admin')
@login_required
@admin_required
def admin():
    tickets = Ticket.query.all()
    total_tickets = len(tickets)
    open_tickets = len([t for t in tickets if t.status != 'Resolved'])
    resolved_tickets = len([t for t in tickets if t.status == 'Resolved'])
    high_priority_tickets = len([t for t in tickets if t.priority == 'High'])
    return render_template('admin.html', tickets=tickets, total_tickets=total_tickets, open_tickets=open_tickets, resolved_tickets=resolved_tickets, high_priority_tickets=high_priority_tickets)

@app.route('/admin/pending_users')
@login_required
@admin_required
def pending_users():
    users_to_approve = User.query.filter_by(email_verified=True, is_active=False).all()
    return render_template('pending_users.html', users=users_to_approve)

@app.route('/admin/approve_user/<int:user_id>')
@login_required
@admin_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = True
    db.session.commit()
    flash(f"User '{user.username}' has been approved and can now log in.", 'success')
    return redirect(url_for('pending_users'))



with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True,port=7000)
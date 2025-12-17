# Ticket System (Flask Demo App)

## Project Description
This is a Flask-based Issue/Support Ticket Management System designed to demonstrate end-to-end backend thinking with clear role separation (User/Admin). It's a mini Zendesk/Freshdesk application that allows users to raise and track support tickets, while administrators can manage tickets, users, and system data through a comprehensive admin panel.

## Core Features

### 🔐 Authentication & Authorization
*   **Login / Register:** Users can create accounts and log in. Passwords are confirmed during registration.
*   **OTP Verification during Registration:** New users must verify their email with a One-Time Password (OTP).
*   **Admin Approval for New Users:** After email verification, new user accounts require approval from an administrator.
*   **Forgot Password:** Users can reset their password via an email link.
*   **Role-based Access:** Differentiates between 'user' and 'admin' roles.

### 🎫 Ticket Management
*   **Create Ticket:** Users can submit new support tickets with a title, description, category, and priority.
*   **Track Ticket Status:** Users can view the status of their submitted tickets.
*   **Update Ticket Status/Priority (Admin):** Administrators can update the status (Open, In Progress, Resolved) and priority (Low, Medium, High).
*   **Ticket History:** All changes to a ticket's status and priority are logged and viewable on the ticket detail page.

### 💬 Communication
*   **Ticket Replies:** Users and admins can post replies to tickets.

### 📊 Dashboards
*   **User Dashboard:** Displays a user's submitted tickets with a summary of total, open, and resolved tickets.
*   **Admin Dashboard:** A custom dashboard showing an overview of all tickets, with filtering and search capabilities.

### ⚙️ Admin Panel
*   **Full CRUD Operations:** Administrators have full Create, Read, Update, and Delete capabilities for Users, Tickets, Replies, and Ticket History.
*   **Password Management:** Admins can set or change user passwords, which are securely hashed.
*   **Custom Views:** The admin panel provides customized views for managing different models, with search, filtering, and sorting options.

## Tech Stack
*   **Flask:** Web framework.
*   **Flask-Admin:** For the administrative interface.
*   **SQLAlchemy:** ORM for database interactions.
*   **SQLite:** Database used for development.
*   **Jinja2:** Templating engine.
*   **Bootstrap:** Frontend framework.
*   **Flask-Login:** User session management.
*   **Flask-Mail:** For sending emails.
*   **ItsDangerous:** For secure token generation.
*   **Faker:** For generating test data.

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/ishant721/Ticket-Syatem.git
cd Ticket-Syatem
```

### 2. Create and activate a virtual environment
```bash
python -m venv venv
# On Windows:
# venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r ticket_system/requirements.txt
```

### 4. Configure Email Settings (for OTP and Password Reset)
Edit `ticket_system/app.py` and replace the placeholder values for `MAIL_USERNAME` and `MAIL_PASSWORD` with your email credentials. For Gmail, an App Password is required.
```python
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'
```

### 5. Initialize and Seed the Database
To set up the database with initial admin and user data, including sample tickets, run the `flask seed` command.
```bash
# Make sure your virtual environment is activated
PYTHONPATH=. flask --app ticket_system/app.py seed
```
**Note:** This command will **delete all existing data** and recreate it.

### 6. Run the Application
```bash
python ticket_system/app.py
```
The application will be accessible at `http://127.0.0.1:7000/`.

## Test Credentials

### Admin User
*   **Username:** `admin`
*   **Email:** `admin@test.com`
*   **Password:** `adminpass`

### Regular Users
*   The seed script creates 10 regular users with random usernames and emails.
*   The password for all seeded regular users is `password`.
*   You can view and manage these users from the Admin Panel.

## Database Schema

### Users Table
*   `id` (PK), `username`, `email`, `password` (Hashed), `role`, `created_at`, `is_active`, `email_verified`, `otp`

### Tickets Table
*   `id` (PK), `title`, `description`, `category`, `priority`, `status`, `user_id` (FK), `created_at`

### Replies Table
*   `id` (PK), `ticket_id` (FK), `commentor_name`, `role`, `message`, `created_at`

### TicketHistory Table
*   `id` (PK), `ticket_id` (FK), `field_changed`, `old_value`, `new_value`, `changed_by_id` (FK), `changed_at`
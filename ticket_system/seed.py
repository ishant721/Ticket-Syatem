import random
from faker import Faker
from app import app, db
from models import User, Ticket, Reply
from werkzeug.security import generate_password_hash

fake = Faker()

def seed_data():
    with app.app_context():
        # Clean up existing data
        db.drop_all()
        db.create_all()

        # Create Admin User
        admin_password = generate_password_hash('adminpass')
        admin_user = User(username='admin', email='admin@test.com', password=admin_password, role='admin', is_active=True, email_verified=True)
        db.session.add(admin_user)

        # Create Regular Users
        users = [admin_user]
        for _ in range(10):
            username = fake.user_name()
            # Ensure username is unique
            while User.query.filter_by(username=username).first():
                username = fake.user_name()
            
            user = User(
                username=username,
                email=fake.email(),
                password=generate_password_hash('password'),
                is_active=True,
                email_verified=True
            )
            db.session.add(user)
            users.append(user)
        
        db.session.commit()

        # Create Tickets
        tickets = []
        for user in users:
            if user.role == 'admin': continue # Admin doesn't create tickets in this seed
            for _ in range(random.randint(1, 3)): # Each user creates 1 to 3 tickets
                ticket = Ticket(
                    title=fake.sentence(nb_words=6),
                    description=fake.paragraph(nb_sentences=5),
                    category=random.choice(['Tech', 'HR', 'General']),
                    priority=random.choice(['Low', 'Medium', 'High']),
                    status=random.choice(['Open', 'In Progress', 'Resolved']),
                    author=user
                )
                db.session.add(ticket)
                tickets.append(ticket)
        
        db.session.commit()

        # Create Replies
        for ticket in tickets:
            # Add a few replies to each ticket
            for _ in range(random.randint(0, 5)):
                # Decide if the reply is from the author or the admin
                commentor = random.choice([ticket.author, admin_user])
                
                reply = Reply(
                    message=fake.paragraph(nb_sentences=2),
                    commentor_name=commentor.username,
                    role=commentor.role,
                    ticket=ticket
                )
                db.session.add(reply)
        
        db.session.commit()
        print("Database seeded with 1 admin, 10 users, and several tickets and replies.")

if __name__ == '__main__':
    seed_data()

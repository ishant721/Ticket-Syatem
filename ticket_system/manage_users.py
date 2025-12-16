import argparse
from app import app, db
from models import User

def promote_user(username):
    """Promotes a user to the admin role."""
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"Error: User '{username}' not found.")
            return
        
        if user.role == 'admin':
            print(f"User '{username}' is already an admin.")
            return

        user.role = 'admin'
        db.session.commit()
        print(f"Success: User '{username}' has been promoted to admin.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage users for the ticket system.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Promote user command
    promote_parser = subparsers.add_parser('promote', help='Promote a user to admin.')
    promote_parser.add_argument('username', type=str, help='The username of the user to promote.')

    args = parser.parse_args()

    if args.command == 'promote':
        promote_user(args.username)

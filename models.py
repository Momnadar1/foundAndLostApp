from app import app
from sqlalchemy.orm import relationship, backref


# Database Tables

class Users(app.config['DB'].Model):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}
    name = app.config['DB'].Column(app.config['DB'].String(200))
    email = app.config['DB'].Column(app.config['DB'].String(200))
    username = app.config['DB'].Column(app.config['DB'].String(200))
    password = app.config['DB'].Column(app.config['DB'].String(200))
    id = app.config['DB'].Column(app.config['DB'].Integer, primary_key=True)

class Items(app.config['DB'].Model):
    __tablename__ = 'items'
    __table_args__ = {'extend_existing': True}
    id = app.config['DB'].Column(app.config['DB'].Integer, primary_key=True)
    name = app.config['DB'].Column(app.config['DB'].String(200))
    location = app.config['DB'].Column(app.config['DB'].String(500))
    description = app.config['DB'].Column(app.config['DB'].String(13))
    date = app.config['DB'].Column(app.config['DB'].DATETIME(19))

if __name__ == "__main__":

    # Run this file directly to create the database tables.
    print ("Creating database tables...")
    app.config['DB'].create_all()
    print ("Done!")
from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class Student(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150))
    surname = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    country = db.Column(db.String(120))
    birthday = db.Column(db.String(150))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    course = db.Column(db.String(40))
    phone = db.Column(db.Integer)
    password = db.Column(db.String(150))


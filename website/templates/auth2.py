from flask import Blueprint, render_template, request, redirect, url_for, flash
from .models import Student
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = Student.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return redirect(url_for('auth.dashboard'))
            else:
                flash('Incorrect password', category='error')
        else:
            flash('Email does not exist', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        surname = request.form.get('surname')
        email = request.form.get('email')
        phone = request.form.get('phone')
        course = request.form.get('course')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = Student.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 6:
            flash("Email must be greater than 5 characters", category='error')
        elif len(first_name) < 2:
            flash("Firstname must be greater than 1", category='error')
        elif len(surname) < 2:
            flash("Surname must be greater than 1", category='error')
        elif len(password1) < 5:
            flash("Password must be greater than 4")
        elif password1 != password2:
            flash("Passwords do not match", category='error')
        else:
            new_user = Student(first_name=first_name, phone=phone, email=email,
                               surname=surname, course=course, password=generate_password_hash(password1))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash("Account created successfully", category='success')
            return redirect(url_for('auth.login'))

    return render_template("signup.html", user=current_user)

@auth.route('/dashboard')
def dashboard():
    return render_template("graphic_design.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    next_page = request.args.get('next')
    return redirect(next_page or url_for('auth.login'))
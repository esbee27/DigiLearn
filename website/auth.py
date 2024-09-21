from flask import Blueprint, render_template, session, request, redirect, url_for, flash
from .models import Student
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)


"""Login route"""
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = Student.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=False)
                return redirect(url_for('auth.profile'))
            else:
                flash('Incorrect password', category='error')
        else:
            flash('Email does not exist', category='error')

    return render_template("login.html")


"""Sign up route"""
@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        surname = request.form.get('surname')
        email = request.form.get('email')
        phone = request.form.get('phone')
        course = request.form.get('course')
        gender = request.form.get('gender')
        birthday = request.form.get('birthday')
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
                               surname=surname, course=course, 
                               birthday=birthday, gender=gender, 
                               password=generate_password_hash(password1))
            db.session.add(new_user)
            db.session.commit()
            session['email'] = email
            flash("Account created successfully", category='success')
            return redirect(url_for('auth.login', course=course))

    return render_template('signup.html')


"""Course page route"""
@auth.route('/dashboard/<course>')
def course_page(course):
    if 'email' not in session:
        return redirect(url_for('auth.login'))
    
    course_templates = {
        'JavaScript': 'javascript.html',
        'HTML5': 'html5.html',
        'Digital Marketing': 'digital.html',
        'Graphics Design': 'graphic_design.html',
        'CSS3': 'css3.html'
    }

    if course in course_templates:
        return render_template(course_templates[course], email=session['email'])
    else:
        return render_template('404.html'), 404


@auth.route('/dashboard')
def dashboard():
    return render_template('profile.html')


"""User's profile route"""
@auth.route('/profile')
def profile():
    return render_template('profile.html')


"""Logout route"""
@auth.route('/logout')
def logout():
    session.pop('current_user.email', None)
    return redirect(url_for('auth.login'))


"""Mentors segment"""

# Route to display the booking form

# Route to handle form submission and display mentor details
@auth.route('/book_session', methods=['POST', 'GET'])
def book_session():
    if request.method == 'POST':
        mentor_name = request.form['mentor']
        message = request.form['message']

     # Mentors data
        mentors = {
        "Blessing Ebele": {
        "email": "ogorblessing96@gmail.com",
        "whatsapp": "+234 901 459 9651"
        },
        "Miracle Amajama": {
        "email": "miraclemajama14@gmail.com",
        "whatsapp": "+234 706 518 1830"
        }
        }
        
        user_name = request.form['name']
        mentor_name = request.form['mentor']
        message = request.form['message']
        
        if mentor_name in mentors:
            mentor_details = mentors[mentor_name]
            email = mentor_details['email']
            whatsapp = mentor_details['whatsapp']
            return redirect(url_for('auth.session_confirm', mentor=mentor_name, 
                                   email=email, whatsapp=whatsapp, message=message))
        else:
            return "Mentor not found", 404
    return render_template('book_session.html')


@auth.route('/session_confirm')
def session_confirm():
    return render_template('session_confirm.html')

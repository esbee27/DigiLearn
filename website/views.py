from flask import Blueprint, render_template, request, redirect, url_for, flash
from .models import Student
from . import db
from flask_login import login_user, login_required, logout_user, current_user


views = Blueprint('views', __name__)

@views.route('/')
def index():
    return render_template("index.html")
@views.route('/digital')
def digital():
    return render_template("digital.html")
@views.route('/javascript')
def javascript():
    return render_template("javascript.html")
@views.route('/graphics')
def graphics():
    return render_template("graphic_design.html")

@views.route('/about_us')
def landing_page():
    return render_template('landing_page.html')



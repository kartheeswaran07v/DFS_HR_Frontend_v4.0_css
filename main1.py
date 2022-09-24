from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from forms import *
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, ForeignKey, String, Boolean, DateTime, Float
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from flask import abort
import os

# app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = "kkkkk"
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///dfx_db_uno.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# creating login manager
login_manager = LoginManager()
login_manager.init_app(app)


# function to sort roster data
def sortRosterData(rosterData):
    key_list = []
    value_list = []
    for i in rosterData:
        key_list.append(i)
        value_list.append(rosterData[i])

    # sort list into desirable pattern
    a = len(value_list) - 2  # subtracting submit and csrf token
    b = int(a / 43)  # calculating number of iterations needed
    iter_ = 0
    hotel_lists = []
    for i in range(b):
        hotel_lists.append(value_list[iter_:(iter_ + 43)])
        iter_ += 43

    meta_list = []
    for i in hotel_lists:
        hotel_dict = {"hotel_name": i[0], "staffs": []}
        iter_hotel = 1
        for j in range(6):  # 6 indicates number of staffs, it is hard coded, it can be made dynamic in future
            staff_dict = {"name": i[iter_hotel], "time_in": i[iter_hotel + 1], "time_out": i[iter_hotel + 2],
                          "time_in_a": i[iter_hotel + 3], "time_in_b": i[iter_hotel + 4], "pick_up": i[iter_hotel + 5],
                          "remarks": i[iter_hotel + 6]}
            hotel_dict['staffs'].append(staff_dict)
            iter_hotel += 7
        meta_list.append(hotel_dict)

    return meta_list


def sortTsData(tsData):
    key_list = []
    value_list = []
    for i in tsData:
        key_list.append(i)
        value_list.append(tsData[i])

    print(key_list)
    print(value_list)

    time_sheet_list = []
    ts_dict = {"date": value_list[0], "sheet_no": value_list[1], "hotel": value_list[2], "staff": []}

    ts_iter = 3
    a = int((len(value_list) - 4) / 6)
    for j in range(5):
        staff_dict = {"name": value_list[ts_iter], "time_in1": value_list[ts_iter + 1],
                      "time_out1": value_list[ts_iter + 2], "time_in2": value_list[ts_iter + 3],
                      "time_out2": value_list[ts_iter + 4], "hours": value_list[ts_iter + 5]}
        ts_dict["staff"].append(staff_dict)
        ts_iter += 6

    return ts_dict


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        try:
            if current_user.id != 1:
                return abort(403)
            # Otherwise, continue with the route function
            return f(*args, **kwargs)
        except:
            return abort(403)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create database classes

# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "Users"
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True)
    password = Column(String(100))
    name = Column(String(1000))

    # This will act like a list of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class
    # posts = relationship("BlogPost", back_populates="author")
    # comments = relationship("Comment", back_populates="comment_author")


# db.create_all()
# Website routes
@app.route('/', methods=["GET", "POST"])
def cover():
    return render_template("index.html")


@app.route('/admin-register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            # user already exists
            flash("You've already signed up with that email, login instead")
            return redirect(url_for('login'))

        new_user = User(email=form.email.data,
                        password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8),
                        name=form.name.data,
                        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Logged in successfully.')
        return redirect(url_for('home'))

    return render_template("admin_register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():

        user = User.query.filter_by(email=form.email.data).first()

        # email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))

        # Password incorrect
        elif not check_password_hash(user.password, form.password.data):
            flash("Password incorrect, please try again.")
            return redirect(url_for('login'))

        # email exists and password correct
        else:
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('home'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/home', methods=["GET", "POST"])
# Mark with decorator
@admin_only
def home():
    return render_template("home.html")


@app.route('/reg', methods=["GET", "POST"])
# Mark with decorator
@admin_only
def registration():
    form = RegistrationForm()
    if form.validate_on_submit():
        return render_template("reg_suc.html", name=form.name.data)

    return render_template("reg2.html", form=form)


@app.route('/leave', methods=["GET", "POST"])
# Mark with decorator
@admin_only
def leave():
    form = LeaveForm()
    if form.validate_on_submit():
        return render_template("reg_suc.html", name=form.name.data)
    return render_template("leave.html", form=form)


@app.route('/passport', methods=["GET", "POST"])
# Mark with decorator
@admin_only
def passport():
    form = PassportForm()
    if form.validate_on_submit():
        return render_template("reg_suc.html", name=form.name.data)
    return render_template("passport.html", form=form)


@app.route("/timesheet", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def timesheet():
    form = TimeSheet()
    if form.validate_on_submit():
        data_form = form.data
        value = sortTsData(data_form)
        return render_template("times_suc.html", data=data_form)
    return render_template("timesheet.html", form=form)


@app.route("/roster", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def roster():
    form = RosterExtend()
    if form.validate_on_submit():
        data_form = form.data
        value = sortRosterData(data_form)
        return f"{value}"
    return render_template("roster_extended.html", form=form)


@app.route("/reports", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def reports():
    return render_template("reports.html")


@app.route("/archives", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def archives():
    form = Archives()
    if form.validate_on_submit():
        data_form = form.data
        return f"{data_form}"
    return render_template("archives.html", form=form)


if __name__ == "__main__":
    app.run(debug=True)

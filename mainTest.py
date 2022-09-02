from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from forms import *
from datetime import date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, ForeignKey, String, Boolean, DateTime, Float
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from flask import abort
from werkzeug.utils import secure_filename
import os

home_directory = os.path.expanduser('~')

# app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = "kkkkk"
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///dfx_db_seis.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# creating login manager
login_manager = LoginManager()
login_manager.init_app(app)


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        admin = User.query.all()
        admin_id = []
        for i in admin:
            id_ = i.id
            admin_id.append(id_)

        if current_user.id not in admin_id:
            return abort(403)
        # Otherwise, continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# to create dates list for master_ts
def date_range_list(start_date, end_date):
    # Return list of datetime.date objects between start_date and end_date (inclusive).
    date_list = []
    curr_date = start_date
    while curr_date <= end_date:
        date_list.append(str(curr_date))
        curr_date += timedelta(days=1)
    return date_list


# Create database classes

# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "Users"
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True)
    password = Column(String(100))
    name = Column(String(1000))

    # relationships
    # TODO 1 - Employee Master
    employee = relationship("employeeMaster", back_populates="user")
    # TODO 2 - roster Master
    roster = relationship("rosterMaster", back_populates="user")
    # TODO 3 - Time sheet master
    timesheet = relationship("timesheetMaster", back_populates="user")
    # TODO 4 - Leave Appln Master
    leave = relationship("leaveApplicationMaster", back_populates="user")
    # TODO 5 - Passport Appln Master
    passport = relationship("passportApplicationMaster", back_populates="user")


class employeeMaster(db.Model):
    __tablename__ = "employeeMaster"
    id = Column(Integer, primary_key=True)
    employeeID = Column(String(300))
    joining_date = Column(DateTime)
    name = Column(String(300))
    addressUae = Column(String(300))
    poBox = Column(String(300))
    mobilePersonal = Column(Integer)
    mobileHome = Column(Integer)
    personalMail = Column(String(300))
    addressHome = Column(String(300))
    passportNumber = Column(Integer)
    nationality = Column(String(300))
    ownCar = Column(Boolean)
    carRent = Column(Boolean)
    company_laptop = Column(String(300))
    company_mobile = Column(String(300))
    emUaeName = Column(String(300))
    emUaeRel = Column(String(300))
    emUaeAddr = Column(String(300))
    emUaeMobileNumber = Column(Integer)
    emUaeHomeNumber = Column(Integer)
    originCountry = Column(String(300))
    emCoName = Column(String(300))
    emCoRel = Column(String(300))
    emCoAddr = Column(String(300))
    emCoMobileNumber = Column(Integer)
    emCoHomeNumber = Column(Integer)

    # relationships as child
    createdBy = Column(Integer, ForeignKey("Users.id"))
    user = relationship("User", back_populates="employee")

    departmentId = Column(Integer, ForeignKey("departmentMaster.id"))
    department = relationship("departmentMaster", back_populates="employee")

    # relationships as parent
    # TODO 1 - document Master
    document = relationship("documentMaster", back_populates="employee")
    # TODO 2 - actionItem Master
    actionItem = relationship("actionItemMaster", back_populates="employee")
    # TODO 3 - Leave Appln Master
    leave = relationship("leaveApplicationMaster", back_populates="employee")
    # TODO 4 - Passport Appln Master
    passport = relationship("passportApplicationMaster", back_populates="employee")
    # TODO 5 - Time sheet Entry master
    timesheet = relationship("timesheetEntryMaster", back_populates="employee")
    # TODO 6 - Roster Entry master
    roster = relationship("rosterEntryMaster", back_populates="employee")


class rosterMaster(db.Model):
    __tablename__ = "rosterMaster"
    id = Column(Integer, primary_key=True)
    date = Column(String(300))

    # relationship as parent
    entry = relationship("rosterEntryMaster", back_populates="roster")

    # relationships as child
    createdBy = Column(Integer, ForeignKey("Users.id"))
    user = relationship("User", back_populates="roster")


class timesheetMaster(db.Model):
    __tablename__ = "timesheetMaster"
    id = Column(Integer, primary_key=True)
    date = Column(String(300))
    sheet_no = Column(Integer)

    # relationship as parent
    entry = relationship("timesheetEntryMaster", back_populates="timesheet")

    # relationships as child
    createdBy = Column(Integer, ForeignKey("Users.id"))
    user = relationship("User", back_populates="timesheet")

    hotelID = Column(Integer, ForeignKey("hotelMaster.id"))
    hotel = relationship("hotelMaster", back_populates="timesheet")


class hotelMaster(db.Model):
    __tablename__ = "hotelMaster"
    id = Column(Integer, primary_key=True)
    name = Column(String(300))
    address = Column(String(300))

    # relationship as parent
    rosterEntry = relationship("rosterEntryMaster", back_populates="hotel")
    timesheet = relationship("timesheetMaster", back_populates="hotel")


class departmentMaster(db.Model):
    __tablename__ = "departmentMaster"
    id = Column(Integer, primary_key=True)
    name = Column(String(300))

    # relationship as parent
    employee = relationship("employeeMaster", back_populates="department")


class documentMaster(db.Model):
    __tablename__ = "documentMaster"
    id = Column(Integer, primary_key=True)
    documentName = Column(String(300))
    documentDirectory = Column(String(300))

    # relationships as child
    employeeID = Column(Integer, ForeignKey("employeeMaster.id"))
    employee = relationship("employeeMaster", back_populates="document")


class actionItemMaster(db.Model):
    __tablename__ = "actionItemMaster"
    id = Column(Integer, primary_key=True)
    actionText = Column(String(300))

    # relationships as child
    employeeID = Column(Integer, ForeignKey("employeeMaster.id"))
    employee = relationship("employeeMaster", back_populates="actionItem")


class leaveApplicationMaster(db.Model):
    __tablename__ = "leaveApplicationMaster"
    id = Column(Integer, primary_key=True)

    date = Column(DateTime)
    company = Column(String(300))
    dept = Column(String(300))
    designation = Column(String(300))
    nationality = Column(String(300))
    pass_no = Column(Integer)
    emp = Column(String(300))

    # type of leave
    leave_type = Column(String(300))

    # Personal Details
    addr_wol = Column(String(300))
    con_per = Column(String(300))
    rel = Column(String(300))
    pol = Column(String(300))
    # sign = StringField("Signature and Date")
    dot = Column(DateTime)
    con_wol = Column(String(300))
    sub_emp = Column(String(300))
    leave_f = Column(DateTime)
    leave_t = Column(DateTime)
    no_days = Column(Integer)
    air_tic = Column(String(300))

    # Guarantors
    g1_name = Column(String(300))
    g1_dept = Column(String(300))
    g1_id_no = Column(Integer)
    # g1_sign = IntegerField("Sign and Date")
    g2_name = Column(String(300))
    g2_dept = Column(String(300))
    g2_id_no = Column(Integer)
    # g2_sign = IntegerField("Sign and Date")

    # HR Dept
    doj = Column(DateTime)
    tla = Column(Integer)
    less_this = Column(Integer)
    nod_app = Column(Integer)
    dor = Column(DateTime)
    eligibility = Column(String(300))
    last_leave = Column(String(300))
    balance_leave = Column(Integer)
    release_date = Column(DateTime)
    # sign_hr = StringField("Sign & Date HR Assistant: ")

    # If Annual Leave not Approved
    amt_appr = Column(Integer)
    cheq_no = Column(Integer)
    # empl_sign = StringField("Employee Signature: ")
    pbc = Column(String(300))
    bank_tr = Column(String(300))
    date_tr = Column(DateTime)

    # Approval
    approved_by = Column(String(300))
    approved_by_2 = Column(String(300))

    # relationships as child
    createdBy = Column(Integer, ForeignKey("Users.id"))
    user = relationship("User", back_populates="leave")

    employeeID = Column(Integer, ForeignKey("employeeMaster.id"))
    employee = relationship("employeeMaster", back_populates="leave")


class passportApplicationMaster(db.Model):
    __tablename__ = "passportApplicationMaster"
    id = Column(Integer, primary_key=True)

    date = Column(DateTime)
    emp_no = Column(Integer)
    pow = Column(String(300))
    days_req = Column(String(300))
    remarks = Column(String(300))

    # guarantors
    g1_name = Column(String(300))
    g1_dept = Column(String(300))
    g1_id_no = Column(Integer)
    g2_name = Column(String(300))
    g2_dept = Column(String(300))
    g2_id_no = Column(Integer)

    # approval
    checked_by = Column(String(300))
    appr_by_lm = Column(String(300))
    appr_by_hr = Column(String(300))
    dir_op = Column(String(300))

    # issue
    pass_rec = Column(String(300))
    date_pass_rec = Column(DateTime)
    lc_rec = Column(String(300))
    date_lc_rec = Column(DateTime)

    # return
    pass_rec_e = Column(String(300))
    date_pass_rec_e = Column(DateTime)
    lc_rec_e = Column(String(300))
    date_lc_rec_e = Column(DateTime)

    # relationships as child
    createdBy = Column(Integer, ForeignKey("Users.id"))
    user = relationship("User", back_populates="passport")

    employeeID = Column(Integer, ForeignKey("employeeMaster.id"))
    employee = relationship("employeeMaster", back_populates="passport")


class timesheetEntryMaster(db.Model):
    __tablename__ = "timesheetEntryMaster"
    id = Column(Integer, primary_key=True)
    timeIn1 = Column(Integer)
    timeOut1 = Column(Integer)
    timeIn2 = Column(Integer)
    timeOut2 = Column(Integer)

    # relationships as child
    employeeID = Column(Integer, ForeignKey("employeeMaster.id"))
    employee = relationship("employeeMaster", back_populates="timesheet")

    timesheetID = Column(Integer, ForeignKey("timesheetMaster.id"))
    timesheet = relationship("timesheetMaster", back_populates="entry")


class rosterEntryMaster(db.Model):
    __tablename__ = "rosterEntryMaster"
    id = Column(Integer, primary_key=True)
    timeIn1 = Column(Integer)
    timeOut1 = Column(Integer)
    timeIn2 = Column(Integer)
    timeOut2 = Column(Integer)
    pickUp = Column(Integer)
    remark = Column(String(300))
    absent = Column(String(300))

    # relationships as child
    employeeID = Column(Integer, ForeignKey("employeeMaster.id"))
    employee = relationship("employeeMaster", back_populates="roster")

    rosterID = Column(Integer, ForeignKey("rosterMaster.id"))
    roster = relationship("rosterMaster", back_populates="entry")

    hotelID = Column(Integer, ForeignKey("hotelMaster.id"))
    hotel = relationship("hotelMaster", back_populates="rosterEntry")


db.create_all()


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


@app.route('/registration', methods=["GET", "POST"])
# Mark with decorator
@admin_only
def registration():
    form = RegistrationForm()
    if request.method == "POST":
        department = db.session.query(departmentMaster).filter_by(id=1).first()
        a_date = datetime.datetime.strptime(request.form.get('joining_date'), '%Y-%m-%d').date()

        new_employee = employeeMaster(
            name=request.form.get("name"),
            addressUae=request.form.get('address_uae'),
            poBox=request.form.get('po_box'),
            mobilePersonal=request.form.get('mobile_p'),
            mobileHome=request.form.get('mobile_h'),
            personalMail=request.form.get('personal_mail'),
            addressHome=request.form.get('address_home'),
            passportNumber=request.form.get('passport_no'),
            nationality=request.form.get('nationality'),
            ownCar=request.form.get('own_car'),
            carRent=request.form.get('car_rent'),
            emUaeName=request.form.get('e_uae_name'),
            emUaeRel=request.form.get('e_uae_rel'),
            emUaeAddr=request.form.get('e_uae_addr'),
            emUaeMobileNumber=request.form.get('e_uae_mob'),
            emUaeHomeNumber=request.form.get('e_uae_hom'),
            originCountry=request.form.get('origin_country'),
            emCoName=request.form.get('e_co_name'),
            emCoRel=request.form.get('e_co_rel'),
            emCoAddr=request.form.get('e_co_addr'),
            emCoMobileNumber=request.form.get('e_co_mob'),
            emCoHomeNumber=request.form.get('e_co_hom'),
            employeeID=request.form.get('employee_id'),
            joining_date=a_date,
            company_laptop=request.form.get('company_laptop'),
            company_mobile=request.form.get('company_mobile'),
            user=current_user,
            department=department
        )
        db.session.add(new_employee)
        db.session.commit()
        return render_template("upload_doc.html", name=form.name.data)

    return render_template("reg2.html", form=form)


@app.route("/doc", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def doc():
    if request.method == 'POST':

        directory = request.form.get('name')
        employee_element = db.session.query(employeeMaster).filter_by(name=directory).first()

        # Parent Directory path
        parent_dir = home_directory

        # Path
        path = os.path.join(parent_dir, directory)

        # Create the directory
        # 'GeeksForGeeks' in
        # '/home / User / Documents'
        os.mkdir(path)

        files = request.files.getlist("file")  # other multiple files
        photo = request.form.get('photo')  # photo file
        UPLOAD_FOLDER = f"{home_directory}/{directory}"
        app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
        for file in files:
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        # Save pic in folder

        new_doc = documentMaster(documentName=photo, documentDirectory=UPLOAD_FOLDER, employee=employee_element)
        db.session.add(new_doc)
        db.session.commit()

        return render_template("reg_suc.html", name=request.form.get('name'))


@app.route('/leave', methods=["GET", "POST"])
# Mark with decorator
@admin_only
def leave():
    form = LeaveForm()
    if form.validate_on_submit():
        employee = db.session.query(employeeMaster).filter_by(name=form.name.data).first()

        new_leave = leaveApplicationMaster(
            date=form.date.data,
            company=form.company.data,
            dept=form.dept.data,
            designation=form.designation.data,
            nationality=form.nationality.data,
            pass_no=form.pass_no.data,
            emp=form.emp.data,
            leave_type=form.leave_type.data,
            addr_wol=form.addr_wol.data,
            con_per=form.con_per.data,
            rel=form.rel.data,
            pol=form.pol.data,
            dot=form.dot.data,
            con_wol=form.con_wol.data,
            sub_emp=form.sub_emp.data,
            leave_f=form.leave_f.data,
            leave_t=form.leave_t.data,
            no_days=form.no_days.data,
            air_tic=form.air_tic.data,
            g1_name=form.g1_name.data,
            g1_dept=form.g1_dept.data,
            g1_id_no=form.g1_id_no.data,
            g2_name=form.g2_name.data,
            g2_dept=form.g2_dept.data,
            g2_id_no=form.g2_id_no.data,
            doj=form.doj.data,
            tla=form.tla.data,
            less_this=form.less_this.data,
            nod_app=form.nod_app.data,
            dor=form.dor.data,
            eligibility=form.eligibility.data,
            last_leave=form.last_leave.data,
            balance_leave=form.balance_leave.data,
            release_date=form.release_date.data,
            amt_appr=form.amt_appr.data,
            cheq_no=form.cheq_no.data,
            pbc=form.pbc.data,
            bank_tr=form.bank_tr.data,
            date_tr=form.date_tr.data,
            approved_by=form.approved_by.data,
            approved_by_2=form.approved_by_2.data,
            employee=employee,
            user=current_user
        )
        db.session.add(new_leave)
        db.session.commit()
        return render_template("reg_suc.html", name=form.name.data)
    return render_template("leave.html", form=form)


@app.route('/passport', methods=["GET", "POST"])
# Mark with decorator
@admin_only
def passport():
    form = PassportForm()
    if form.validate_on_submit():
        employee = db.session.query(employeeMaster).filter_by(name=form.name.data).first()

        new_pp = passportApplicationMaster(
            date=form.date.data,
            emp_no=form.emp_no.data,
            pow=form.pow.data,
            days_req=form.days_req.data,
            remarks=form.remarks.data,
            g1_name=form.g1_name.data,
            g1_dept=form.g1_dept.data,
            g1_id_no=form.g1_id_no.data,
            g2_name=form.g2_name.data,
            g2_dept=form.g2_dept.data,
            g2_id_no=form.g2_id_no.data,
            checked_by=form.checked_by.data,
            appr_by_lm=form.appr_by_lm.data,
            appr_by_hr=form.appr_by_hr.data,
            dir_op=form.dir_op.data,
            pass_rec=form.pass_rec.data,
            date_pass_rec=form.date_pass_rec_e.data,
            lc_rec=form.lc_rec.data,
            date_lc_rec=form.date_lc_rec_e.data,
            pass_rec_e=form.pass_rec_e.data,
            date_pass_rec_e=form.date_pass_rec_e.data,
            lc_rec_e=form.lc_rec_e.data,
            date_lc_rec_e=form.date_lc_rec_e.data,
            employee=employee,
            user=current_user
        )
        db.session.add(new_pp)
        db.session.commit()
        return render_template("reg_suc.html", name=form.name.data)
    return render_template("passport.html", form=form)


@app.route("/ts", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def timesheet():
    employee_list = employeeMaster.query.all()
    employee_name = [i.name for i in employee_list]
    if request.method == 'POST':
        data = request.form.to_dict(flat=False)
        a = jsonify(data).json

        hotel_element = db.session.query(hotelMaster).filter_by(name=a['hotel'][0]).first()
        new_timesheet = timesheetMaster(date=a['date'][0], sheet_no=a['sheetNo'][0], user=current_user,
                                        hotel=hotel_element)

        # Create logic to check whether ts is added properly - Create a page for success and not success
        # Create logic for checking duplicates
        # print(type(a['date'][0]))
        db.session.add(new_timesheet)
        db.session.commit()

        for i in range(len(a['name'])):
            if a['name'][i] != '':
                employee_element = db.session.query(employeeMaster).filter_by(name=a['name'][i]).first()
                ts_element = new_timesheet
                new_entry = timesheetEntryMaster(timeIn1=a['timeIn1'][i], timeIn2=a['timeIn2'][i],
                                                 timeOut1=a['timeOut1'][i], timeOut2=a['timeOut2'][i],
                                                 employee=employee_element, timesheet=ts_element)
                db.session.add(new_entry)
                db.session.commit()

        return render_template("ts_success_db.html", data=a, len=range(len(a['name'])))

    return render_template("timesheet.html", array=employee_name)


@app.route("/roster", methods=["GET", "POST"])
# # Mark with decorator
@admin_only
def roster():
    all_roster = rosterMaster.query.all()
    dates_list = []
    for i in all_roster:
        date_el = i.date
        dates_list.append(date_el)

    if request.method == 'POST':
        data = request.form.to_dict(flat=False)
        a = jsonify(data).json

        got_date = a['date'][0]
        got_date_year = got_date[6:10]
        got_date_day = got_date[3:5]
        got_date_month = got_date[0:2]
        format_date = f"{got_date_year}-{got_date_month}-{got_date_day}"
        new_roster = rosterMaster(date=format_date, user=current_user)
        db.session.add(new_roster)
        db.session.commit()

        # Create logic for checking duplicates
        # create a mechanism to tell the user

        roster_element = new_roster

        for i in range(len(a['hotel'])):
            if a['hotel'][i] != '':  # check if there's no entry
                hotel_element = db.session.query(hotelMaster).filter_by(name=a['hotel'][i]).first()
                nameStr = "name" + str(i + 1)
                timeInStr1 = "timeInA" + str(i + 1)
                timeOutStr1 = "timeOutA" + str(i + 1)
                timeInStr2 = "timeInB" + str(i + 1)
                timeOutStr2 = "timeOutB" + str(i + 1)
                pickup = "pickUp" + str(i + 1)
                remarks = "remarks" + str(i + 1)
                absent = "absent" + str(i + 1)

                for j in range(len(a[nameStr])):
                    if a[nameStr][j] != '':
                        employee_element = db.session.query(employeeMaster).filter_by(name=a[nameStr][j]).first()
                        new_entry = rosterEntryMaster(timeIn1=a[timeInStr1][j], timeOut1=a[timeOutStr1][j],
                                                      timeIn2=a[timeInStr2][j],
                                                      timeOut2=a[timeOutStr2][j], pickUp=a[pickup][j],
                                                      remark=a[remarks][j], absent=a[absent][j],
                                                      employee=employee_element, roster=roster_element,
                                                      hotel=hotel_element)
                        db.session.add(new_entry)
                        db.session.commit()

        # return render_template("roster_complete.html", date=today, data=value)
        print(a)
        return redirect(url_for("roster_single", roster_id=new_roster.id))
    # form = RosterExtend()
    # if form.validate_on_submit():
    #     data_form = form.data
    #     value = sortRosterData(data_form)
    #
    #     # create logic to add values in db - rosterMaster, rosterEntryMaster
    #     # Get hotel id


@app.route("/roster_date", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def roster_date():
    all_roster = rosterMaster.query.all()
    dates_list = []
    for i in all_roster:
        date_el = i.date
        dates_list.append(date_el)

    if request.method == "POST":
        date_roster = request.form.get('date')
        rosters = rosterMaster.query.all()
        dates = []
        for roster in rosters:
            i = roster.date
            dates.append(i)
        if date_roster in dates:
            return render_template("roster_date.html", array=dates_list,
                                   msg="Roster with the same date exists. Choose new one.")
        elif date_roster:
            return render_template('roster_new.html', date_roster=date_roster)
        else:
            return render_template("roster_date.html", array=dates_list, msg="Choose a date to continue")

    return render_template("roster_date.html", array=dates_list, msg="None")


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
    employee_list = employeeMaster.query.all()
    if form.validate_on_submit():
        data1 = form.date1.data
        data2 = form.date2.data
        date_list = date_range_list(data1, data2)
        ts_list = []
        for i in date_list:
            ts_element = db.session.query(timesheetMaster).filter_by(date=i).first()
            if not ts_element:
                return render_template("archives.html", form=form, msg="Choose correct dates")
            else:
                ts_list.append(ts_element)

        master_ts_list = []
        for i in range(len(employee_list)):
            ms_dict = {"name": employee_list[i].name, "hours": []}
            for j in range(len(ts_list)):
                ts_entry_element = db.session.query(timesheetEntryMaster).filter_by(employeeID=employee_list[i].id,
                                                                                    timesheetID=ts_list[j].id).first()
                if not ts_entry_element:
                    roster_element = db.session.query(rosterMaster).filter_by(date=ts_list[j].date).first()
                    if not roster_element:
                        hours = "N/A"
                    else:
                        rs_entry_element = db.session.query(rosterEntryMaster).filter_by(employeeID=employee_list[i].id, rosterID=roster_element.id).first()
                        if (not rs_entry_element) or (rs_entry_element.absent == "none"):
                            hours = "N/A"
                        else:
                            hours = rs_entry_element.absent


                else:
                    hours = ts_entry_element.timeOut1 - ts_entry_element.timeIn1 + ts_entry_element.timeOut2 - ts_entry_element.timeIn2
                    print(ts_entry_element.timeOut1)

                ms_dict['hours'].append(hours)
            master_ts_list.append(ms_dict)

        return render_template("masterTs.html", data=master_ts_list, dates=date_list, len=range(len(date_list)))
    return render_template("archives.html", form=form, msg="")


@app.route("/roster_archive", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def roster_archive():
    rosters_list = rosterMaster.query.all()
    return render_template("roster_archive_list.html", rosters=rosters_list)


@app.route("/roster_single/<roster_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def roster_single(roster_id):
    roster_entries = db.session.query(rosterEntryMaster).filter_by(rosterID=roster_id).all()
    employee_list = []
    hotel_list = []
    for i in roster_entries:
        employee = db.session.query(employeeMaster).filter_by(id=i.employeeID).first()
        hotel = db.session.query(hotelMaster).filter_by(id=i.hotelID).first()
        hotel_list.append(hotel.name)
        employee_list.append(employee.name)
    return render_template("roster_entries.html", entries=roster_entries, employees=employee_list, hotels=hotel_list,
                           len=range(len(roster_entries)))


@app.route("/roster_single_edit/<roster_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def roster_single_edit(roster_id):
    roster_entries = db.session.query(rosterEntryMaster).filter_by(rosterID=roster_id).all()
    employee_list = []
    hotel_list = []
    for i in roster_entries:
        employee = db.session.query(employeeMaster).filter_by(id=i.employeeID).first()
        hotel = db.session.query(hotelMaster).filter_by(id=i.hotelID).first()
        hotel_list.append(hotel.name)
        employee_list.append(employee.name)
    return render_template("roster_entries_edit.html", entries=roster_entries, employees=employee_list,
                           hotels=hotel_list,
                           len=range(len(roster_entries)))


@app.route("/add_roster_element/<roster_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def add_roster_element(roster_id):
    if request.method == 'POST':
        hotel_element = db.session.query(hotelMaster).filter_by(name=request.form.get('hotel')).first()
        employee_element = db.session.query(employeeMaster).filter_by(name=request.form.get('name')).first()
        roster_element = db.session.query(rosterMaster).filter_by(id=roster_id).first()
        new_entry = rosterEntryMaster(timeIn1=request.form.get('timeIn1'), timeOut1=request.form.get('timeOut1'),
                                      timeIn2=request.form.get('timeIn2'),
                                      timeOut2=request.form.get('timeOut2'), pickUp=request.form.get('pickUp'),
                                      remark=request.form.get('remark'), absent=request.form.get('absent'),
                                      employee=employee_element, roster=roster_element,
                                      hotel=hotel_element)
        db.session.add(new_entry)
        db.session.commit()

        return redirect(url_for("roster_single_edit", roster_id=roster_id))


@app.route("/del_roster_element/<entry_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def del_roster_element(entry_id):
    entry_to_delete = rosterEntryMaster.query.get(entry_id)
    roster_id = entry_to_delete.rosterID
    db.session.delete(entry_to_delete)
    db.session.commit()
    return redirect(url_for("roster_single_edit", roster_id=roster_id))


# timesheet edit/view

@app.route("/timesheet_archive", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def timesheet_archive():
    timesheet_list = timesheetMaster.query.all()
    hotels = []
    for ts in timesheet_list:
        hotel_element = hotelMaster.query.get(ts.hotelID)
        hotel_name = hotel_element.name
        hotels.append(hotel_name)
    return render_template("timesheet_archive_list.html", ts=timesheet_list, len=range(len(hotels)), hotels=hotels)


@app.route("/timesheet_single/<timesheet_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def timesheet_single(timesheet_id):
    timesheet_entries = db.session.query(timesheetEntryMaster).filter_by(timesheetID=timesheet_id).all()
    ts_element = timesheetMaster.query.get(timesheet_id)
    sheet_no = ts_element.sheet_no
    date__ = ts_element.date
    hotel_element = hotelMaster.query.get(ts_element.hotelID)
    hotel_name = hotel_element.name
    employee_list = []
    for i in timesheet_entries:
        employee = db.session.query(employeeMaster).filter_by(id=i.employeeID).first()
        employee_list.append(employee.name)
    return render_template("timesheet_entries.html", entries=timesheet_entries, employees=employee_list,
                           hotel_name=hotel_name,
                           len=range(len(timesheet_entries)), date__=date__, sheet=sheet_no)


@app.route("/timesheet_single_edit/<timesheet_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def timesheet_single_edit(timesheet_id):
    timesheet_entries = db.session.query(timesheetEntryMaster).filter_by(timesheetID=timesheet_id).all()
    ts_element = timesheetMaster.query.get(timesheet_id)
    sheet_no = ts_element.sheet_no
    date__ = ts_element.date
    hotel_element = hotelMaster.query.get(ts_element.hotelID)
    hotel_name = hotel_element.name
    employee_list = []
    for i in timesheet_entries:
        employee = db.session.query(employeeMaster).filter_by(id=i.employeeID).first()
        employee_list.append(employee.name)
    return render_template("timesheet_entries_edit.html", entries=timesheet_entries, employees=employee_list,
                           hotel_name=hotel_name,
                           len=range(len(timesheet_entries)), date__=date__, sheet=sheet_no)


@app.route("/add_ts_element/<ts_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def add_ts_element(ts_id):
    if request.method == 'POST':
        ts_element = timesheetMaster.query.get(ts_id)
        hotel_element = hotelMaster.query.get(ts_element.hotelID)
        employee_element = db.session.query(employeeMaster).filter_by(name=request.form.get('name')).first()
        new_entry = timesheetEntryMaster(timeIn1=request.form.get('timeIn1'), timeOut1=request.form.get('timeOut1'),
                                         timeIn2=request.form.get('timeIn2'),
                                         timeOut2=request.form.get('timeOut2'),
                                         employee=employee_element, timesheet=ts_element)
        db.session.add(new_entry)
        db.session.commit()

        return redirect(url_for("timesheet_single_edit", timesheet_id=ts_id))


@app.route("/del_ts_element/<entry_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def del_ts_element(entry_id):
    entry_to_delete = timesheetEntryMaster.query.get(entry_id)
    ts_id = entry_to_delete.timesheetID
    db.session.delete(entry_to_delete)
    db.session.commit()
    return redirect(url_for("timesheet_single_edit", timesheet_id=ts_id))


# reports

@app.route("/employee_report", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def employee_report():
    employee_list = employeeMaster.query.all()
    date_test = '2022-09-01'
    roster_element = db.session.query(rosterMaster).filter_by(date=date_test).first()
    roster_entries = db.session.query(rosterEntryMaster).filter_by(rosterID=roster_element.id).all()
    off_days = 0
    for i in roster_entries:
        if i.absent != 'none':
            off_days += 1

    data = {'Task': 'Hours per Day', 'Absent': off_days, 'Present': len(roster_entries)}
    department = []
    for ts in employee_list:
        department_element = departmentMaster.query.get(ts.departmentId)
        hotel_name = department_element.name
        department.append(hotel_name)
    return render_template("employee_report.html", ts=employee_list, len=range(len(department)), departments=department,
                           data=data)


@app.route("/employee_edit/<employee_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def employee_edit(employee_id):
    form = RegistrationForm()
    employee_element = employeeMaster.query.get(employee_id)
    print(employee_element.joining_date)
    a = str(employee_element.joining_date)
    date_str = a[:10]
    print(date_str)
    if form.validate_on_submit():
        employee_element.name = request.form.get("name")
        employee_element.addressUae = request.form.get('address_uae')
        employee_element.poBox = request.form.get('po_box')
        employee_element.mobilePersonal = request.form.get('mobile_p')
        employee_element.mobileHome = request.form.get('mobile_h')
        employee_element.personalMail = request.form.get('personal_mail')
        employee_element.addressHome = request.form.get('address_home')
        employee_element.passportNumber = request.form.get('passport_no')
        employee_element.nationality = request.form.get('nationality')
        employee_element.ownCar = request.form.get('own_car')
        employee_element.carRent = request.form.get('car_rent')
        employee_element.emUaeName = request.form.get('e_uae_name')
        employee_element.emUaeRel = request.form.get('e_uae_rel')
        employee_element.emUaeAddr = request.form.get('e_uae_addr')
        employee_element.emUaeMobileNumber = request.form.get('e_uae_mob')
        employee_element.emUaeHomeNumber = request.form.get('e_uae_hom')
        employee_element.originCountry = request.form.get('origin_country')
        employee_element.emCoName = request.form.get('e_co_name')
        employee_element.emCoRel = request.form.get('e_co_rel')
        employee_element.emCoAddr = request.form.get('e_co_addr')
        employee_element.emCoMobileNumber = request.form.get('e_co_mob')
        employee_element.emCoHomeNumber = request.form.get('e_co_hom')
        employee_element.employeeID = request.form.get('employee_id')
        employee_element.joining_date = request.form.get('joining_date')
        employee_element.company_laptop = request.form.get('company_laptop')
        employee_element.company_mobile = request.form.get('company_mobile')
        employee_element.user = current_user
        db.session.commit()
        return redirect(url_for("employee_report"))
    return render_template("employee_edit.html", data=employee_element, form=form, date_str=date_str)


@app.route("/employee_view/<employee_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def employee_view(employee_id):
    form = ActionItem()
    employee_element = employeeMaster.query.get(employee_id)
    a = str(employee_element.joining_date)
    date_str = a[:10]
    actionItems = db.session.query(actionItemMaster).filter_by(employeeID=employee_id).all()
    doc_element = db.session.query(documentMaster).filter_by(employeeID=employee_id).first()
    img_url = doc_element.documentName

    # get total hours worked
    ts_employee = db.session.query(timesheetEntryMaster).filter_by(employeeID=employee_id).all()
    totalHours = 0
    for i in ts_employee:
        b = (i.timeOut1 - i.timeIn1) + (i.timeOut2 - i.timeIn2)
        totalHours += b

    # get profile completion %
    list_empl = [employee_element.name,
                 employee_element.addressUae,
                 employee_element.poBox,
                 employee_element.mobilePersonal,
                 employee_element.mobileHome,
                 employee_element.personalMail,
                 employee_element.addressHome,
                 employee_element.passportNumber,
                 employee_element.nationality,
                 employee_element.emUaeName,
                 employee_element.emUaeRel,
                 employee_element.emUaeAddr,
                 employee_element.emUaeMobileNumber,
                 employee_element.emUaeHomeNumber,
                 employee_element.originCountry,
                 employee_element.emCoName,
                 employee_element.emCoRel,
                 employee_element.emCoAddr,
                 employee_element.emCoMobileNumber,
                 employee_element.emCoHomeNumber,
                 employee_element.employeeID,
                 employee_element.joining_date,
                 employee_element.company_laptop,
                 employee_element.company_mobile]
    profileCompletion = 0
    for i in list_empl:
        if not i:
            profileCompletion += 1

    profilePercent = ((len(list_empl) - profileCompletion) / len(list_empl)) * 100

    if form.validate_on_submit():
        newActionItem = actionItemMaster(actionText=form.content.data, employee=employee_element)
        db.session.add(newActionItem)
        db.session.commit()
        return redirect(url_for("employee_view", employee_id=employee_id))

    return render_template("employee_view.html", employee=employee_element, form=form, date_str=date_str,
                           workedHours=totalHours, profile=round(profilePercent, 0), items=actionItems, img_url=img_url)


@app.route("/action_item_del/<entry_id>", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def action_item_del(entry_id):
    entry_to_delete = actionItemMaster.query.get(entry_id)
    employee_id = entry_to_delete.employeeID
    db.session.delete(entry_to_delete)
    db.session.commit()
    return redirect(url_for("employee_view", employee_id=employee_id))



if __name__ == "__main__":
    app.run(debug=True)

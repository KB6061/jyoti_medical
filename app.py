from sqlalchemy.exc import OperationalError
import time
from datetime import datetime, date
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from models import db, Product, Distributor, Purchase, PurchaseItem  # adjust import path

def safe_commit(retries=5, delay=0.2):
    """
    Attempts to commit the session, retrying if the database is locked.
    """
    for i in range(retries):
        try:
            db.session.commit()
            return
        except OperationalError as e:
            # Common in SQLite during concurrent writes
            if "database is locked" in str(e):
                time.sleep(delay)
            else:
                db.session.rollback()  # Rollback on other operational errors
                raise
                
    raise Exception("Database locked after multiple retry attempts")# ============================
# Imports (Grouped & Cleaned)
import logging
import os
import secrets
from datetime import datetime, timedelta, date

# Flask Core
from flask import (
    Flask, render_template, redirect, url_for,
    flash, request, session
)

# Security & Auth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user
)

# Forms
from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField, FloatField,
    IntegerField, DateField, SelectField, TextAreaField
)
from wtforms.validators import DataRequired, Optional

# Database & Models
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from models import (
    db, User, Product, Customer, Sale, SaleItem, OTPCode,
    Billing, BillingItem, Appointment, Doctor,
    Prescription, PrescriptionItem, StockMovement
)

def gst_for_category(category):
    if category == "life_saving":
        return 0, 0, 0
    if category == "medicine":
        return 5, 2.5, 2.5
    if category == "ayurvedic":
        return 12, 6, 6
    if category in ["cosmetic", "fmcg", "equipment", "general"]:
        return 18, 9, 9
    return 5, 2.5, 2.5  # fallback


# ============================
# App Configuration
# ============================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.update(
    SECRET_KEY='change-me',
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(app.root_path, 'app.db') + '?check_same_thread=False',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    OTP_EXPIRY_MINUTES=10,
    WTF_CSRF_ENABLED=True,
    MAX_CONTENT_LENGTH=4 * 1024 * 1024
)
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "connect_args": {"timeout": 30}
}

app.config['SQLALCHEMY_DATABASE_URI']
app.config['SECRET_KEY'] = secrets.token_hex(16)

db.init_app(app)

with app.app_context():
    db.create_all()



# ============================
# Login Manager Setup
# ============================

login_manager = LoginManager(app)
login_manager.login_view = 'login_page'
login_manager.login_message = None


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None

# ============================
# GLOBAL LOGIN GUARD (FIXED)
# ============================
@app.before_request
def require_login():
    # Some requests (favicon, static, etc.) have no endpoint
    if request.endpoint is None:
        return

    allowed_routes = ['login', 'forgot', 'reset_otp', 'static']

    # Allow static files
    if request.endpoint.startswith('static'):
        return

    # Block only when needed
    if request.endpoint not in allowed_routes and not current_user.is_authenticated:
        return redirect(url_for('login'))


# Redirect unauthorized users to login page
@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('login'))



# ============================
# WTForms Definitions
# ============================

class LoginForm(FlaskForm):
    username = StringField('User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class ForgotForm(FlaskForm):
    username = StringField('User ID', validators=[DataRequired()])
    submit = SubmitField('Generate OTP')


class OTPVerifyForm(FlaskForm):
    username = StringField('User ID', validators=[DataRequired()])
    otp = StringField('OTP', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')


class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[Optional()])
    first_name = StringField('First Name', validators=[Optional()])
    last_name = StringField('Last Name', validators=[Optional()])
    password = PasswordField('Password', validators=[Optional()])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('staff', 'Staff')])
    submit = SubmitField('Save')


class ProductForm(FlaskForm):
    sku = StringField('SKU', validators=[Optional()])
    name = StringField('Name', validators=[DataRequired()])
    brand = StringField('Brand', validators=[Optional()])
    batch_no = StringField('Batch No', validators=[Optional()])
    expiry_date = DateField('Expiry Date', format='%Y-%m-%d', validators=[Optional()])
    purchase_price = FloatField('Purchase Price', validators=[Optional()])
    sale_price = FloatField('Sale Price', validators=[Optional()])
    current_stock = IntegerField('Stock', validators=[Optional()])
    submit = SubmitField('Save')


class PatientForm(FlaskForm):
    name = StringField('Patient Name', validators=[DataRequired()])
    phone = StringField('Mobile Number', validators=[Optional()])
    address = StringField('Address', validators=[Optional()])
    description = TextAreaField('Medical Description', validators=[Optional()])
    submit = SubmitField('Save')


class AppointmentForm(FlaskForm):
    patient_id = SelectField('Patient', coerce=int, validators=[DataRequired()])
    doctor_id = SelectField('Doctor', coerce=int, validators=[Optional()])
    reason = TextAreaField('Reason / Notes', validators=[Optional()])
    status = SelectField('Status', choices=[
        ('Scheduled', 'Scheduled'),
        ('Completed', 'Completed'),
        ('Cancelled', 'Cancelled')
    ])
    submit = SubmitField('Save')


class DoctorForm(FlaskForm):
    name = StringField('Doctor Name', validators=[DataRequired()])
    specialization = StringField('Specialization', validators=[Optional()])
    phone = StringField('Phone', validators=[Optional()])
    notes = TextAreaField('Notes', validators=[Optional()])
    submit = SubmitField('Save')


class PrescriptionForm(FlaskForm):
    doctor_id = SelectField('Doctor', coerce=int, validators=[Optional()])
    diagnosis = TextAreaField('Diagnosis', validators=[Optional()])
    notes = TextAreaField('Notes', validators=[Optional()])
    submit = SubmitField('Save')


# ============================
# Helper Functions
# ============================

def get_initials_from_username(username: str) -> str:
    if not username:
        return ""
    parts = username.strip().split()
    if len(parts) >= 2:
        return (parts[0][0] + parts[1][0]).upper()
    return username[:2].upper()


def ensure_user_file_label(user: User) -> str:
    """
    Ensures each user has a unique file label.
    """
    if getattr(user, 'file_label', None):
        return user.file_label

    if user.id:
        label = f"{user.id:04d}"
    else:
        label = datetime.utcnow().strftime("%y%m%d%H%M%S")

    user.file_label = label
    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        user.file_label = datetime.utcnow().strftime("%y%m%d%H%M%S")
        db.session.add(user)
        db.session.commit()

    return user.file_label

def is_admin():
    return current_user.is_authenticated and current_user.role == 'admin'
def admin_required():
    return current_user.is_authenticated and current_user.role == 'admin'
def is_staff():
    return current_user.is_authenticated and current_user.role in ['admin', 'staff']

def generate_invoice_number():
    today = datetime.now().strftime("%d%m%y")  # DDMMYY

    # Find last invoice for today
    last_sale = Sale.query.filter(
        Sale.invoice_no.like(f"INV-{today}-%")
    ).order_by(Sale.id.desc()).first()

    if last_sale:
        # Extract last incremental part
        last_number = int(last_sale.invoice_no.split("-")[-1])
        new_number = last_number + 1
    else:
        new_number = 1

    return f"INV-{today}-{new_number:03d}"

def get_low_stock_products():
    try:
        return Product.query.filter(Product.current_stock <= 5).all()
    except Exception:
        # Database schema not ready yet (e.g., during login)
        return []


def get_default_gst(product):
    name = (product.name or "").lower()

    # Life-saving drugs
    if "oncology" in name or "cancer" in name or "hiv" in name or "tb" in name:
        return 0, 0, 0

    # Vitamins / supplements
    if "vitamin" in name or "supplement" in name or "nutra" in name:
        return 18, 9, 9

    # Specialized equipment
    if "equipment" in name or "reagent" in name or "furniture" in name:
        return 18, 9, 9

    # Default: prescription / common medicines
    return 5, 2.5, 2.5

def gst_for_category(category):
    if category == "life_saving":
        return 0, 0, 0
    if category == "medicine":
        return 5, 2.5, 2.5
    if category == "ayurvedic":
        return 12, 6, 6
    if category in ["cosmetic", "fmcg", "equipment", "general"]:
        return 18, 9, 9
    return 5, 2.5, 2.5  # fallback


# ============================
# AUTH ROUTES
# ============================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page.
    Redirects authenticated users to dashboard.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))

        flash('Invalid credentials', 'danger')

    return render_template('auth/login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """
    Logout user and clear session cookie.
    """
    logout_user()
    session.clear()  # IMPORTANT FIX
    return redirect(url_for('login'))


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    """
    Forgot password page.
    Generates OTP and redirects to reset page.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = ForgotForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user:
            code = f"{datetime.utcnow().strftime('%f')[:6]}"
            expires = datetime.utcnow() + timedelta(minutes=app.config['OTP_EXPIRY_MINUTES'])

            try:
                otp = OTPCode(
                    user_id=user.id,
                    code=code,
                    expires_at=expires,
                    used=False
                )
                db.session.add(otp)
                db.session.commit()
            except Exception:
                db.session.rollback()

            flash(f"Your OTP is: {code}", 'info')
            logger.info("Generated OTP for %s: %s", user.username, code)
            return redirect(url_for('reset_otp'))

        flash('User ID not found', 'danger')

    return render_template('auth/forgot.html', form=form)


@app.route('/reset_otp', methods=['GET', 'POST'])
def reset_otp():
    """
    OTP verification and password reset.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = OTPVerifyForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if not user:
            flash('Invalid User ID', 'danger')
            return redirect(url_for('forgot'))

        otp = OTPCode.query.filter_by(
            user_id=user.id,
            code=form.otp.data,
            used=False
        ).order_by(OTPCode.expires_at.desc()).first()

        if not otp or otp.expires_at < datetime.utcnow():
            flash('Invalid or expired OTP', 'danger')
            return redirect(url_for('forgot'))

        otp.used = True
        user.password_hash = generate_password_hash(form.new_password.data)
        db.session.commit()

        flash('Password reset successful. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/reset_otp.html', form=form)


# ============================
# DASHBOARD
# ============================

@app.route('/')
@login_required
def dashboard():
    """
    Dashboard with stock alerts and sales summary.
    """
    # Low stock logic
    try:
        low_stock_count = Product.query.filter(Product.current_stock <= 5).count()
    except Exception:
        low_stock_count = 0

    # Expiry logic
    try:
        expiring_30 = Product.query.filter(
            Product.expiry_date != None,
            Product.expiry_date <= date.today() + timedelta(days=30)
        ).count()
    except Exception:
        expiring_30 = 0

    # Today's sales calculations
    today = date.today()
    start_today = datetime.combine(today, datetime.min.time())
    end_today = start_today + timedelta(days=1)

    today_total = db.session.query(
        func.coalesce(func.sum(Sale.total), 0.0)
    ).filter(
        Sale.date >= start_today,
        Sale.date < end_today
    ).scalar()

    # Yesterday's sales calculations
    yesterday = today - timedelta(days=1)
    start_y = datetime.combine(yesterday, datetime.min.time())
    end_y = start_y + timedelta(days=1)

    yesterday_total = db.session.query(
        func.coalesce(func.sum(Sale.total), 0.0)
    ).filter(
        Sale.date >= start_y,
        Sale.date < end_y
    ).scalar()

    # Last 7 days chart data
    last7 = []
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        s = datetime.combine(d, datetime.min.time())
        e = s + timedelta(days=1)

        total = db.session.query(
            func.coalesce(func.sum(Sale.total), 0.0)
        ).filter(
            Sale.date >= s,
            Sale.date < e
        ).scalar()

        last7.append((d, total))

    return render_template(
        'dashboard.html',
        low_stock_count=low_stock_count,
        expiring_30=expiring_30,
        today_total=today_total,
        yesterday_total=yesterday_total,
        last7=last7
    )

# ============================
# PRODUCT ROUTES
# ============================

@app.route('/products')
@login_required
def products():
    """Paginated product list (10 per page)."""
    page = request.args.get('page', 1, type=int)

    try:
        products = Product.query.order_by(Product.name).paginate(
            page=page,
            per_page=10,
            error_out=False
        )
    except Exception:
        # Database schema not fully refreshed yet
        products = []

    return render_template('products/list.html', products=products)



@app.route('/products/new', methods=['GET', 'POST'])
@login_required
def product_new():
    """
    Create new product.
    """
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    form = ProductForm()

    if form.validate_on_submit():
        sku_value = form.sku.data.strip() if form.sku.data else None

        if not sku_value:
            sku_value = f"AUTO-{int(datetime.utcnow().timestamp())}"

        p = Product(
            sku=sku_value,
            name=form.name.data,
            brand=form.brand.data,
            batch_no=form.batch_no.data,
            expiry_date=form.expiry_date.data,
            purchase_price=form.purchase_price.data or 0.0,
            sale_price=form.sale_price.data or 0.0,
            current_stock=form.current_stock.data or 0
        )

        db.session.add(p)

        try:
            db.session.commit()
            flash('Product added', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('SKU already exists. Please use a different SKU.', 'danger')
            return render_template('products/form.html', form=form)

        return redirect(url_for('products'))

    return render_template('products/form.html', form=form)


@app.route('/products/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def product_edit(product_id):
    """
    Edit existing product.
    """
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('products'))

    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)

    if form.validate_on_submit():
        sku_value = form.sku.data.strip() if form.sku.data else None

        if not sku_value:
            sku_value = product.sku or f"AUTO-{int(datetime.utcnow().timestamp())}"

        product.sku = sku_value
        product.name = form.name.data
        product.brand = form.brand.data
        product.batch_no = form.batch_no.data
        product.expiry_date = form.expiry_date.data
        product.purchase_price = form.purchase_price.data or 0.0
        product.sale_price = form.sale_price.data or 0.0
        product.current_stock = form.current_stock.data or 0

        try:
            db.session.commit()
            flash('Product updated', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('SKU already exists. Please use a different SKU.', 'danger')

        return redirect(url_for('products'))

    return render_template('products/form.html', form=form, product=product)

@app.route('/products/<int:product_id>/delete', methods=['POST'])
@login_required
def product_delete(product_id):
    if not is_admin():
        flash("Only admin can delete products", "danger")
        return redirect(url_for('products'))

    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()

    flash("Product deleted", "success")
    return redirect(url_for('products'))

# ============================
# PRODUCT DETAIL ROUTE (FINAL)
# ============================

@app.route('/products/<int:product_id>')
@login_required
def product_detail(product_id):
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    product = Product.query.get_or_404(product_id)

    # Fetch stock movement history
    movements = StockMovement.query.filter_by(
        product_id=product.id
    ).order_by(StockMovement.created_at.desc()).all()

    return render_template(
        'products/detail.html',
        product=product,
        movements=movements
    )


# ============================
# PRODUCT SEARCH ROUTE
# ============================

@app.route('/products/search')
@login_required
def product_search():
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    q = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)

    query = Product.query

    if q:
        query = query.filter(
            (Product.name.ilike(f"%{q}%")) |
            (Product.sku.ilike(f"%{q}%")) |
            (Product.brand.ilike(f"%{q}%"))
        )

    products = query.order_by(Product.name).paginate(
        page=page,
        per_page=10,
        error_out=False
    )

    return render_template('products/list.html', products=products, q=q)

@app.route("/products/get/<int:id>")
def get_product_gst(id):
    p = Product.query.get_or_404(id)

    gst, cgst, sgst = gst_for_category(p.category or "medicine")

    return {
        "gst_percent": gst,
        "cgst_percent": cgst,
        "sgst_percent": sgst,
        "category": p.category or ""
    }

# ============================
# USER MANAGEMENT ROUTES
# ============================


@app.route('/users')
@login_required
def users_list():
    """
    List all users (admin only).
    """
    if not admin_required():
        return redirect(url_for('dashboard'))

    users = User.query.order_by(User.username).all()
    return render_template('users/list.html', users=users)


@app.route('/users/new', methods=['GET', 'POST'])
@login_required
def user_new():
    """
    Create a new user (admin only).
    """
    if not admin_required():
        return redirect(url_for('dashboard'))

    form = UserForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data or None
        first_name = form.first_name.data
        last_name = form.last_name.data
        password = form.password.data or 'password123'
        role = form.role.data

        # Check duplicates
        if User.query.filter(
            (User.username == username) | (User.email == email)
        ).first():
            flash('User with same username or email already exists', 'danger')
            return redirect(url_for('users_list'))

        u = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password_hash=generate_password_hash(password),
            role=role
        )

        db.session.add(u)
        db.session.commit()
        ensure_user_file_label(u)

        flash('User created', 'success')
        return redirect(url_for('users_list'))

    return render_template('users/form.html', form=form)


@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def user_edit(user_id):
    """
    Edit user details (admin only).
    """
    if not admin_required():
        return redirect(url_for('dashboard'))

    u = User.query.get_or_404(user_id)
    form = UserForm(obj=u)

    if form.validate_on_submit():
        u.username = form.username.data
        u.email = form.email.data or None
        u.first_name = form.first_name.data
        u.last_name = form.last_name.data

        if form.password.data:
            u.password_hash = generate_password_hash(form.password.data)

        u.role = form.role.data

        db.session.commit()
        flash('User updated', 'success')
        return redirect(url_for('users_list'))

    return render_template('users/form.html', form=form, user=u)


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def user_delete(user_id):
    """
    Delete a user (admin only).
    """
    if not admin_required():
        return redirect(url_for('dashboard'))

    u = User.query.get_or_404(user_id)

    if u.username == 'admin':
        flash('Cannot delete default admin', 'danger')
        return redirect(url_for('users_list'))

    db.session.delete(u)
    db.session.commit()

    flash('User deleted', 'success')
    return redirect(url_for('users_list'))

# ============================
# PATIENT ROUTES
# ============================

@app.route('/patients')
@login_required
def patients():
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    # NEW: get search query
    query = request.args.get('q', '').strip()

    # NEW: apply search if query exists
    if query:
        patients = Customer.query.filter(
            (Customer.name.ilike(f"%{query}%")) |
            (Customer.phone.ilike(f"%{query}%")) |
            (Customer.address.ilike(f"%{query}%"))
        ).order_by(Customer.created_at.desc()).all()
    else:
        patients = Customer.query.order_by(Customer.created_at.desc()).all()

    # KEEP: selected patient logic
    selected_id = request.args.get('id', type=int)
    selected = Customer.query.get(selected_id) if selected_id else None

    prescriptions = []
    if selected:
        prescriptions = Prescription.query.filter_by(
            patient_id=selected.id
        ).order_by(Prescription.date.desc()).all()

    return render_template(
        'patients/list.html',
        patients=patients,
        selected=selected,
        prescriptions=prescriptions,
        query=query   # NEW: pass search text to template
    )


@app.route('/patients/new', methods=['GET', 'POST'])
@login_required
def patient_new():
    """
    Create a new patient record.
    """
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    form = PatientForm()

    if form.validate_on_submit():
        p = Customer(
            name=form.name.data,
            phone=form.phone.data,
            address=form.address.data,
            description=form.description.data
        )
        db.session.add(p)
        db.session.commit()

        flash('Patient added', 'success')
        return redirect(url_for('patients'))

    return render_template('patients/form.html', form=form)

@app.route('/patients/<int:patient_id>/edit', methods=['GET', 'POST'])
@login_required
def patient_edit(patient_id):
    if not is_admin():
        flash("Only admin can edit patients", "danger")
        return redirect(url_for('patients'))

    patient = Customer.query.get_or_404(patient_id)

    # If you already have a PatientForm, use it here
    form = PatientForm(obj=patient)

    if form.validate_on_submit():
        patient.name = form.name.data
        patient.phone = form.phone.data
        patient.address = form.address.data
        patient.description = form.description.data
        db.session.commit()

        flash("Patient updated successfully", "success")
        return redirect(url_for('patients', id=patient.id))

    return render_template('patients/form.html', form=form, patient=patient)

@app.route('/patients/<int:patient_id>/delete', methods=['POST'])
@login_required
def patient_delete(patient_id):
    if not is_admin():
        flash("Only admin can delete patients", "danger")
        return redirect(url_for('patients'))

    patient = Customer.query.get_or_404(patient_id)
    db.session.delete(patient)
    db.session.commit()

    flash("Patient deleted", "success")
    return redirect(url_for('patients'))

# ============================
# SALES ROUTES
# ============================

@app.route('/sales')
@login_required
def sales_list():
    """
    List all sales.
    """
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    sales = Sale.query.order_by(Sale.date.desc()).all()
    return render_template('sales/list.html', sales=sales)


	
@app.route('/sales/search')
@login_required
def sales_search():
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    q = request.args.get('q', '').strip()

    if not q:
        return redirect(url_for('sales_list'))

    sales = Sale.query.filter(
        (Sale.invoice_no.ilike(f"%{q}%")) |
        (Sale.customer_id.ilike(f"%{q}%"))
    ).order_by(Sale.date.desc()).all()

    return render_template('sales/list.html', sales=sales)

@app.route('/sales/<int:sale_id>/edit', methods=['GET', 'POST'])
@login_required
def sale_edit(sale_id):
    if current_user.role not in ('admin', 'staff'):
        flash("Unauthorized", "danger")
        return redirect(url_for('sales_list'))

    sale = Sale.query.get_or_404(sale_id)
    customers = Customer.query.order_by(Customer.name).all()
    try:
    	products = Product.query.order_by(Product.name).all()
    except Exception:
        products = []


    # Load existing items
    existing_items = SaleItem.query.filter_by(sale_id=sale.id).all()

    if request.method == 'POST':
        customer_id = request.form.get('customer_id', type=int)

        product_ids = request.form.getlist('product_id')
        qtys = request.form.getlist('qty')
        prices = request.form.getlist('unit_price')
        discounts = request.form.getlist('discount')

        # Reverse stock for old items
        for item in existing_items:
            product = Product.query.get(item.product_id)
            if product:
                product.current_stock += item.qty
            db.session.delete(item)

        total = 0
        new_items = []

        for pid, q, up, disc in zip(product_ids, qtys, prices, discounts):
            if not pid or not q:
                continue

            pid = int(pid)
            qty = int(q)
            unit_price = float(up or 0)
            discount = float(disc or 0)

            line_total = qty * unit_price - discount
            if line_total < 0:
                line_total = 0

            total += line_total
            new_items.append((pid, qty, unit_price, discount))

        # Update sale
        sale.customer_id = customer_id
        sale.total = total
        db.session.commit()

        # Insert new items + stock movement
        for pid, qty, unit_price, discount in new_items:
            si = SaleItem(
                sale_id=sale.id,
                product_id=pid,
                qty=qty,
                unit_price=unit_price,
                discount=discount
            )
            db.session.add(si)

            product = Product.query.get(pid)
            if product:
                product.current_stock -= qty

                sm = StockMovement(
                    product_id=product.id,
                    movement_type='OUT',
                    quantity=qty,
                    reference=sale.invoice_no,
                    note='Sale Edit'
                )
                db.session.add(sm)

        db.session.commit()

        flash("Sale updated", "success")
        return redirect(url_for('invoice_view', sale_id=sale.id))

    return render_template(
        'sales/edit.html',
        sale=sale,
        customers=customers,
        products=products,
        items=existing_items
    )


@app.route('/sales/<int:sale_id>/delete', methods=['POST'])
@login_required
def sale_delete(sale_id):
    if current_user.role not in ('admin', 'staff'):
        flash("Unauthorized", "danger")
        return redirect(url_for('sales_list'))

    sale = Sale.query.get_or_404(sale_id)
    db.session.delete(sale)
    safe_commit()

    flash("Sale deleted", "success")
    return redirect(url_for('sales_list'))

@app.route('/sales/new', methods=['GET', 'POST'])
@login_required
def sales_new():
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    customers = Customer.query.order_by(Customer.name).all()
    
    # Fix: Indent 'products' inside try, and 'products = []' inside except
    try:
        products = Product.query.order_by(Product.name).all()
    except Exception:
        products = []

    # Always generate invoice number for GET and POST
    invoice_no = f"INV-{int(datetime.utcnow().timestamp())}"

    if request.method == 'POST':
        customer_id = request.form.get('customer_id', type=int)

        product_ids = request.form.getlist('product_id')
        qtys = request.form.getlist('qty')
        prices = request.form.getlist('unit_price')
        discounts = request.form.getlist('discount')

        items_to_process = []
        total_amount = 0.0

        for pid, q, up, disc in zip(product_ids, qtys, prices, discounts):
            if not pid or not q:
                continue

            pid = int(pid)
            qty = int(q)
            unit_price = float(up or 0.0)
            discount = float(disc or 0.0)

            line_total = (qty * unit_price) - discount
            total_amount += line_total

            items_to_process.append((pid, qty, unit_price, discount))

        # Create sale record
        sale = Sale(
            invoice_no=invoice_no,
            customer_id=customer_id,
            total=total_amount,
            created_by=current_user.id
        )
        db.session.add(sale)
        db.session.flush()  # Use flush to get sale.id without committing yet

        # Insert sale items + stock movement
        for pid, qty, unit_price, discount in items_to_process:
            si = SaleItem(
                sale_id=sale.id,
                product_id=pid,
                qty=qty,
                unit_price=unit_price,
                discount=discount
            )
            db.session.add(si)

            product = Product.query.get(pid)
            if product:
                product.current_stock -= qty

                sm = StockMovement(
                    product_id=product.id,
                    movement_type='OUT',
                    quantity=qty,
                    reference=sale.invoice_no,
                    note='Sale'
                )
                db.session.add(sm)

        # Single commit at the end for atomicity
        db.session.commit()

        flash('Sale created', 'success')
        return redirect(url_for('invoice_view', sale_id=sale.id))

    # GET request
    return render_template(
        'sales/new.html',
        customers=customers,
        products=products,
        invoice_no=invoice_no
    )
# ============================
# INVOICE ROUTES
# ============================

@app.route('/invoice/<int:sale_id>')
@login_required
def invoice_view(sale_id):
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    sale = Sale.query.get_or_404(sale_id)
    items = SaleItem.query.filter_by(sale_id=sale.id).all()
    customer = Customer.query.get(sale.customer_id) if sale.customer_id else None

    # Calculate grand total (same logic as PDF)
    grand_total = 0
    for it in items:
        line = (it.qty or 0) * (it.unit_price or 0) - (it.discount or 0)
        if line < 0:
            line = 0
        grand_total += line

    return render_template(
        'invoice.html',
        sale=sale,
        items=items,
        customer=customer,
        grand_total=grand_total
    )


@app.route('/invoice/<int:sale_id>/pdf')
@login_required
def invoice_pdf(sale_id):
    """
    Generate PDF invoice using WeasyPrint.
    """
    from weasyprint import HTML, CSS

    sale = Sale.query.get_or_404(sale_id)
    items = SaleItem.query.filter_by(sale_id=sale.id).all()
    customer = Customer.query.get(sale.customer_id) if sale.customer_id else None

    # Calculate total safely
    grand_total = 0
    for it in items:
        line = (it.qty or 0) * (it.unit_price or 0) - (it.discount or 0)
        if line < 0:
            line = 0
        grand_total += line

    html = render_template(
        'invoice_pdf.html',
        sale=sale,
        items=items,
        customer=customer,
        grand_total=grand_total
    )

    pdf = HTML(string=html).write_pdf(
        stylesheets=[CSS(filename=os.path.join(app.root_path, 'static/css/style.css'))]
    )

    return pdf


# ============================
# BILLING ROUTES
# ============================

@app.route('/billing')
@login_required
def billing_list():
    """List all bills."""
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    bills = Billing.query.order_by(Billing.date.desc()).all()
    patients = {p.id: p for p in Customer.query.all()}

    return render_template(
        'billing/list.html',
        bills=bills,
        patients=patients
    )

def get_default_gst(product):
    name = (product.name or "").lower()

    # Life-saving drugs
    if "oncology" in name or "cancer" in name or "hiv" in name or "tb" in name:
        return 0, 0, 0

    # Vitamins / supplements
    if "vitamin" in name or "supplement" in name or "nutra" in name:
        return 18, 9, 9

    # Specialized equipment
    if "equipment" in name or "reagent" in name or "furniture" in name:
        return 18, 9, 9

    # Default: prescription / common medicines
    return 5, 2.5, 2.5

@app.route('/billing/new', methods=['GET', 'POST'])
@login_required
def billing_new():
    # Fix: Corrected try/except blocks and removed duplicate code
    try:
        distributors = Distributor.query.order_by(Distributor.name).all()
    except Exception:
        distributors = []

    try:
        products = Product.query.order_by(Product.name).all()
    except Exception:
        products = []

    if request.method == 'POST':
        raw_distributor = request.form.get('distributor_id')
        distributor_id = int(raw_distributor) if raw_distributor and raw_distributor.isdigit() else None
        invoice_no = request.form.get('invoice_no')
        invoice_date = request.form.get('invoice_date')
        purchase_date = request.form.get('purchase_date')
        payment_status = request.form.get('payment_status')
        payment_mode = request.form.get('payment_mode')
        notes = request.form.get('notes')

        inv_date = datetime.strptime(invoice_date, "%Y-%m-%d").date() if invoice_date else None
        pur_date = datetime.strptime(purchase_date, "%Y-%m-%d").date() if purchase_date else date.today()

        # Item lists
        product_ids = request.form.getlist('product_id[]')
        hsn_codes = request.form.getlist('hsn_code[]')
        batch_nos = request.form.getlist('batch_no[]')
        expiry_dates = request.form.getlist('expiry_date[]')
        qtys = request.form.getlist('qty[]')
        free_qtys = request.form.getlist('free_qty[]')
        purchase_prices = request.form.getlist('purchase_price[]')
        mrps = request.form.getlist('mrp[]')
        sale_prices = request.form.getlist('sale_price[]')
        gst_percents = request.form.getlist('gst_percent[]')
        cgst_percents = request.form.getlist('cgst_percent[]')
        sgst_percents = request.form.getlist('sgst_percent[]')
        discount_amounts = request.form.getlist('discount_amount[]')

        subtotal = 0.0
        total_discount = 0.0
        total_cgst = 0.0
        total_sgst = 0.0

        purchase_no = f"PUR-{int(datetime.utcnow().timestamp())}"

        purchase = Purchase(
            purchase_no=purchase_no,
            distributor_id=distributor_id,
            invoice_no=invoice_no,
            invoice_date=inv_date,
            purchase_date=pur_date,
            payment_status=payment_status,
            payment_mode=payment_mode,
            notes=notes,
            created_by=current_user.id
        )
        db.session.add(purchase)
        db.session.flush()

        for i in range(len(product_ids)):
            if not product_ids[i]:
                continue

            pid = int(product_ids[i])
            product = Product.query.get(pid)

            qty = int(qtys[i] or 0)
            free_qty = int(free_qtys[i]) if i < len(free_qtys) and free_qtys[i] else 0
            p_price = float(purchase_prices[i] or 0)
            mrp = float(mrps[i] or 0)
            s_price = float(sale_prices[i] or 0)

            # ⭐ GST Calculation logic
            default_gst, default_cgst, default_sgst = get_default_gst(product)

            gst_p = float(gst_percents[i] or default_gst)
            cgst_p = float(cgst_percents[i] or default_cgst)
            sgst_p = float(sgst_percents[i] or default_sgst)

            disc_amt = float(discount_amounts[i] or 0)
            exp_date = datetime.strptime(expiry_dates[i], "%Y-%m-%d").date() if expiry_dates[i] else None

            base_amount = qty * p_price
            taxable_amount = base_amount - disc_amt

            cgst_amt = taxable_amount * (cgst_p / 100.0)
            sgst_amt = taxable_amount * (sgst_p / 100.0)
            line_total = taxable_amount + cgst_amt + sgst_amt

            subtotal += base_amount
            total_discount += disc_amt
            total_cgst += cgst_amt
            total_sgst += sgst_amt

            item = PurchaseItem(
                purchase_id=purchase.id,
                product_id=pid,
                hsn_code=hsn_codes[i],
                batch_no=batch_nos[i],
                expiry_date=exp_date,
                qty=qty,
                free_qty=free_qty,
                purchase_price=p_price,
                mrp=mrp,
                sale_price=s_price,
                gst_percent=gst_p,
                cgst_percent=cgst_p,
                sgst_percent=sgst_p,
                cgst_amount=cgst_amt,
                sgst_amount=sgst_amt,
                discount_amount=disc_amt,
                line_total=line_total
            )
            db.session.add(item)

            # Update stock
            if product:
                product.current_stock = (product.current_stock or 0) + qty + free_qty

        purchase.subtotal = subtotal
        purchase.total_discount = total_discount
        purchase.total_cgst = total_cgst
        purchase.total_sgst = total_sgst
        purchase.grand_total = subtotal - total_discount + total_cgst + total_sgst

        db.session.commit()
        flash("Purchase saved successfully", "success")
        return redirect(url_for('billing_list'))

    return render_template(
        'billing/new.html',
        distributors=distributors,
        products=products,
        today=date.today()
    )



@app.route('/billing/<int:bill_id>')
@login_required
def billing_view(bill_id):
    bill = Billing.query.get_or_404(bill_id)
    items = BillingItem.query.filter_by(bill_id=bill.id).all()

    # Recalculate total
    grand_total = 0
    for it in items:
        qty = it.qty or 0
        price = it.unit_price or 0
        discount = it.discount or 0

        line = (qty * price) - discount
        if line < 0:
            line = 0

        grand_total += line

    bill.total = grand_total
    safe_commit()

    patient = Customer.query.get(bill.patient_id)

    return render_template(
        'billing/view.html',
        bill=bill,
        items=items,
        patient=patient,
        grand_total=grand_total
    )


@app.route('/billing/<int:bill_id>/edit', methods=['GET', 'POST'])
@login_required
def billing_edit(bill_id):
    if not is_admin():
        flash("Only admin can edit bills", "danger")
        return redirect(url_for('billing_list'))

    bill = Billing.query.get_or_404(bill_id)
    items = BillingItem.query.filter_by(bill_id=bill.id).all()
    patients = Customer.query.order_by(Customer.name).all()

    if request.method == 'POST':
        bill.patient_id = request.form.get('patient_id', type=int)

        BillingItem.query.filter_by(bill_id=bill.id).delete(synchronize_session=False)


        descs = request.form.getlist('item_desc')
        qtys = request.form.getlist('item_qty')
        prices = request.form.getlist('item_price')
        discounts = request.form.getlist('item_discount')

        total = 0

        for d, q, p, disc in zip(descs, qtys, prices, discounts):
            if not d:
                continue

            qty = int(q or 0)
            price = float(p or 0)
            discount = float(disc or 0)

            line = qty * price - discount
            if line < 0:
                line = 0

            total += line

            db.session.add(BillingItem(
                bill_id=bill.id,
                product_name=d,
                qty=qty,
                unit_price=price,
                discount=discount
            ))

        bill.total = total
        safe_commit()

        flash("Bill updated successfully", "success")
        return redirect(url_for('billing_view', bill_id=bill.id))

    return render_template(
        'billing/edit.html',
        bill=bill,
        items=items,
        patients=patients
    )


@app.route('/billing/<int:bill_id>/delete', methods=['POST'])
@login_required
def billing_delete(bill_id):
    if not is_admin():
        flash("Only admin can delete billing entries", "danger")
        return redirect(url_for('billing_list'))

    bill = Billing.query.get_or_404(bill_id)

    # ⭐ FIX: Delete child rows first
    BillingItem.query.filter_by(bill_id=bill.id).delete(synchronize_session=False)

    db.session.delete(bill)
    safe_commit()

    flash("Billing entry deleted", "success")
    return redirect(url_for('billing_list'))

# ============================
# DISTRIBUTOR ROUTES
# ============================
@app.route('/distributors')
@login_required
def distributor_list():
    return render_template('distributors/list.html')


# ============================
# PURCHASE ROUTES
# ============================

@app.route('/purchases')
@login_required
def purchase_list():
    purchases = Purchase.query.order_by(Purchase.id.desc()).all()
    distributors = {d.id: d for d in Distributor.query.all()}

    return render_template(
        'billing/list.html',
        mode="purchase",
        purchases=purchases,
        distributors=distributors
    )

@app.route("/products/add_inline", methods=["POST"])
def add_inline_product():
    data = request.get_json()
    name = data.get("name")
    category = data.get("category", "medicine")  # default category

    if not name:
        return {"success": False, "message": "No name provided"}, 400

    existing = Product.query.filter_by(name=name).first()
    if existing:
        return {"success": True, "id": existing.id}

    import random
    sku = f"SKU-{random.randint(100000, 999999)}"

    gst, cgst, sgst = gst_for_category(category)

    new_product = Product(
        name=name,
        sku=sku,
        category=category,
        gst_percent=gst,
        cgst_percent=cgst,
        sgst_percent=sgst,
        current_stock=0
    )

    db.session.add(new_product)
    db.session.commit()

    return {"success": True, "id": new_product.id}

@app.route('/purchases/<int:purchase_id>')
@login_required
def purchase_view(purchase_id):
    purchase = Purchase.query.get_or_404(purchase_id)
    items = PurchaseItem.query.filter_by(purchase_id=purchase.id).all()
    distributor = Distributor.query.get(purchase.distributor_id)

    return render_template(
        'billing/view.html',
        purchase=purchase,
        items=items,
        distributor=distributor,
        mode="purchase"
    )


@app.route('/purchases/<int:purchase_id>/edit', methods=['GET', 'POST'])
@login_required
def purchase_edit(purchase_id):
    purchase = Purchase.query.get_or_404(purchase_id)
    items = PurchaseItem.query.filter_by(purchase_id=purchase.id).all()
    
    # Corrected indentation for Distributor try-except
    try:
        distributors = Distributor.query.order_by(Distributor.name).all()
    except Exception:
        distributors = []

    # Corrected indentation for Product try-except
    try:
        products = Product.query.order_by(Product.name).all()
    except Exception:
        products = []

    if request.method == 'POST':
        # HEADER FIELDS
        purchase.invoice_no = request.form.get("invoice_no")

        inv_date = request.form.get("invoice_date")
        pur_date = request.form.get("purchase_date")

        purchase.invoice_date = datetime.strptime(inv_date, "%Y-%m-%d").date() if inv_date else None
        purchase.purchase_date = datetime.strptime(pur_date, "%Y-%m-%d").date() if pur_date else None

        purchase.payment_status = request.form.get("payment_status")
        purchase.payment_mode = request.form.get("payment_mode")
        purchase.notes = request.form.get("notes")

        # RESET TOTALS
        subtotal = 0
        total_discount = 0
        total_cgst = 0
        total_sgst = 0

        # UPDATE ITEMS
        for it in items:
            it.hsn_code = request.form.get(f"hsn_{it.id}")
            it.batch_no = request.form.get(f"batch_{it.id}")

            exp = request.form.get(f"expiry_{it.id}")
            it.expiry_date = datetime.strptime(exp, "%Y-%m-%d").date() if exp else None

            # Note: Changing quantity here will not update 'current_stock' in Product. 
            # If you want stock to sync, you'll need additional logic here.
            it.qty = int(request.form.get(f"qty_{it.id}") or 0)
            it.free_qty = int(request.form.get(f"free_{it.id}") or 0)

            it.purchase_price = float(request.form.get(f"pp_{it.id}") or 0)
            it.mrp = float(request.form.get(f"mrp_{it.id}") or 0)
            it.sale_price = float(request.form.get(f"sp_{it.id}") or 0)

            it.gst_percent = float(request.form.get(f"gst_{it.id}") or 0)
            it.cgst_percent = float(request.form.get(f"cgst_{it.id}") or 0)
            it.sgst_percent = float(request.form.get(f"sgst_{it.id}") or 0)

            it.discount_amount = float(request.form.get(f"disc_{it.id}") or 0)

            # RECALCULATE LINE TOTAL
            base_amount = it.qty * it.purchase_price
            taxable = base_amount - it.discount_amount

            it.cgst_amount = taxable * (it.cgst_percent / 100)
            it.sgst_amount = taxable * (it.sgst_percent / 100)
            it.line_total = taxable + it.cgst_amount + it.sgst_amount

            subtotal += base_amount
            total_discount += it.discount_amount
            total_cgst += it.cgst_amount
            total_sgst += it.sgst_amount

        # UPDATE TOTALS
        purchase.subtotal = subtotal
        purchase.total_discount = total_discount
        purchase.total_cgst = total_cgst
        purchase.total_sgst = total_sgst
        purchase.grand_total = subtotal - total_discount + total_cgst + total_sgst

        db.session.commit()

        flash("Purchase updated successfully!", "success")
        return redirect(url_for("purchase_list"))

    return render_template(
        'billing/edit.html',
        purchase=purchase,
        items=items,
        distributors=distributors,
        products=products,
        mode="purchase"
    )


@app.route('/purchases/<int:purchase_id>/delete', methods=['POST'])
@login_required
def purchase_delete(purchase_id):
    purchase = Purchase.query.get_or_404(purchase_id)

    PurchaseItem.query.filter_by(purchase_id=purchase.id).delete(synchronize_session=False)
    db.session.delete(purchase)
    safe_commit()

    flash("Purchase deleted", "success")
    return redirect(url_for('purchase_list'))




# ============================
# REPORT ROUTES
# ============================

@app.route('/reports/sales')
@login_required
def report_sales():
    """Paginated sales report (10 per page)."""
    page = request.args.get('page', 1, type=int)

    sales = Sale.query.order_by(Sale.date.desc()).paginate(
        page=page,
        per_page=10,
        error_out=False
    )

    # Total of ALL sales (not just current page)
    total = sum((s.total or 0) for s in Sale.query.all())

    return render_template(
        'reports/sales_report.html',
        sales=sales,
        total=total
    )


@app.route('/reports/stock')
@login_required
def report_stock():
    """Paginated stock report (10 per page)."""
    page = request.args.get('page', 1, type=int)

    products = Product.query.order_by(Product.name).paginate(
        page=page,
        per_page=10,
        error_out=False
    )

    # Total value of ALL products
    total_value = sum(
        (p.current_stock or 0) * (p.purchase_price or 0)
        for p in Product.query.all()
    )

    return render_template(
        'reports/stock_report.html',
        products=products,
        total_value=total_value
    )


@app.route('/reports/expiry')
@login_required
def report_expiry():
    """Paginated expiry report (10 per page)."""
    from datetime import date, timedelta

    page = request.args.get('page', 1, type=int)

    products_query = Product.query.order_by(Product.expiry_date)

    products = products_query.paginate(
        page=page,
        per_page=10,
        error_out=False
    )

    current_date = date.today()
    soon_date = current_date + timedelta(days=30)

    # Counts must use full dataset
    all_products = products_query.all()

    expired_count = sum(
        1 for p in all_products
        if p.expiry_date and p.expiry_date <= current_date
    )

    expiring_soon_count = sum(
        1 for p in all_products
        if p.expiry_date and current_date < p.expiry_date <= soon_date
    )

    return render_template(
        'reports/expiry_report.html',
        products=products,
        current_date=current_date,
        soon_date=soon_date,
        expired_count=expired_count,
        expiring_soon_count=expiring_soon_count
    )



@app.route('/guide')
@login_required
def guide():
    return render_template('guide.html')

# ============================
# APPOINTMENT ROUTES
# ============================

@app.route('/appointments')
@login_required
def appointments_list():
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    status_filter = request.args.get('status', 'all')
    search = request.args.get('search', '').strip()

    q = Appointment.query

    if status_filter != 'all':
        q = q.filter_by(status=status_filter)

    appointments = q.order_by(Appointment.appointment_time.desc()).all()

    doctors = {d.id: d for d in Doctor.query.all()}
    patients = {p.id: p for p in Customer.query.all()}

    # ⭐ Patient name search
    if search:
        filtered = [
            a for a in appointments
            if a.patient_id in patients and search.lower() in patients[a.patient_id].name.lower()
        ]

        if not filtered:
            flash("No patient found – please book an appointment again or consult with doctor", "warning")
            appointments = []
        else:
            appointments = filtered

    return render_template(
        'appointments/list.html',
        appointments=appointments,
        doctors=doctors,
        patients=patients,
        status_filter=status_filter
    )


@app.route('/appointments/<int:aid>/edit', methods=['GET', 'POST'])
@login_required
def appointments_edit(aid):
    if not is_admin():
        flash("Only admin can edit appointments", "danger")
        return redirect(url_for('appointments_list'))

    appt = Appointment.query.get_or_404(aid)
    patients = Customer.query.order_by(Customer.name).all()
    doctors = Doctor.query.order_by(Doctor.name).all()

    form = AppointmentForm(obj=appt)
    form.patient_id.choices = [(p.id, p.name) for p in patients]
    form.doctor_id.choices = [(0, '-- None --')] + [(d.id, d.name) for d in doctors]

    if form.validate_on_submit():
        appt.patient_id = form.patient_id.data
        appt.doctor_id = form.doctor_id.data or None
        appt.reason = form.reason.data
        appt.status = form.status.data

        safe_commit()
        flash("Appointment updated", "success")
        return redirect(url_for('appointments_list'))

    return render_template('appointments/form.html', form=form)


@app.route('/appointments/<int:aid>/delete', methods=['POST'])
@login_required
def appointments_delete(aid):
    if not is_admin():
        flash("Only admin can delete appointments", "danger")
        return redirect(url_for('appointments_list'))

    appt = Appointment.query.get_or_404(aid)
    db.session.delete(appt)
    safe_commit()

    flash("Appointment deleted", "success")
    return redirect(url_for('appointments_list'))


@app.route('/appointments/new', methods=['GET', 'POST'])
@login_required
def appointments_new():
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    patients = Customer.query.order_by(Customer.name).all()
    doctors = Doctor.query.order_by(Doctor.name).all()

    form = AppointmentForm()
    form.patient_id.choices = [(p.id, p.name) for p in patients]
    form.doctor_id.choices = [(0, '-- None --')] + [(d.id, d.name) for d in doctors]

    if form.validate_on_submit():
        doctor_id = form.doctor_id.data or None
        if doctor_id == 0:
            doctor_id = None

        appt = Appointment(
            patient_id=form.patient_id.data,
            doctor_id=doctor_id,
            appointment_time=datetime.now(datetime.UTC),
            reason=form.reason.data,
            status=form.status.data
        )

        db.session.add(appt)
        safe_commit()

        flash('Appointment created', 'success')
        return redirect(url_for('appointments_list'))

    return render_template('appointments/form.html', form=form)

# ============================
# DOCTOR ROUTES
# ============================

@app.route('/doctors')
@login_required
def doctors_list():
    """List all doctors."""
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    doctors = Doctor.query.order_by(Doctor.name).all()
    return render_template('doctors/list.html', doctors=doctors)


@app.route('/doctors/search')
@login_required
def doctor_search():
    """Search doctors by name or specialization."""
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    q = request.args.get('q', '').strip()

    if not q:
        return redirect(url_for('doctors_list'))

    doctors = Doctor.query.filter(
        (Doctor.name.ilike(f"%{q}%")) |
        (Doctor.specialization.ilike(f"%{q}%"))
    ).order_by(Doctor.name).all()

    return render_template('doctors/list.html', doctors=doctors)


@app.route('/doctors/<int:doctor_id>')
@login_required
def doctor_detail(doctor_id):
    """View doctor details."""
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    doctor = Doctor.query.get_or_404(doctor_id)
    return render_template('doctors/detail.html', doctor=doctor)


@app.route('/doctors/new', methods=['GET', 'POST'])
@login_required
def doctors_new():
    """Create a new doctor record."""
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    form = DoctorForm()

    if form.validate_on_submit():
        d = Doctor(
            name=form.name.data,
            specialization=form.specialization.data,
            phone=form.phone.data,
            notes=form.notes.data
        )
        db.session.add(d)
        safe_commit()

        flash('Doctor added', 'success')
        return redirect(url_for('doctors_list'))

    return render_template('doctors/form.html', form=form)


@app.route('/doctors/<int:doctor_id>/edit', methods=['GET', 'POST'])
@login_required
def doctors_edit(doctor_id):
    """Edit doctor details."""
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    d = Doctor.query.get_or_404(doctor_id)
    form = DoctorForm(obj=d)

    if form.validate_on_submit():
        d.name = form.name.data
        d.specialization = form.specialization.data
        d.phone = form.phone.data
        d.notes = form.notes.data

        safe_commit()
        flash('Doctor updated', 'success')

        return redirect(url_for('doctors_list'))

    return render_template('doctors/form.html', form=form, doctor=d)


@app.route('/doctors/<int:doctor_id>/delete', methods=['POST'])
@login_required
def doctors_delete(doctor_id):
    """Delete a doctor (admin + staff allowed)."""
    if current_user.role not in ('admin', 'staff'):
        flash("Unauthorized", "danger")
        return redirect(url_for('doctors_list'))

    d = Doctor.query.get_or_404(doctor_id)
    db.session.delete(d)
    safe_commit()

    flash('Doctor deleted', 'success')
    return redirect(url_for('doctors_list'))

# ============================
# PRESCRIPTION ROUTES
# ============================

@app.route('/patients/<int:patient_id>/prescriptions')
@login_required
def prescriptions_list(patient_id):
    """
    List prescriptions for a patient.
    """
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    patient = Customer.query.get_or_404(patient_id)

    prescriptions = Prescription.query.filter_by(
        patient_id=patient.id
    ).order_by(Prescription.date.desc()).all()

    doctors = {d.id: d for d in Doctor.query.all()}

    return render_template(
        'prescriptions/list.html',
        patient=patient,
        prescriptions=prescriptions,
        doctors=doctors
    )


@app.route('/patients/<int:patient_id>/prescriptions/new', methods=['GET', 'POST'])
@login_required
def prescriptions_new(patient_id):
    """
    Create a new prescription for a patient.
    """
    if current_user.role not in ('admin', 'staff'):
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))

    patient = Customer.query.get_or_404(patient_id)
    doctors = Doctor.query.order_by(Doctor.name).all()

    form = PrescriptionForm()
    form.doctor_id.choices = [(0, '-- None --')] + [(d.id, d.name) for d in doctors]

    if request.method == 'POST' and form.validate_on_submit():
        doctor_id = form.doctor_id.data or None
        if doctor_id == 0:
            doctor_id = None

        pres = Prescription(
            patient_id=patient.id,
            doctor_id=doctor_id,
            diagnosis=form.diagnosis.data,
            notes=form.notes.data
        )
        db.session.add(pres)
        db.session.commit()

        names = request.form.getlist('med_name')
        dosages = request.form.getlist('med_dosage')
        freqs = request.form.getlist('med_freq')
        durs = request.form.getlist('med_duration')

        for n, d, f, du in zip(names, dosages, freqs, durs):
            if not n:
                continue

            item = PrescriptionItem(
                prescription_id=pres.id,
                medicine_name=n,
                dosage=d,
                frequency=f,
                duration=du
            )
            db.session.add(item)

        db.session.commit()

        flash('Prescription created', 'success')
        return redirect(url_for('prescriptions_list', patient_id=patient.id))

    return render_template('prescriptions/form.html', form=form, patient=patient)

@app.route('/prescriptions/<int:pres_id>/delete', methods=['POST'])
@login_required
def prescription_delete(pres_id):
    if not is_admin():
        flash("Only admin can delete prescriptions", "danger")
        return redirect(url_for('patients'))

    pres = Prescription.query.get_or_404(pres_id)
    patient_id = pres.patient_id

    db.session.delete(pres)
    db.session.commit()

    flash("Prescription deleted", "success")
    return redirect(url_for('prescriptions_list', patient_id=patient_id))

# ============================
# GLOBAL TEMPLATE VARIABLES
# ============================

@app.context_processor
def inject_globals():
    if current_user.is_authenticated:
        initials = current_user.username[:2].upper()
        display_name = current_user.username
    else:
        initials = ""
        display_name = ""

    ist = datetime.utcnow() + timedelta(hours=5, minutes=30)
    current_dt_display = ist.strftime("%A, %d %b %Y, %I:%M:%S %p IST")
    current_day = ist.strftime("%A")

    return dict(
        initials=initials,
        display_name=display_name,
        current_dt_display=current_dt_display,
        current_day=current_day,
        is_admin=is_admin   # ⭐ ADD THIS LINE
    )

# ============================
# DATABASE INITIALIZATION
# ============================

def initialize_database():
    """
    Ensures database exists and admin user is always present.
    """
    db_path = os.path.join(app.root_path, 'app.db')

    with app.app_context():
        # Always create tables (safe if they already exist)
        db.create_all()

        # ============================================
        # ALWAYS ENSURE ADMIN USER EXISTS
        # ============================================
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                role='admin'
            )
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()
            print(">>> Admin created: admin / admin123")
        else:
            print(">>> Admin already exists")

        # ============================================
        # FIRST-TIME DATA ONLY IF DB FILE WAS MISSING
        # ============================================
        if not os.path.exists(db_path):
            print("Database created (first-time setup).")

            # Walk-in Patient
            if Customer.query.count() == 0:
                c1 = Customer(
                    name="Walk-in Patient",
                    phone="",
                    address="",
                    description=""
                )
                db.session.add(c1)
                db.session.commit()
                print("Default Walk-in Patient added.")

            # Demo Product
            if Product.query.count() == 0:
                now_ts = int(datetime.utcnow().timestamp())
                p1 = Product(
                    sku=f"AUTO-{now_ts}-1",
                    name="Paracetamol 500mg",
                    brand="MediCare",
                    batch_no="BATCH-001",
                    expiry_date=date.today() + timedelta(days=365),
                    purchase_price=5.0,
                    sale_price=10.0,
                    current_stock=50
                )
                db.session.add(p1)
                db.session.commit()
                print("Demo product added.")

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

@app.context_processor
def inject_low_stock():
    from flask import request

    # Disable low-stock queries for ALL auth-related endpoints
    # This prevents SQLAlchemy from querying before schema is ready
    if request.endpoint and (
        "login" in request.endpoint or
        "auth" in request.endpoint
    ):
        return dict(low_stock=[], expiring_soon=[])

    try:
        # Low stock (<= 5)
        low_stock = Product.query.filter(Product.current_stock <= 5).all()

        # Expiring within next 30 days
        today = date.today()
        soon = today + timedelta(days=30)

        expiring_soon = Product.query.filter(
            Product.expiry_date <= soon,
            Product.expiry_date >= today
        ).all()

        return dict(
            low_stock=low_stock,
            expiring_soon=expiring_soon
        )

    except Exception:
        # If DB schema isn't ready yet, return empty lists
        return dict(low_stock=[], expiring_soon=[])


# ============================
# APP RUNNER
# ============================

if __name__ == '__main__':
    initialize_database()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)



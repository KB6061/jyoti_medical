from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# ============================
# USER MODEL (FIXED)
# ============================
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='staff')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    first_name = db.Column(db.String(120), nullable=True)
    last_name = db.Column(db.String(120), nullable=True)
    file_label = db.Column(db.String(64), nullable=True)
    profile_image = db.Column(db.String(256), nullable=True)

    # Password helpers
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# ============================
# OTP CODES
# ============================
class OTPCode(db.Model):
    __tablename__ = 'otp_codes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    code = db.Column(db.String(10), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)


# ============================
# PRODUCTS
# ============================
class Product(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    brand = db.Column(db.String(100))
    batch_no = db.Column(db.String(100))
    expiry_date = db.Column(db.Date)
    purchase_price = db.Column(db.Float, default=0.0)
    sale_price = db.Column(db.Float, default=0.0)
    tax_rate = db.Column(db.Float, default=0.0)
    current_stock = db.Column(db.Integer, default=0)

    # ⭐ NEW FIELDS FOR REAL GST
    category = db.Column(db.String(50))  # medicine, cosmetic, fmcg, life_saving, ayurvedic, equipment, general
    gst_percent = db.Column(db.Float, default=0)
    cgst_percent = db.Column(db.Float, default=0)
    sgst_percent = db.Column(db.Float, default=0)


# ============================
# CUSTOMERS / PATIENTS
# ============================
class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(50))
    address = db.Column(db.String(300))
    description = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================
# SALES
# ============================
class Sale(db.Model):
    __tablename__ = 'sales'
    id = db.Column(db.Integer, primary_key=True)
    invoice_no = db.Column(db.String(50), unique=True, nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    total = db.Column(db.Float, default=0.0)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))


class SaleItem(db.Model):
    __tablename__ = 'sale_items'

    id = db.Column(db.Integer, primary_key=True)
    sale_id = db.Column(db.Integer, db.ForeignKey('sales.id'), nullable=False)

    # ⭐ FIX: Add proper foreign key
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)

    qty = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)
    discount = db.Column(db.Float, default=0.0)

    # ⭐ FIX: Add relationship so you can access it.product.name
    product = db.relationship("Product")


# ============================
# BILLING
# ============================
class Billing(db.Model):
    __tablename__ = 'billing'
    id = db.Column(db.Integer, primary_key=True)
    bill_no = db.Column(db.String(50), unique=True, nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    total = db.Column(db.Float, default=0.0)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # ⭐ FIX: Cascade delete children when parent is deleted
    items = db.relationship(
        "BillingItem",
        backref="bill",
        cascade="all, delete-orphan",
        passive_deletes=True
    )



class BillingItem(db.Model):
    __tablename__ = 'billing_items'

    id = db.Column(db.Integer, primary_key=True)
    bill_id = db.Column(
        db.Integer,
        db.ForeignKey('billing.id', ondelete="CASCADE"),
        nullable=False
    )

    product_name = db.Column(db.String(100))
    qty = db.Column(db.Integer)
    unit_price = db.Column(db.Float)
    discount = db.Column(db.Float)


# ============================
# APPOINTMENTS
# ============================
class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=True)
    appointment_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), default='Scheduled')
    reason = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================
# DOCTORS
# ============================
class Doctor(db.Model):
    __tablename__ = 'doctors'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    specialization = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    notes = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================
# PRESCRIPTIONS
# ============================
class Prescription(db.Model):
    __tablename__ = 'prescriptions'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    diagnosis = db.Column(db.String(500))
    notes = db.Column(db.String(500))


class PrescriptionItem(db.Model):
    __tablename__ = 'prescription_items'
    id = db.Column(db.Integer, primary_key=True)
    prescription_id = db.Column(db.Integer, db.ForeignKey('prescriptions.id'), nullable=False)
    medicine_name = db.Column(db.String(200), nullable=False)
    dosage = db.Column(db.String(200))
    frequency = db.Column(db.String(200))
    duration = db.Column(db.String(200))


# ============================
# STOCK MOVEMENTS
# ============================
class StockMovement(db.Model):
    __tablename__ = 'stock_movements'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    movement_type = db.Column(db.String(20), nullable=False)  # 'IN' or 'OUT'
    quantity = db.Column(db.Integer, nullable=False)
    reference = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    note = db.Column(db.String(300))

# ============================
# DISTRIBUTORS
# ============================
class Distributor(db.Model):
    __tablename__ = "distributors"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    contact_person = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    address = db.Column(db.String(300))

    gst_number = db.Column(db.String(30))
    drug_license_number = db.Column(db.String(50))
    distributor_code = db.Column(db.String(50))

    payment_terms = db.Column(db.String(100))
    credit_limit = db.Column(db.Float, default=0.0)
    opening_balance = db.Column(db.Float, default=0.0)
    current_balance = db.Column(db.Float, default=0.0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    purchases = db.relationship("Purchase", backref="distributor", lazy=True)


# ============================
# PURCHASE (HEADER)
# ============================
class Purchase(db.Model):
    __tablename__ = "purchases"

    id = db.Column(db.Integer, primary_key=True)
    purchase_no = db.Column(db.String(50), unique=True, nullable=False)

    # This block was previously un-indented, causing the error
    distributor_id = db.Column(
        db.Integer,
        db.ForeignKey("distributors.id"),
        nullable=True
    )

    invoice_no = db.Column(db.String(100))
    invoice_date = db.Column(db.Date)
    purchase_date = db.Column(db.Date, default=date.today)

    subtotal = db.Column(db.Float, default=0.0)
    total_discount = db.Column(db.Float, default=0.0)
    total_cgst = db.Column(db.Float, default=0.0)
    total_sgst = db.Column(db.Float, default=0.0)
    other_charges = db.Column(db.Float, default=0.0)
    round_off = db.Column(db.Float, default=0.0)
    grand_total = db.Column(db.Float, default=0.0)

    payment_status = db.Column(db.String(20), default="Pending")  # Pending / Paid / Partial
    payment_mode = db.Column(db.String(30))  # Cash / UPI / Bank / Credit

    notes = db.Column(db.String(500))

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    items = db.relationship(
        "PurchaseItem",
        backref="purchase",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy=True
    )
class PurchaseItem(db.Model):
    __tablename__ = "purchase_items"

    id = db.Column(db.Integer, primary_key=True)

    purchase_id = db.Column(
        db.Integer,
        db.ForeignKey("purchases.id", ondelete="CASCADE"),
        nullable=False
    )

    product_id = db.Column(
        db.Integer,
        db.ForeignKey("products.id"),
        nullable=False
    )

    # ⭐ ADD THIS RELATIONSHIP
    product = db.relationship("Product", backref="purchase_items", lazy=True)

    hsn_code = db.Column(db.String(20))
    batch_no = db.Column(db.String(100))
    expiry_date = db.Column(db.Date)

    qty = db.Column(db.Integer, nullable=False, default=0)
    free_qty = db.Column(db.Integer, default=0)

    purchase_price = db.Column(db.Float, nullable=False, default=0.0)
    mrp = db.Column(db.Float, default=0.0)
    sale_price = db.Column(db.Float, default=0.0)

    gst_percent = db.Column(db.Float, default=0.0)
    cgst_percent = db.Column(db.Float, default=0.0)
    sgst_percent = db.Column(db.Float, default=0.0)

    cgst_amount = db.Column(db.Float, default=0.0)
    sgst_amount = db.Column(db.Float, default=0.0)

    discount_amount = db.Column(db.Float, default=0.0)
    line_total = db.Column(db.Float, default=0.0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


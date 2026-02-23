from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FloatField, DateField, SelectField
from wtforms.validators import DataRequired, Email, Length, Optional

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ForgotForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send OTP')

class OTPVerifyForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    otp = StringField('OTP', validators=[DataRequired(), Length(6,6)])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Reset Password')

class ProductForm(FlaskForm):
    sku = StringField('SKU', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    brand = StringField('Brand', validators=[Optional()])
    batch_no = StringField('Batch No', validators=[Optional()])
    expiry_date = DateField('Expiry Date', validators=[Optional()])
    purchase_price = FloatField('Purchase Price', validators=[Optional()])
    sale_price = FloatField('Sale Price', validators=[Optional()])
    current_stock = IntegerField('Stock', validators=[Optional()])
    submit = SubmitField('Save')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = SelectField('Role', choices=[('staff','Staff'),('admin','Admin')], default='staff')
    password = PasswordField('Password', validators=[Optional(), Length(min=6)])
    submit = SubmitField('Create')

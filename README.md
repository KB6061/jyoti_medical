# Jyoti Medical Store

Flask-based Medical & Stock Management starter project.

## Features
- Role-based login (admin/staff)
- Forgot password with on-screen OTP (demo)
- SQLite database (jyoti_medical.db)
- Product CRUD, Sales skeleton
- Invoice PDF generation (WeasyPrint)
- Static header & footer with "Developed By Krishna Bhandare"

## Setup
1. Create virtualenv:
   python -m venv venv
   source venv/bin/activate
2. Install:
   pip install -r requirements.txt
3. Run:
   export FLASK_APP=app.py
   flask run

Default admin: username `admin`, password `admin123`

## Notes
- OTP is flashed on screen for demo. Integrate SMTP/SMS for production.
- Customize CSS in `static/css/style.css` to match exact screenshot colors.

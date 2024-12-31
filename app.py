from flask import jsonify, request, session, send_file
from flask import jsonify, request, send_file
from flask import Flask, request, render_template, redirect, url_for, session, flash, send_file, jsonify
from flask_mail import Mail, Message
import os
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from dotenv import load_dotenv
import ssl
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import random
import logging
import time
import requests
import json
import hashlib
import base64
import qrcode
import io
import asyncio
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import pdfkit



load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['TEMPLATES_AUTO_RELOAD'] = True




logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)






# MongoDB credentials
mongo_uri = os.getenv('MONGO_URI')
client = MongoClient(mongo_uri, ssl=True, ssl_cert_reqs=ssl.CERT_NONE,
                     tls=True, tlsAllowInvalidCertificates=True)
db = client['User_Login_Credentials']
otp_collection = db['OTP_Codes']

# Mail server configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.getenv(
    'MAIL_USE_TLS').lower() in ['true', '1', 't']
app.config['MAIL_USE_SSL'] = os.getenv(
    'MAIL_USE_SSL').lower() in ['true', '1', 't']

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def generate_otp():
    return random.randint(100000, 999999)



# def get_submission_status(submission_uid):
#     submission_url = f"{os.getenv('GET_SUBMISSION')}/{submission_uid}"
#     response = requests.get(submission_url, headers=headers)
#     if response.status_code == 200:
#         submission_details = response.json()
#         overall_status = submission_details['overallStatus']
#         long_id = submission_details['documentSummary'][0]['longId']
#         return {'overallStatus': overall_status, 'longId': long_id}
#     return None


def generate_qr_code(data):
    """Generate a QR code image from the provided data and return as a BytesIO object."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')

    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0) 

    return img_buffer


def get_encryption_key():
    secret_key = app.config['SECRET_KEY'].encode()  # Ensure it's in bytes
    # Change this to a fixed, unique value
    salt = b'unique_salt_for_key_derivation'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(secret_key))


encryption_key = get_encryption_key()
cipher_suite = Fernet(encryption_key)


def encrypt_data(data: str) -> str:
    return cipher_suite.encrypt(data.encode()).decode()


def decrypt_data(encrypted_data: str) -> str:
    return cipher_suite.decrypt(encrypted_data.encode()).decode()


# Define the function to get the payment method description
def get_payment_description(payment_code):
    payment_methods = {
        "01": "Cash",
        "02": "Cheque",
        "03": "Bank Transfer",
        "04": "Credit Card",
        "05": "Debit Card",
        "06": "e-Wallet / Digital Wallet",
        "07": "Digital Bank",
        "08": "Others"
    }
    return payment_methods.get(payment_code, "Unknown Payment Method")

# Utility function for safely accessing nested data


def get_nested(data, keys, default=None):
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        elif isinstance(data, list) and isinstance(key, int) and key < len(data):
            data = data[key]
        else:
            return default
    return data if data is not None else default


def authenticate():
    auth_url = os.getenv('AUTH_URL')
    client_id = os.getenv('CLIENT_ID')
    client_secret = os.getenv('CLIENT_SECRET')
    grant_type = os.getenv('GRANT_TYPE')
    scope = os.getenv('SCOPE')

    if not all([auth_url, client_id, client_secret, grant_type, scope]):
        logger.error('One or more environment variables are missing')
        return None

    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': grant_type,
        'scope': scope
    }

    try:
        response = requests.post(auth_url, data=data)
        response.raise_for_status() 
        auth_token = response.json().get('access_token')
        if auth_token:
            logger.info(f'New token generated for user: {auth_token}')
            return auth_token
        else:
            logger.error('Failed to retrieve access token from response')
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f'Failed to authenticate: {e}')
        return None


def ensure_fresh_token():
    if 'auth_token' in session:
        token_time = session.get('token_time')
        if token_time and (datetime.now(timezone.utc) - token_time).total_seconds() > 3598:
            
            new_token = authenticate()
            if new_token:
                session['auth_token'] = new_token
                session['token_time'] = datetime.now(timezone.utc)
    else:
        
        new_token = authenticate()
        if new_token:
            session['auth_token'] = new_token
            session['token_time'] = datetime.now(timezone.utc)


@app.before_request
def before_request():
    if 'email' in session:
        ensure_fresh_token()



@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    user_collection = db[email]
    user = user_collection.find_one({'sup_email': email})

    print(f"Login attempt for email: {email}")  
    print(f"User found: {user}") 

    if user and check_password_hash(user['password'], password):
        session['email'] = email

        
        auth_token = authenticate()
        if auth_token:
            session['auth_token'] = auth_token
            session['token_time'] = datetime.utcnow()

        
        if not all(key in user for key in ['supplier_name', 'sup_msic', 'sup_tin']):
            session['profile_incomplete'] = True
            return redirect(url_for('profile'))
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid email or password', 'danger')
        return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    session.clear()
    if request.method == 'POST':
        supplier_name = request.form.get('supplier_name')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)

        
        user_collection = db[email]
        if user_collection.find_one({'sup_email': email}):
            flash('Email already registered. Please login.', 'danger')
            return redirect(url_for('index'))

        
        user_collection.insert_one(
            {'supplier_name': supplier_name, 'sup_email': email, 'password': hashed_password})

        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    session.clear()
    if request.method == 'POST':
        email = request.form.get('email')
        user_collection = db[email]
        if user_collection.find_one({'sup_email': email}):
            otp = generate_otp()
            expiry_time = datetime.utcnow() + timedelta(minutes=10)
            otp_collection.update_one(
                {'sup_email': email},
                {'$set': {'otp': otp, 'expiry': expiry_time}},
                upsert=True
            )
            msg = Message('Password Reset OTP',
                          sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Your OTP to reset the password is {otp}. It is valid for 10 minutes.'
            mail.send(msg)
            session['reset_email'] = email
            flash('OTP sent to your email.', 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('Email not found!', 'danger')
    return render_template('forgot.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_email' not in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = session['reset_email']
        entered_otp = request.form.get('otp')
        otp_entry = otp_collection.find_one({'sup_email': email})

        if otp_entry and otp_entry['otp'] == int(entered_otp):
            if otp_entry['expiry'] > datetime.utcnow():
                token = s.dumps(email, salt='email-confirm')
                return redirect(url_for('reset_password', token=token))
            else:
                flash('OTP expired. Please request a new one.', 'danger')
                return redirect(url_for('forgot'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('otp.html')


@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    if 'reset_email' not in session:
        return redirect(url_for('index'))

    email = session['reset_email']
    otp = generate_otp()
    expiry_time = datetime.utcnow() + timedelta(minutes=10)
    otp_collection.update_one(
        {'sup_email': email},
        {'$set': {'otp': otp, 'expiry': expiry_time}},
        upsert=True
    )
    msg = Message('Password Reset OTP',
                  sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your OTP to reset the password is {otp}. It is valid for 10 minutes.'
    mail.send(msg)
    flash('New OTP sent to your email.', 'info')
    return redirect(url_for('verify_otp'))


@app.route('/updatePassword/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'

    if request.method == 'POST':
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        user_collection = db[email]
        user_collection.update_one(
            {"sup_email": email}, {"$set": {"password": hashed_password}})
        flash('Your password has been updated!', 'success')
        return redirect(url_for('index'))

    return render_template('updatePassword.html', token=token)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    email = session.get('email')
    if not email:
        flash('You must be logged in to access the profile page.', 'danger')
        return redirect(url_for('index'))

    user_collection = db[email]
    user = user_collection.find_one({'sup_email': email})

    if request.method == 'POST':
        
        profile_data = {
            "supplier_name": request.form.get('supplier_name'),
            "sup_msic": request.form.get('sup_msic'),
            "sup_tin": request.form.get('sup_tin'),
            "sup_reg_no": request.form.get('sup_reg_no'),
            "sup_contact": request.form.get('sup_contact'),
            "sup_tour_reg_no": request.form.get('sup_tour_reg_no'),
            "sup_sst": request.form.get('sup_sst'),
            "sup_addr0": request.form.get('sup_addr0'),
            "sup_addr1": request.form.get('sup_addr1'),
            "sup_addr2": request.form.get('sup_addr2'),
            "sup_city": request.form.get('sup_city'),
            "sup_state": request.form.get('sup_state'),
            "sup_country": request.form.get('sup_country'),
            "sup_postal": request.form.get('sup_postal'),
            "sup_bis_act": request.form.get('sup_bis_act')
        }
        user_collection.update_one({"sup_email": email}, {
                                   "$set": profile_data})
        flash('Your profile has been updated!', 'success')
        
        session.pop('profile_incomplete', None)
        return redirect(url_for('dashboard'))

    if not user:
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('index'))

    return render_template('profile.html', user=user)


@app.route('/contactUs', methods=['GET', 'POST'])
def contact_us():
    if request.method == 'POST':
        email = session.get('email', 'Guest')
        subject = request.form['subject']
        body = request.form['body']

        msg = Message(subject,
                      sender=os.getenv('MAIL_USERNAME'),
                      recipients=['dhiraaj@greenifyzen.com'])
        msg.body = f"Message from {email}:\n\n{body}"
        mail.send(msg)
        flash('Email sent successfully.', 'success')
        return redirect(url_for('contact_us'))

    email = session.get('email', 'Guest')
    return render_template('contactUs.html', email=email)


@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('index'))

    
    if session.get('profile_incomplete'):
        return redirect(url_for('profile'))

    return render_template('dashboard.html')



@app.route('/invoice_redirect', methods=['GET','POST'])
def invoice_redirect():
    email = session.get('email')
    if not email:
            print('Please log in to access the invoice page.')
            flash('Please log in to access the invoice page.', 'error')
            return redirect(url_for('index'))

    
    user_collection = db[email]

        
    supplier_data = user_collection.find_one({"sup_email": email})
    supplier_info = supplier_data if supplier_data else {}
    sup_tin = supplier_info.get('sup_tin', '')
    sup_reg_no = supplier_info.get('sup_reg_no', '')
    return render_template('invoice.html', supplier_info=supplier_info, sup_tin=sup_tin, sup_reg_no=sup_reg_no)


@app.route('/creditNote_redirect', methods=['GET', 'POST']) 
def creditNote_redirect(): 
    email = session.get('email') 
    if not email: 
        flash('Please log in to access the invoice page.', 'error') 
        return redirect(url_for('index')) # Fetch user data from MongoDB 
    user_collection = db[email] 
    supplier_data = user_collection.find_one({"sup_email": email}) 
    supplier_info = supplier_data if supplier_data else {} 
    sup_tin = supplier_info.get('sup_tin', '') 
    sup_reg_no = supplier_info.get('sup_reg_no', '') # Fetch invoices, credit notes, debit notes, and refund notes 
    documents = [] 
    if supplier_data and "invoices" in supplier_data: 
        invoices = supplier_data.get("invoices", {}) 
        for invoice_id, invoice_data in invoices.items(): 
            if isinstance(invoice_data, dict) and "documentSummary" in invoice_data: 
                for doc in invoice_data["documentSummary"]: 
                    documents.append({ "invoice_type": doc.get('typeName', 'Unknown Type'), 
                    "invoice_no": doc.get('internalId', invoice_id), "uuid": doc.get("uuid") }) # Render template with supplier info and document list return 
    return render_template( 'creditNote.html', supplier_info=supplier_info, sup_tin=sup_tin, sup_reg_no=sup_reg_no, documents=documents )





@app.route('/debitNote_redirect', methods=['GET','POST'])
def debitNote_redirect():
    email = session.get('email')
    if not email:
            print('Please log in to access the invoice page.')
            flash('Please log in to access the invoice page.', 'error')
            return redirect(url_for('index'))

    
    user_collection = db[email]

        
    supplier_data = user_collection.find_one({"sup_email": email})
    supplier_info = supplier_data if supplier_data else {}
    sup_tin = supplier_info.get('sup_tin', '')
    sup_reg_no = supplier_info.get('sup_reg_no', '')
    return render_template('debitNote.html', supplier_info=supplier_info, sup_tin=sup_tin, sup_reg_no=sup_reg_no)

@app.route('/refundNote_redirect', methods=['GET','POST'])
def refundNote_redirect():
    email = session.get('email')
    if not email:
            print('Please log in to access the invoice page.')
            flash('Please log in to access the invoice page.', 'error')
            return redirect(url_for('index'))

    
    user_collection = db[email]

        
    supplier_data = user_collection.find_one({"sup_email": email})
    supplier_info = supplier_data if supplier_data else {}
    sup_tin = supplier_info.get('sup_tin', '')
    sup_reg_no = supplier_info.get('sup_reg_no', '')
    return render_template('refundNote.html', supplier_info=supplier_info, sup_tin=sup_tin, sup_reg_no=sup_reg_no)


@app.route('/task_status/<task_id>', methods=['GET'])
def task_status(task_id):
    task = process_invoice.AsyncResult(task_id)
    if task.state == 'PENDING':
        response = {'state': task.state, 'status': 'Pending...'}
    elif task.state != 'FAILURE':
        response = {'state': task.state, 'result': task.result}
    else:
        response = {'state': task.state, 'status': str(task.info)}
    return jsonify(response)


@app.route('/invoice', methods=['GET', 'POST'])
def invoice():
    try:
        
        email = session.get('email')
        if not email:
            print('Please log in to access the invoice page.')
            flash('Please log in to access the invoice page.', 'error')
            return redirect(url_for('index'))

        

        
        user_collection = db[email]

        
        supplier_data = user_collection.find_one({"sup_email": email})
        supplier_info = supplier_data if supplier_data else {}
        sup_tin = supplier_info.get('sup_tin', '')
        sup_reg_no = supplier_info.get('sup_reg_no', '')

        print(f"Supplier Info: TIN={sup_tin}, BRN={sup_reg_no}")

        
        auth_token = session.get('auth_token')
        if not auth_token:
            print('Authentication token is missing or invalid.')
            flash('Authentication token is missing or invalid.', 'error')
            return redirect(url_for('index'))

        
        validation_url = os.getenv('VALIDATION_URL')
        if not validation_url:
            print('Validation URL is not set in the environment variables.')
            flash('Validation URL is not set. Please contact the administrator.', 'error')
            return redirect(url_for('index'))

        
        full_validation_url = f'{validation_url}{sup_tin}?idType=BRN&idValue={sup_reg_no}'
        headers = {'Authorization': f'Bearer {auth_token}'}
        print(f"Making GET request to Validation URL: {full_validation_url}")

        
        response = requests.get(full_validation_url, headers=headers)

        print(f"Validation URL: {full_validation_url}")
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.content}")

        if response.status_code != 200:
            print('Error validating supplier information.')
            flash('Error validating supplier information.', 'error')
            return render_template('invoice.html', supplier_info=supplier_info, sup_tin=sup_tin, sup_reg_no=sup_reg_no, error="Validation failed")

        if request.method == 'POST':
            print("Form submission detected.")
            required_fields = [
                "supplier_name", "sup_sst", 'sup_tin', "sup_contact", 'sup_reg_no', "sup_email",
                "tax_type", "bill_start_date", "bill_end_date", 'invoice_code',
                "invoice_currency",  "buy_contact",
                "buy_country", "buy_state", "buy_city", "buy_postal", "buy_addr2", "buy_addr1",
                "buy_addr0", "buy_email", "buy_reg_no", "buy_tin", "buyer_name",
                "sup_bis_act", "sup_country", "sup_state", "sup_msic", "sup_city", "sup_postal",
                "sup_addr1", "sup_addr2", "sup_tour_reg_no", "sup_addr0", "issueDate", "issueTime"
            ]

            
            missing_fields = [
                field for field in required_fields if not request.form.get(field)]
            if missing_fields:
                for field in missing_fields:
                    flash(f'{field} is required.', 'error')
                print(f"Missing required fields: {missing_fields}")
                return render_template('invoice.html', supplier_info=supplier_data)

            print("All required fields are present.")

            details_of_tax_exemp = request.form.get("details_of_tax_exemp")
            invoice_code = request.form.get("invoice_code")
            
            issue_date = request.form.get('issueDate')
            
            issue_time = request.form.get('issueTime')

            pay_date = request.form.get('pay_date')

            pay_time = request.form.get('pay_time')

            InvoiceTypeCode = "01"

            session['invoice_code'] = invoice_code


            #information fetched here below for showcasing them in preview invoice
            invoice_code = request.form.get("invoice_code")

            issue_date = request.form.get('issueDate')

            invoice_currency = request.form.get('invoice_currency')

            supplier_name = request.form.get('supplier_name')

            supplier_tin = request.form.get('sup_tin')

            supplier_brn = request.form.get('sup_reg_no')

            supplier_addr1 = request.form.get('sup_addr1')

            supplier_addr2 = request.form.get('sup_addr2')

            supplier_postal = request.form.get('sup_postal')

            supplier_city = request.form.get('sup_city')

            supplier_state = request.form.get('sup_state')

            supplier_country = request.form.get('sup_country')

            supplier_contact = request.form.get('sup_contact')

            buyer_name = request.form.get('buyer_name')

            buyer_tin = request.form.get('buy_tin')

            buyer_brn = request.form.get('buy_reg_no')

            buyer_addr1 = request.form.get('buy_addr1')

            buyer_addr2 = request.form.get('buy_addr2')

            buyer_postal = request.form.get('buy_postal')

            buyer_city = request.form.get('buy_city')

            buyer_state = request.form.get('buy_state')

            buyer_country = request.form.get('buy_country')

            buyer_contact = request.form.get('buy_contact')



            if issue_date and issue_time:
                #required 'Z' format
                formatted_time = issue_time + 'Z'

            if pay_date and pay_time:
                #required 'Z' format
                formatted_pay_time = pay_time + 'Z'
            print(f"Invoice Code: {invoice_code}")

            # Initialize the invoice data structure
            invoice_data = {
                "_D": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
                "_A": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                "_B": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                "Invoice": [{
                    "AccountingSupplierParty": [{
                        "AdditionalAccountID": [{"_": request.form.get("exp_auth_no"), "schemeAgencyName": "CertEx"}],
                        "Party": [{
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'sup_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_reg_no'), "schemeID": "BRN"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_sst'), "schemeID": "SST"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_tour_reg_no'), "schemeID": "TTX"}]}
                            ],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('sup_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('sup_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('sup_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('sup_postal')}],
                                "CityName": [{"_": request.form.get('sup_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('sup_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('sup_country')}]
                                }]
                            }],
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("supplier_name")}]
                            }],
                            "Contact": [{
                                "ElectronicMail": [{"_": request.form.get('sup_email')}],
                                "Telephone": [{"_": request.form.get('sup_contact')}]
                            }],
                            "IndustryClassificationCode": [
                                # Ensure only one item as per schema
                                {"_": request.form.get("sup_msic")}
                            ]
                        }]
                    }],
                    "AccountingCustomerParty": [{
                        "Party": [{
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'buy_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'buy_reg_no'), "schemeID": "BRN"}]},
                                {"ID": [{"_": request.form.get(
                                    'buy_sst'), "schemeID": "SST"}]}
                            ],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('buy_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('buy_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('buy_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('buy_postal')}],
                                "CityName": [{"_": request.form.get('buy_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('buy_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('buy_country')}]
                                }]
                            }],
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("buyer_name")}]
                            }],
                            "Contact": [{
                                "ElectronicMail": [{"_": request.form.get('buy_email')}],
                                "Telephone": [{"_": request.form.get('buy_contact')}]
                            }]
                        }]
                    }],
                    "InvoiceTypeCode": [{"_": "01", "listVersionID": "1.0"}],
                    "ID": [{"_": invoice_code}],
                    "IssueDate": [{"_": issue_date}],
                    "IssueTime": [{"_": formatted_time}],
                    "DocumentCurrencyCode": [{"_": request.form.get("invoice_currency")}],
                    "TaxExchangeRate": [{
                        "CalculationRate": [{"_": float(request.form.get("currency_rate", 0))}],
                        "SourceCurrencyCode": [{"_": request.form.get("invoice_currency")}],
                        "TargetCurrencyCode": [{"_": "MYR"}]
                    }],
                    "InvoicePeriod": [{
                        "Description": [{"_": request.form.get("freq_billing")}],
                        "StartDate": [{"_": request.form.get("bill_start_date")}],
                        "EndDate": [{"_": request.form.get("bill_end_date")}]
                    }],
                    "BillingReference": [{
                        "AdditionalDocumentReference": [{
                            "ID": [{"_": request.form.get("invoice_ref")}]
                        }]
                    }],
                    "Delivery": [{
                        "DeliveryParty": [{
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("shipping_res_name")}]
                            }],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('shipping_res_postal')}],
                                "CityName": [{"_": request.form.get('shipping_res_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('shipping_res_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('shipping_res_country')}]
                                }]
                            }],
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'shipping_res_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'shipping_res_id'), "schemeID": "BRN"}]}
                            ]
                        }],
                        "Shipment": [{
                            "ID": [{"_": invoice_code}],
                            "FreightAllowanceCharge": [{
                                "ChargeIndicator": [{"_": True}],
                                "Amount": [{
                                    "_": float(request.form.get('other_charges_amount', '0') or '0'),
                                    "currencyID": "MYR"
                                }]
                            }]
                        }]
                    }],
                    "PaymentMeans": [
                        {
                        "PaymentMeansCode": [
                            {
                            "_": request.form.get('Payment_mode')
                            }
                        ],
                        "PayeeFinancialAccount": [
                            {
                            "ID": [
                                {
                                "_": request.form.get('sup_bank_acc_no')
                                }
                            ]
                            }
                        ]
                        }
                    ],
                    "PaymentTerms": [
                        {
                        "Note": [
                            {
                            "_": request.form.get('pay_terms')
                            }
                        ]
                        }
                    ],
                    "PrepaidPayment": [
                        {
                        "ID": [
                            {
                            "_": request.form.get('pay_ref_no')
                            }
                        ],
                        "PaidAmount": [
                            {
                            "_": float(request.form.get('pay_amt')),
                            "currencyID": "MYR"
                            }
                        ],
                        "PaidDate": [
                            {
                            "_": pay_date
                            }
                        ],
                        "PaidTime": [
                            {
                            "_": formatted_pay_time
                            }
                        ]
                        }
                    ],
                    "AdditionalDocumentReference": [
                        {
                            "ID": [{"_": request.form.get("ref_no_custom_form")}],
                            "DocumentType": [{"_": "CustomsImportForm"}]
                        },
                        {
                            "DocumentDescription": [{"_": request.form.get("fta")}],
                            "DocumentType": [{"_": "FreeTradeAgreement"}],
                            "ID": [{"_": "FTA"}]
                        },
                        {
                            "ID": [{"_": request.form.get("ref_no_custom_form2")}],
                            "DocumentType": [{"_": "K2"}]
                        },
                        {
                            "ID": [{"_": request.form.get("incoterms")}]
                        }
                    ],
                    "TaxTotal": [{
                        "TaxAmount": [{
                            "_": float(request.form.get("tax_total_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxSubtotal": [{
                            "TaxableAmount": [{
                                "_": float(request.form.get("tax_subtotal_taxable_amount", 0)),
                                "currencyID": "MYR"
                            }],
                            "TaxAmount": [{
                                "_": float(request.form.get("tax_total_amount", 0)),
                                "currencyID": "MYR"
                            }],
                            "TaxCategory": [{
                                "ID": [{"_": request.form.get("tax_type")}],
                                "TaxExemptionReason": [{"_": request.form.get("details_of_tax_exemp")}],
                                "TaxScheme": [{
                                    "ID": [{"_": "OTH", "schemeID": "UN/ECE 5153", "schemeAgencyID": "6"}]
                                }]
                            }]
                        }]
                    }],
                    "LegalMonetaryTotal": [{
                        "LineExtensionAmount": [{
                            "_": float(request.form.get("legal_line_extension_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxExclusiveAmount": [{
                            "_": float(request.form.get("legal_line_extension_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxInclusiveAmount": [{
                            "_": float(request.form.get("legal_payable_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "PayableAmount": [{
                            "_": float(request.form.get("legal_payable_amount", 0)),
                            "currencyID": "MYR"
                        }]
                    }]
                    
                }]
            }

            print("Invoice data structure initialized.")

            row_index = 0


            products = []
            while request.form.get(f"classification_{row_index}"):
                classification = request.form.get(f"classification_{row_index}")
                description = request.form.get(f"description_{row_index}")
                unit_price = request.form.get(f"unit_price_{row_index}")
                tax_amt = request.form.get(f"tax_amt_{row_index}")
                tax_type = request.form.get("tax_type")
                qty = request.form.get(f"qyt_{row_index}")
                measurement = request.form.get(f"measurement_{row_index}")
                tax_rate = request.form.get(f"tax_rate_{row_index}")
                total_ex = request.form.get(f"total_ex_{row_index}")
                subtotal = request.form.get(f"subtotal_{row_index}")
                disc_rate = request.form.get(f"disc_rate_{row_index}")
                disc_amount = request.form.get(f"disc_amount_{row_index}")
                other_charges = request.form.get("other_charges")

                product_data = {
                    "InvoiceLine": [{
                        "ID": [{"_": f"{row_index + 1}"}],
                        "Item": [  
                            {
                                "CommodityClassification": [
                                    {
                                        "ItemClassificationCode": [
                                            {
                                                "_": classification,
                                                "listID": "CLASS"
                                            }
                                        ]
                                    }
                                ],
                                "Description": [
                                    {
                                        "_": description
                                    }
                                ]
                            }
                        ],
                        "Price": [  
                            {
                                "PriceAmount": [
                                    {
                                        "_": float(unit_price),
                                        "currencyID": "MYR"
                                    }
                                ]
                            }
                        ],
                        "TaxTotal": [
                            {
                                "TaxAmount": [
                                    {
                                        "_": float(tax_amt),
                                        "currencyID": "MYR"
                                    }
                                ],
                                "TaxSubtotal": [
                                    {
                                        "TaxableAmount": [
                                            {
                                                "_": float(total_ex),
                                                "currencyID": "MYR"
                                            }
                                        ],
                                        "TaxAmount": [
                                            {
                                                "_": float(tax_amt),
                                                "currencyID": "MYR"
                                            }
                                        ],
                                        "TaxCategory": [
                                            {
                                                "ID": [
                                                    {
                                                        "_": tax_type
                                                    }
                                                ],
                                                "TaxExemptionReason": [
                                                    {
                                                        "_": request.form.get("details_of_tax_exemp")
                                                    }
                                                ],
                                                "TaxScheme": [
                                                    {
                                                        "ID": [
                                                            {
                                                                "_": "OTH",
                                                                "schemeID": "UN/ECE 5153",
                                                                "schemeAgencyID": "6"
                                                            }
                                                        ]
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "ItemPriceExtension": [  
                            {
                                "Amount": [
                                    {
                                        "_": float(subtotal),
                                        "currencyID": "MYR"
                                    }
                                ]
                            }
                        ],
                        "LineExtensionAmount": [
                            {
                                "_": float(total_ex),
                                "currencyID": "MYR"
                            }
                        ],
                        "InvoicedQuantity": [
                            {
                                "_": float(qty),
                                "unitCode": measurement
                            }
                        ],
                        "AllowanceCharge": [
                            {
                                "ChargeIndicator": [
                                    {
                                        "_": True
                                    }
                                ],
                                "MultiplierFactorNumeric": [
                                    {
                                        "_": float(disc_rate)
                                    }
                                ],
                                "Amount": [
                                    {
                                        "_": float(disc_amount),
                                        "currencyID": "MYR"
                                    }
                                ],
                                "AllowanceChargeReason": [
                                    {
                                        "_": other_charges
                                    }
                                ]
                            }
                        ]
                    }]
                }

                products.append(product_data)
                print(f"Added product {row_index}: {json.dumps(product_data, indent=4)}")
                row_index += 1

                print(f"Total products added: {len(products)}")

                
                invoice_data["Invoice"][0]["InvoiceLine"] = [
                    product["InvoiceLine"][0] for product in products
                ]

                print("Invoice data before cleaning:", json.dumps(invoice_data, indent=4))

                # Remove null fields from invoice data
                for key in list(invoice_data.keys()):
                    if isinstance(invoice_data[key], dict):
                        for subkey in list(invoice_data[key].keys()):
                            if not invoice_data[key][subkey]:  
                                print(f"Removing empty field: {subkey} from {key}")
                                del invoice_data[key][subkey]
                    elif isinstance(invoice_data[key], list):
                        for item in invoice_data[key]:
                            for subkey in list(item.keys()):
                                if not item[subkey]: 
                                    print(f"Removing empty field: {subkey} from list item")
                                    del item[subkey]

                print("Invoice data after cleaning:", json.dumps(invoice_data, indent=4))

                
                invoice_json_str = json.dumps(invoice_data)
                invoice_json_str = json.dumps(invoice_data)
        sha256_hash = hashlib.sha256(
            invoice_json_str.encode('utf-8')).hexdigest()

        base64_encoded = base64.b64encode(
            invoice_json_str.encode('utf-8')).decode('utf-8')

        payload = {
            "documents": [
                {
                    "format": "JSON",
                    "documentHash": sha256_hash,
                    "codeNumber": invoice_code,
                    "document": base64_encoded
                }
            ]
        }

        session['invoice_code'] = invoice_code
        json_filename = f'invoice_data_{invoice_code}.json'
        json_file_path = os.path.join(os.getcwd(), json_filename)
        with open(json_file_path, 'w') as json_file:
            json.dump(invoice_data, json_file, indent=4)
        print(f'Saved invoice data to {json_file_path}')

        api_url = os.getenv('SUBMIT_DOC_URL')
        if not api_url:
            print('API URL is not set in the environment variables.')
            flash('API URL is not set. Please contact the administrator.', 'error')
            return redirect(url_for('invoice'))

        headers = {
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json'
        }

        response = requests.post(
            api_url, headers=headers, data=json.dumps(payload))
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")

        if response.status_code == 202:
            submission_data = response.json()
            submission_uid = submission_data['submissionUid']
            document_uuid = submission_data['acceptedDocuments'][0]['uuid']

            if submission_uid and document_uuid:

                invoice_document = {
                    "payload": payload,
                    "submissionUid": submission_uid,
                    "documentUUID": document_uuid,
                    "sha256_hash": sha256_hash,
                    "base64_encoded": base64_encoded
                }

                user_collection = db[email]
                result = user_collection.update_one(
                    {"sup_email": email},
                    {"$set": {f"invoices.{invoice_code}": invoice_document}},
                    upsert=True
                )
                return jsonify(invoice_document)

                if result.modified_count > 0 or result.upserted_id:
                    print(
                        f"Invoice data saved in MongoDB under invoice code {invoice_code} for user {email}")
                    flash(
                        'Invoice submitted successfully and saved in MongoDB.', 'success')
                else:
                    flash('Invoice submission failed to save in MongoDB.', 'error')
            else:
                flash(
                    'Invoice submission failed due to missing submission UID or document UUID.', 'error')
        else:
            flash(
                f'Failed to submit invoice. Status code: {response.status_code}', 'error')

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        flash('An unexpected error occurred. Please try again later.', 'error')

    return redirect(url_for('get_submission', invoice_code=invoice_code, submission_uid = submission_uid, document_uuid = document_uuid))


@app.route('/get_submission', methods=['GET'])
def get_submission():
    email = session.get('email')
    auth_token = session.get('auth_token')
    submission_uid = request.args.get('submissionUid')
    document_uuid = request.args.get('documentUUID')

    if not email:
        return jsonify({'error': 'User email not found in session'}), 400

    user_collection = db[email]
    user_document = user_collection.find_one({"sup_email": email})

    if user_document is None:
        return jsonify({'error': 'User not found'}), 404

    if submission_uid and document_uuid:
        # Ensure invoice_code is defined outside the loop
        invoice_code = None

        # Safeguard against malformed invoices data
        invoices = user_document.get('invoices', {})
        if not isinstance(invoices, dict):
            return jsonify({'error': 'Invoices data is not in the expected format'}), 500

        for invoice_key, invoice_data in invoices.items():
            if isinstance(invoice_data, dict):
                if invoice_data.get('submissionUid') == submission_uid and \
                   invoice_data.get('payload', {}).get('documents', [{}])[0].get('codeNumber'):
                    invoice_code = invoice_data['payload']['documents'][0]['codeNumber']
                    break

        if not invoice_code:
            return jsonify({'error': 'Invoice code not found for the given parameters.'}), 404

        submission_url = f"{os.getenv('GET_SUBMISSION')}/{submission_uid}"
        headers = {
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json'
        }

        # Retry logic for pending status
        submission_details = None
        for attempt in range(5):
            response = requests.get(submission_url, headers=headers)

            if response.status_code == 200:
                submission_details = response.json()
                try:
                    status = submission_details['documentSummary'][0]['status']
                    long_id = submission_details['documentSummary'][0]['longId']

                    # If status is "Valid" or "Invalid", update MongoDB and exit the loop
                    if status in ["Valid", "Invalid"]:
                        break

                except (KeyError, IndexError) as e:
                    return jsonify({'error': f'Unexpected response format: {e}'}), 500

            else:
                return jsonify({'error': 'Failed to retrieve submission status'}), response.status_code

            # Wait 20 seconds before retrying
            time.sleep(20)

        if not submission_details:
            return jsonify({'error': 'Submission details could not be retrieved.'}), 500

        # Update MongoDB with submission details
        user_collection.update_one(
            {"sup_email": email},
            {"$set": {
                f'invoices.{invoice_code}': submission_details
            }}
        )

        if status in ["Valid", "Invalid"]:
            # Construct QR link
            qr_link = f"https://preprod.myinvois.hasil.gov.my/{document_uuid}/share/{long_id}"
            print(f"QR Link: {qr_link}")

            # Generate QR code from the link
            qr_code_img = generate_qr_code(qr_link)
            print("QR code image generated successfully.")

            # Return the QR code image as a download
            return send_file(qr_code_img, mimetype='image/png', as_attachment=True, download_name='qr_code.png')

        # If still pending after retries
        return jsonify({'error': 'Submission status is still pending after retries.'}), 500

    return jsonify({'error': 'Missing parameters.'}), 400


@app.route('/get_documents', methods=['GET'])
def get_documents():
    user_email = session.get('email')  # Retrieve email from session
    auth_token = session.get('auth_token')  # Retrieve auth token from session

    if not user_email or not auth_token:
        return jsonify({"error": "User not logged in or invalid session"}), 401

    # Assuming `db[user_email]` points to the correct collection
    user_collection = db[user_email]
    user_data = user_collection.find_one({"sup_email": user_email})
    if not user_data:
        return render_template('get_documents.html', email=user_email, documents=[])

    # Parse the invoices and update them
    documents = []
    invoices = user_data.get("invoices", {})

    for invoice_id, invoice_data in invoices.items():
        if isinstance(invoice_data, dict):
            submission_uid = invoice_data.get("submissionUid")
            if not submission_uid:
                continue  # Skip if submissionUid is not present

            # Trigger the GET_SUBMISSION API to fetch updated data
            submission_url = f"{os.getenv('GET_SUBMISSION')}/{submission_uid}"
            headers = {
                'Authorization': f'Bearer {auth_token}',
                'Content-Type': 'application/json'
            }

            try:
                response = requests.get(submission_url, headers=headers)
                if response.status_code == 200:
                    submission_details = response.json()

                    # Update MongoDB with the new submission details
                    user_collection.update_one(
                        {"sup_email": user_email,
                            f"invoices.{invoice_id}": {"$exists": True}},
                        {"$set": {
                            f"invoices.{invoice_id}": submission_details
                        }}
                    )

                    # Extract the document summary and parse status
                    updated_document_summary = submission_details.get(
                        'documentSummary', [])
                    for doc in updated_document_summary:
                        documents.append({
                            "document_code": doc.get("internalId"),
                            "category": doc.get("typeName"),
                            # Status from documentSummary
                            "status": doc.get("status", "Pending"),
                            "validation_time": doc.get("dateTimeValidated", "N/A"),
                            "uuid": doc.get("uuid"),
                            "submissionUid": submission_details.get("submissionUid"),
                            "invoiceId": invoice_id
                        })

            except Exception as e:
                print(f"Error fetching submission for {submission_uid}: {e}")
                continue

    return render_template('get_documents.html', email=user_email, documents=documents)






@app.route('/get_doc_info', methods=['GET'])
def get_doc_info():
    uuid = request.args.get('uuid')
    user_email = session.get('email')  # Retrieve email from session
    auth_token = session.get('auth_token')  # Retrieve auth token from session

    if not user_email:
        return jsonify({"error": "User not logged in"}), 401

    if not auth_token:
        return jsonify({"error": "Auth token not found"}), 401

    # Assuming `db[user_email]` points to the correct collection
    user_collection = db[user_email]
    user_data = user_collection.find_one({"sup_email": user_email})
    if not user_data:
        return jsonify({"error": "User data not found in MongoDB"}), 404

    # Parse the invoices to find the document with the given UUID
    documents = []
    invoices = user_data.get("invoices", {})
    for invoice_id, invoice_data in invoices.items():
        if isinstance(invoice_data, dict):
            for doc in invoice_data.get("documentSummary", []):
                if doc.get("uuid") == uuid:
                    documents.append({
                        "document_code": doc.get("internalId"),
                        "category": doc.get("typeName"),
                        "status": doc.get("status", "Pending"),
                        "validation_time": doc.get("dateTimeValidated", "N/A"),
                        "uuid": doc.get("uuid"),
                        "submissionUid": invoice_data.get("submissionUid"),
                        "longID": doc.get("longId")
                    })

    if not documents:
        return jsonify({"error": "Document not found in MongoDB"}), 404

    document_summary = documents[0]

    # Construct the QR link
    qr_link = f"https://preprod.myinvois.hasil.gov.my/{document_summary['uuid']}/share/{document_summary['longID']}"

    # API call to fetch detailed document info
    api_url = f"{os.getenv('GET_DOC_INFO')}/{document_summary['uuid']}/raw"
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = requests.get(api_url, headers=headers)
    


    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch data from API"}), 500

    data = response.json()


    print("Full API Response: ", data)  # Debugging: Inspect the full API response

    if not data:
        return jsonify({"error": "No document data found in API response"}), 500

    # Parse the `document` field (it's a stringified JSON)
    status = data.get("status", "Unknown")
    document_json_str = data.get('document')
    if not document_json_str:
        return jsonify({"error": "No document content found"}), 500

    # Load the stringified JSON into a dictionary
    document = json.loads(document_json_str)

    # Access the `Invoice` field
    invoice_data = document.get("Invoice", [])
    if not invoice_data:
        return jsonify({"error": "No invoice data found in response"}), 500

    category = doc.get("typeName", "invoice").lower()
    print(category)

    # Extract supplier information
    supplier_party = invoice_data[0].get("AccountingSupplierParty", [{}])[
        0].get("Party", [{}])[0]
    supplier_info = {
        "name": supplier_party.get("PartyLegalEntity", [{}])[0].get("RegistrationName", [{}])[0].get("_", "Unknown"),
        "tin": supplier_party.get("PartyIdentification", [{}])[0].get("ID", [{}])[0].get("_", "Unknown"),
        "brn": supplier_party.get("PartyIdentification", [{}])[1].get("ID", [{}])[0].get("_", "Unknown"),
        "address": [
            line.get("Line", [{}])[0].get("_", "Unknown")
            for line in supplier_party.get("PostalAddress", [{}])[0].get("AddressLine", [])
        ],
        "city": supplier_party.get("PostalAddress", [{}])[0].get("CityName", [{}])[0].get("_", "Unknown"),
        "state": supplier_party.get("PostalAddress", [{}])[0].get("CountrySubentityCode", [{}])[0].get("_", "Unknown"),
        "country": supplier_party.get("PostalAddress", [{}])[0].get("Country", [{}])[0].get("IdentificationCode", [{}])[0].get("_", "Unknown"),
        "postalcode": supplier_party.get("PostalAddress", [{}])[0].get("PostalZone", [{}])[0].get("_", "Unknown"),
        "telephone": supplier_party.get("Contact", [{}])[0].get("Telephone", [{}])[0].get("_", "Unknown"),
        "msic_code" : invoice_data[0].get("AccountingSupplierParty", [{}])[
            0].get("Party", [{}])[0].get("IndustryClassificationCode", [{}])[0].get("_", "Unknown")

    }

    # Extract buyer information
    buyer_party = invoice_data[0].get("AccountingCustomerParty", [{}])[
        0].get("Party", [{}])[0]
    buyer_info = {
        "name": buyer_party.get("PartyLegalEntity", [{}])[0].get("RegistrationName", [{}])[0].get("_", "Unknown"),
        "tin": buyer_party.get("PartyIdentification", [{}])[0].get("ID", [{}])[0].get("_", "Unknown"),
        "brn": buyer_party.get("PartyIdentification", [{}])[1].get("ID", [{}])[0].get("_", "Unknown"),
        "address": [
            line.get("Line", [{}])[0].get("_", "Unknown")
            for line in buyer_party.get("PostalAddress", [{}])[0].get("AddressLine", [])
        ],
        "city": buyer_party.get("PostalAddress", [{}])[0].get("CityName", [{}])[0].get("_", "Unknown"),
        "state": buyer_party.get("PostalAddress", [{}])[0].get("CountrySubentityCode", [{}])[0].get("_", "Unknown"),
        "country": buyer_party.get("PostalAddress", [{}])[0].get("Country", [{}])[0].get("IdentificationCode", [{}])[0].get("_", "Unknown"),
        "postalcode": buyer_party.get("PostalAddress", [{}])[0].get("PostalZone", [{}])[0].get("_", "Unknown"),
        "telephone": buyer_party.get("Contact", [{}])[0].get("Telephone", [{}])[0].get("_", "Unknown"),
    }

    # Extract invoice details
    invoice_info = {
        "invoice_code": invoice_data[0].get("ID", [{}])[0].get("_", "Unknown"),
        "issue_date": invoice_data[0].get("IssueDate", [{}])[0].get("_", "Unknown"),
        "issue_time": invoice_data[0].get("IssueTime", [{}])[0].get("_", "Unknown"),
        "billing_start_date": invoice_data[0].get("InvoicePeriod", [{}])[0].get("StartDate", [{}])[0].get("_", "Unknown"),
        "billing_end_date": invoice_data[0].get("InvoicePeriod", [{}])[0].get("EndDate", [{}])[0].get("_", "Unknown"),
        "currency_code": invoice_data[0].get("DocumentCurrencyCode", [{}])[0].get("_", "Unknown"),
        "total_excluding_tax": invoice_data[0].get("LegalMonetaryTotal", [{}])[0].get("TaxExclusiveAmount", [{}])[0].get("_", 0.0), 
        "total_including_tax": invoice_data[0].get("LegalMonetaryTotal", [{}])[0].get("TaxInclusiveAmount", [{}])[0].get("_", 0.0)
    }

    invoice_details = {
        "product_lines": [],
        "subtotal": 0.0,
        "total_excluding_tax": 0.0,
        "tax_amount": 0.0,
        "total_including_tax": 0.0,
        "total_payable_amount": 0.0,
    }

    # Extract product lines
    product_lines = []


    for line in invoice_data[0].get("InvoiceLine", []):
        # Extract values
        unit_price = line.get("Price", [{}])[0].get(
            "PriceAmount", [{}])[0].get("_", "Unknown")
        quantity = line.get("InvoicedQuantity", [{}])[0].get("_", "Unknown")
        discount = line.get("AllowanceCharge", [{}])[
            0].get("Amount", [{}])[0].get("_", 0.0)
        tax_rate = line.get("TaxTotal", [{}])[0].get("TaxSubtotal", [{}])[0].get(
            "TaxCategory", [{}])[0].get("ID", [{}])[0].get("_", "Unknown")
        tax_amount = line.get("TaxTotal", [{}])[0].get(
            "TaxAmount", [{}])[0].get("_", 0.0)
        total_excl_tax = line.get("LineExtensionAmount", [{}])[
            0].get("_", "Unknown")
        total_incl_tax = float(total_excl_tax) + float(
            tax_amount) if total_excl_tax != "Unknown" and tax_amount != "Unknown" else "Unknown"

        # Append product line
        product_lines.append({
            "classification_code": line.get("Item", [{}])[0].get("CommodityClassification", [{}])[0].get("ItemClassificationCode", [{}])[0].get("_", "Unknown"),
            "description": line.get("Item", [{}])[0].get("Description", [{}])[0].get("_", "Unknown"),
            "unit_price": unit_price,
            "quantity": quantity,
            "discount": discount,
            "tax_rate": tax_rate,
            "tax_amount": tax_amount,
            "total_excl_tax": total_excl_tax,
            "total_incl_tax": total_incl_tax,
        })

        # Update subtotals and totals
        invoice_details["subtotal"] += float(unit_price) * float(
            quantity) if unit_price != "Unknown" and quantity != "Unknown" else 0.0
        invoice_details["tax_amount"] += float(
            tax_amount) if tax_amount != "Unknown" else 0.0
        invoice_details["total_excluding_tax"] += float(
            total_excl_tax) if total_excl_tax != "Unknown" else 0.0
        invoice_details["total_including_tax"] += float(
            total_incl_tax) if total_incl_tax != "Unknown" else 0.0

    # Map total payable amount
    invoice_details["total_payable_amount"] = invoice_data[0].get(
        "LegalMonetaryTotal", [{}])[0].get("PayableAmount", [{}])[0].get("_", "Unknown")

    # Add product lines to the invoice details
    invoice_details["product_lines"] = product_lines

    # Output final invoice details
    print(invoice_details)


    payment_info = {}
    payment_means = invoice_data[0].get("PaymentMeans", [{}])
    if payment_means:
        payment_info = {
            "payment_means_code": get_payment_description(invoice_data[0].get("PaymentMeans", [{}])[0].get("PaymentMeansCode", [{}])[0].get("_", "Unknown")),
            "payee_account_id": invoice_data[0].get("PaymentMeans", [{}])[0].get("PayeeFinancialAccount", [{}])[0].get("ID", [{}])[0].get("_", "Unknown"),
            "payment_terms": invoice_data[0].get("PaymentTerms", [{}])[0].get("Note", [{}])[0].get("_", "Unknown"),
            "prepaid_payment_id": invoice_data[0].get("PrepaidPayment", [{}])[0].get("ID", [{}])[0].get("_", "Unknown"),
            "prepaid_amount": invoice_data[0].get("PrepaidPayment", [{}])[0].get("PaidAmount", [{}])[0].get("_", "Unknown"),
            "prepaid_currency": invoice_data[0].get("PrepaidPayment", [{}])[0].get("PaidAmount", [{}])[0].get("currencyID", "Unknown"),
            "prepaid_date": invoice_data[0].get("PrepaidPayment", [{}])[0].get("PaidDate", [{}])[0].get("_", "Unknown"),
            "prepaid_time": invoice_data[0].get("PrepaidPayment", [{}])[0].get("PaidTime", [{}])[0].get("_", "Unknown"),
        }

    # Extract shipping (delivery) information
    shipping_info = {}
    delivery_info = invoice_data[0].get("Delivery", [{}])
    if delivery_info:
        delivery_party = delivery_info[0].get("DeliveryParty", [{}])[0].get("PartyLegalEntity", [{}])[0]
        shipping_info = {
            "delivery_name": delivery_party.get("RegistrationName", [{}])[0].get("_", "Unknown"),
            "delivery_address": [
                line.get("Line", [{}])[0].get("_", "Unknown")
                for line in delivery_info[0].get("PostalAddress", [{}])[0].get("AddressLine", [])
            ],
            "delivery_city": delivery_info[0].get("CityName", [{}])[0].get("_", "Unknown"),
            "delivery_state": delivery_info[0].get("CountrySubentityCode", [{}])[0].get("_", "Unknown"),
            "delivery_country": delivery_info[0].get("Country", [{}])[0].get("IdentificationCode", [{}])[0].get("_", "Unknown"),
            "delivery_postalcode": delivery_info[0].get("PostalZone", [{}])[0].get("_", "Unknown"),
        }
    

    # Combine the extracted information
    combined_info = {
        "supplier_info": supplier_info,
        "buyer_info": buyer_info,
        "invoice_info": invoice_info,
        "product_lines": product_lines,
        "payment_info": payment_info,
        "shipping_info": shipping_info,
        "uuid": document_summary["uuid"],
        "submissionUid": document_summary["submissionUid"],
        "qr_link": qr_link,  # Send the QR link to the frontend
        "status": status
    }
    session['combined_info'] = combined_info  # Store in session


    # Debugging: Print the combined info
    print("Extracted Information: ", combined_info)
    template_mapping = {
        "invoice": "invoice_preview1.html",
        "credit note": "creditNote_preview1.html",
        "debit note": "debitNote_preview1.html",
        "refund note": "refundNote_preview1.html"
    }

    selected_template = template_mapping.get(category, "invoice_preview1.html")

    return render_template(selected_template, combined_info=combined_info, invoice_details=invoice_details)

@app.route('/update_document_status/<uuid>/cancel', methods=['POST'])
def update_document_status(uuid):
    user_email = session.get('email')
    auth_token = session.get('auth_token')

    cancel_reject_url = os.getenv('CANCEL_REJECT_URL')
    get_submission_url = os.getenv('GET_SUBMISSION')

    if not user_email or not auth_token:
        return jsonify({"error": "Unauthorized access"}), 401

    # Define the cancel API endpoint
    api_url = f"{cancel_reject_url}/{uuid}/state"
    request_data = request.get_json()
    reason = request_data.get('reason')

    payload = {"status": "cancelled", "reason": reason}

    # Make the cancel API call
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = requests.put(api_url, json=payload, headers=headers)

    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        print(f"Response Text: {response.text}")
        return jsonify({"error": "Failed to cancel document"}), response.status_code

    # Extract submission UID and invoice ID from the request data
    submission_uid = request_data.get('submissionUid')
    invoice_id = request_data.get('invoiceId')

    if not submission_uid or not invoice_id:
        return jsonify({"error": "Missing submission UID or invoice ID"}), 400

    # Fetch updated submission details
    submission_url = f"{get_submission_url}/{uuid}"
    response = requests.get(submission_url, headers=headers)

    if response.status_code == 200:
        submission_details = response.json()

        # Update MongoDB with the new submission details and the status update
        user_collection = db[user_email]
        user_collection.update_one(
            {"sup_email": user_email, f"invoices.{invoice_id}": {"$exists": True}},
            {
                "$set": {
                    f"invoices.{invoice_id}": submission_details
                }
            }
        )
        return redirect(url_for('get_documents'))
    else:
        return jsonify({"error": "Failed to fetch updated submission details"}), response.status_code


@app.route('/send_invoice_email', methods=['POST'])
def send_invoice_email():
    try:
        # Extract form data from the request
        uuid = request.form.get('uuid')
        recipient_email = request.form['recipient_email']
        subject = request.form['subject']
        body = request.form['body']

        # Retrieve the PDF file from the form data
        pdf_file = request.files.get('pdf_file')

        if not pdf_file:
            return jsonify({'error': 'No PDF file found in the request.'}), 400

        # Read the PDF file content
        pdf_data = pdf_file.read()
        pdf_filename = f"invoice_{uuid}.pdf"  # Dynamically set the filename

        # Create the email message
        msg = Message(subject, sender=os.getenv('MAIL_USERNAME'),
                      recipients=[recipient_email])
        msg.body = body

        # Attach the PDF to the email
        msg.attach(pdf_filename, 'application/pdf', pdf_data)

        # Send the email
        mail.send(msg)
        return jsonify({'message': 'Email sent successfully!'}), 200

    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return jsonify({'error': f'Error sending email: {str(e)}'}), 500






@app.route('/creditNote', methods=['GET', 'POST'])
def creditNote():
    try:

        email = session.get('email')
        if not email:
            print('Please log in to access the invoice page.')
            flash('Please log in to access the invoice page.', 'error')
            return redirect(url_for('index'))

        user_collection = db[email]

        supplier_data = user_collection.find_one({"sup_email": email})
        supplier_info = supplier_data if supplier_data else {}
        sup_tin = supplier_info.get('sup_tin', '')
        sup_reg_no = supplier_info.get('sup_reg_no', '')

        print(f"Supplier Info: TIN={sup_tin}, BRN={sup_reg_no}")

        auth_token = session.get('auth_token')
        if not auth_token:
            print('Authentication token is missing or invalid.')
            flash('Authentication token is missing or invalid.', 'error')
            return redirect(url_for('index'))

        validation_url = os.getenv('VALIDATION_URL')
        if not validation_url:
            print('Validation URL is not set in the environment variables.')
            flash('Validation URL is not set. Please contact the administrator.', 'error')
            return redirect(url_for('index'))

        full_validation_url = f'{validation_url}{sup_tin}?idType=BRN&idValue={sup_reg_no}'
        headers = {'Authorization': f'Bearer {auth_token}'}
        print(f"Making GET request to Validation URL: {full_validation_url}")

        response = requests.get(full_validation_url, headers=headers)

        print(f"Validation URL: {full_validation_url}")
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.content}")

        if response.status_code != 200:
            print('Error validating supplier information.')
            flash('Error validating supplier information.', 'error')
            return render_template('invoice.html', supplier_info=supplier_info, sup_tin=sup_tin, sup_reg_no=sup_reg_no, error="Validation failed")

        if request.method == 'POST':
            print("Form submission detected.")
            required_fields = [
                "supplier_name", "sup_sst", 'sup_tin', "sup_contact", 'sup_reg_no', "sup_email",
                "tax_type", "bill_start_date", "bill_end_date", 'invoice_code',
                "invoice_currency",  "buy_contact",
                "buy_country", "buy_state", "buy_city", "buy_postal", "buy_addr2", "buy_addr1",
                "buy_addr0", "buy_email", "buy_reg_no", "buy_tin", "buyer_name",
                "sup_bis_act", "sup_country", "sup_state", "sup_msic", "sup_city", "sup_postal",
                "sup_addr1", "sup_addr2", "sup_tour_reg_no", "sup_addr0", "issueDate", "issueTime"
            ]

            missing_fields = [
                field for field in required_fields if not request.form.get(field)]
            if missing_fields:
                for field in missing_fields:
                    flash(f'{field} is required.', 'error')
                print(f"Missing required fields: {missing_fields}")
                return render_template('invoice.html', supplier_info=supplier_data)

            print("All required fields are present.")

            details_of_tax_exemp = request.form.get("details_of_tax_exemp")
            invoice_code = request.form.get("invoice_code")

            issue_date = request.form.get('issueDate')

            issue_time = request.form.get('issueTime')

            pay_date = request.form.get('pay_date')

            pay_time = request.form.get('pay_time')

            InvoiceTypeCode = "02"

            session['invoice_code'] = invoice_code

            # information fetched here below for showcasing them in preview invoice
            invoice_code = request.form.get("invoice_code")

            issue_date = request.form.get('issueDate')

            invoice_currency = request.form.get('invoice_currency')

            supplier_name = request.form.get('supplier_name')

            supplier_tin = request.form.get('sup_tin')

            supplier_brn = request.form.get('sup_reg_no')

            supplier_addr1 = request.form.get('sup_addr1')

            supplier_addr2 = request.form.get('sup_addr2')

            supplier_postal = request.form.get('sup_postal')

            supplier_city = request.form.get('sup_city')

            supplier_state = request.form.get('sup_state')

            supplier_country = request.form.get('sup_country')

            supplier_contact = request.form.get('sup_contact')

            buyer_name = request.form.get('buyer_name')

            buyer_tin = request.form.get('buy_tin')

            buyer_brn = request.form.get('buy_reg_no')

            buyer_addr1 = request.form.get('buy_addr1')

            buyer_addr2 = request.form.get('buy_addr2')

            buyer_postal = request.form.get('buy_postal')

            buyer_city = request.form.get('buy_city')

            buyer_state = request.form.get('buy_state')

            buyer_country = request.form.get('buy_country')

            buyer_contact = request.form.get('buy_contact')

            if issue_date and issue_time:
                # required 'Z' format
                formatted_time = issue_time + 'Z'

            if pay_date and pay_time:
                # required 'Z' format
                formatted_pay_time = pay_time + 'Z'
            print(f"Invoice Code: {invoice_code}")

            # This contains "Invoice - INV0092|RSWQ637N3XX6TWHFTAN8QEBJ10"
            invoice_ref = request.form.get('invoice_ref')


            invoice_uuid = request.form.get('invoice_uuid')  # UUID is fetched separately

            # Split invoice_ref to extract just the invoice type and number
            if '|' in invoice_ref:
                invoice_type_no, extracted_uuid = invoice_ref.split('|')
                print(invoice_type_no)
                print(extracted_uuid)
            else:
                invoice_type_no = invoice_ref
                print(invoice_type_no, "No")

            # Initialize the invoice data structure
            invoice_data = {
                "_D": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
                "_A": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                "_B": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                "Invoice": [{
                    "AccountingSupplierParty": [{
                        "AdditionalAccountID": [{"_": request.form.get("exp_auth_no"), "schemeAgencyName": "CertEx"}],
                        "Party": [{
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'sup_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_reg_no'), "schemeID": "BRN"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_sst'), "schemeID": "SST"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_tour_reg_no'), "schemeID": "TTX"}]}
                            ],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('sup_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('sup_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('sup_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('sup_postal')}],
                                "CityName": [{"_": request.form.get('sup_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('sup_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('sup_country')}]
                                }]
                            }],
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("supplier_name")}]
                            }],
                            "Contact": [{
                                "ElectronicMail": [{"_": request.form.get('sup_email')}],
                                "Telephone": [{"_": request.form.get('sup_contact')}]
                            }],
                            "IndustryClassificationCode": [
                                # Ensure only one item as per schema
                                {"_": request.form.get("sup_msic")}
                            ]
                        }]
                    }],
                    "AccountingCustomerParty": [{
                        "Party": [{
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'buy_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'buy_reg_no'), "schemeID": "BRN"}]},
                                {"ID": [{"_": request.form.get(
                                    'buy_sst'), "schemeID": "SST"}]}
                            ],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('buy_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('buy_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('buy_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('buy_postal')}],
                                "CityName": [{"_": request.form.get('buy_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('buy_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('buy_country')}]
                                }]
                            }],
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("buyer_name")}]
                            }],
                            "Contact": [{
                                "ElectronicMail": [{"_": request.form.get('buy_email')}],
                                "Telephone": [{"_": request.form.get('buy_contact')}]
                            }]
                        }]
                    }],
                    "InvoiceTypeCode": [{"_": "02", "listVersionID": "1.0"}],
                    "ID": [{"_": invoice_code}],
                    "IssueDate": [{"_": issue_date}],
                    "IssueTime": [{"_": formatted_time}],
                    "DocumentCurrencyCode": [{"_": request.form.get("invoice_currency")}],
                    "TaxExchangeRate": [{
                        "CalculationRate": [{"_": float(request.form.get("currency_rate", 0))}],
                        "SourceCurrencyCode": [{"_": request.form.get("invoice_currency")}],
                        "TargetCurrencyCode": [{"_": "MYR"}]
                    }],
                    "InvoicePeriod": [{
                        "Description": [{"_": request.form.get("freq_billing")}],
                        "StartDate": [{"_": request.form.get("bill_start_date")}],
                        "EndDate": [{"_": request.form.get("bill_end_date")}]
                    }],
                    "BillingReference": [{
                        "AdditionalDocumentReference": [{
                            "ID": [{"_": invoice_type_no }],
                            "UUID": [{"_": invoice_uuid }]
                        }]
                    }],
                    "Delivery": [{
                        "DeliveryParty": [{
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("shipping_res_name")}]
                            }],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('shipping_res_postal')}],
                                "CityName": [{"_": request.form.get('shipping_res_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('shipping_res_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('shipping_res_country')}]
                                }]
                            }],
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'shipping_res_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'shipping_res_id'), "schemeID": "BRN"}]}
                            ]
                        }],
                        "Shipment": [{
                            "ID": [{"_": invoice_code}],
                            "FreightAllowanceCharge": [{
                                "ChargeIndicator": [{"_": True}],
                                "Amount": [{
                                    "_": float(request.form.get('other_charges_amount', 0) or 0),
                                    "currencyID": "MYR"
                                }]
                            }]
                        }]
                    }],
                    "PaymentMeans": [
                        {
                            "PaymentMeansCode": [
                                {
                                    "_": request.form.get('Payment_mode')
                                }
                            ],
                            "PayeeFinancialAccount": [
                                {
                                    "ID": [
                                        {
                                            "_": request.form.get('sup_bank_acc_no')
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "PaymentTerms": [
                        {
                            "Note": [
                                {
                                    "_": request.form.get('pay_terms')
                                }
                            ]
                        }
                    ],
                    "PrepaidPayment": [
                        {
                            "ID": [
                                {
                                    "_": request.form.get('pay_ref_no')
                                }
                            ],
                            "PaidAmount": [
                                {
                                    "_": float(request.form.get('pay_amt')),
                                    "currencyID": "MYR"
                                }
                            ],
                            "PaidDate": [
                                {
                                    "_": pay_date
                                }
                            ],
                            "PaidTime": [
                                {
                                    "_": formatted_pay_time
                                }
                            ]
                        }
                    ],
                    "AdditionalDocumentReference": [
                        {
                            "ID": [{"_": request.form.get("ref_no_custom_form")}],
                            "DocumentType": [{"_": "CustomsImportForm"}]
                        },
                        {
                            "DocumentDescription": [{"_": request.form.get("fta")}],
                            "DocumentType": [{"_": "FreeTradeAgreement"}],
                            "ID": [{"_": "FTA"}]
                        },
                        {
                            "ID": [{"_": request.form.get("ref_no_custom_form2")}],
                            "DocumentType": [{"_": "K2"}]
                        },
                        {
                            "ID": [{"_": request.form.get("incoterms")}]
                        }
                    ],
                    "TaxTotal": [{
                        "TaxAmount": [{
                            "_": float(request.form.get("tax_total_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxSubtotal": [{
                            "TaxableAmount": [{
                                "_": float(request.form.get("tax_subtotal_taxable_amount", 0)),
                                "currencyID": "MYR"
                            }],
                            "TaxAmount": [{
                                "_": float(request.form.get("tax_total_amount", 0)),
                                "currencyID": "MYR"
                            }],
                            "TaxCategory": [{
                                "ID": [{"_": request.form.get("tax_type")}],
                                "TaxExemptionReason": [{"_": request.form.get("details_of_tax_exemp")}],
                                "TaxScheme": [{
                                    "ID": [{"_": "OTH", "schemeID": "UN/ECE 5153", "schemeAgencyID": "6"}]
                                }]
                            }]
                        }]
                    }],
                    "LegalMonetaryTotal": [{
                        "LineExtensionAmount": [{
                            "_": float(request.form.get("legal_line_extension_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxExclusiveAmount": [{
                            "_": float(request.form.get("legal_line_extension_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxInclusiveAmount": [{
                            "_": float(request.form.get("legal_payable_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "PayableAmount": [{
                            "_": float(request.form.get("legal_payable_amount", 0)),
                            "currencyID": "MYR"
                        }]
                    }]

                }]
            }

            print("Invoice data structure initialized.")

            row_index = 0

            products = []
            while request.form.get(f"classification_{row_index}"):
                classification = request.form.get(
                    f"classification_{row_index}")
                description = request.form.get(f"description_{row_index}")
                unit_price = request.form.get(f"unit_price_{row_index}")
                tax_amt = request.form.get(f"tax_amt_{row_index}")
                tax_type = request.form.get("tax_type")
                qty = request.form.get(f"qyt_{row_index}")
                measurement = request.form.get(f"measurement_{row_index}")
                tax_rate = request.form.get(f"tax_rate_{row_index}")
                total_ex = request.form.get(f"total_ex_{row_index}")
                subtotal = request.form.get(f"subtotal_{row_index}")
                disc_rate = request.form.get(f"disc_rate_{row_index}")
                disc_amount = request.form.get(f"disc_amount_{row_index}")
                other_charges = request.form.get("other_charges")

                product_data = {
                    "InvoiceLine": [{
                        "ID": [{"_": f"{row_index + 1}"}],
                        "Item": [
                            {
                                "CommodityClassification": [
                                    {
                                        "ItemClassificationCode": [
                                            {
                                                "_": classification,
                                                "listID": "CLASS"
                                            }
                                        ]
                                    }
                                ],
                                "Description": [
                                    {
                                        "_": description
                                    }
                                ]
                            }
                        ],
                        "Price": [
                            {
                                "PriceAmount": [
                                    {
                                        "_": float(unit_price),
                                        "currencyID": "MYR"
                                    }
                                ]
                            }
                        ],
                        "TaxTotal": [
                            {
                                "TaxAmount": [
                                    {
                                        "_": float(tax_amt),
                                        "currencyID": "MYR"
                                    }
                                ],
                                "TaxSubtotal": [
                                    {
                                        "TaxableAmount": [
                                            {
                                                "_": float(total_ex),
                                                "currencyID": "MYR"
                                            }
                                        ],
                                        "TaxAmount": [
                                            {
                                                "_": float(tax_amt),
                                                "currencyID": "MYR"
                                            }
                                        ],
                                        "TaxCategory": [
                                            {
                                                "ID": [
                                                    {
                                                        "_": tax_type
                                                    }
                                                ],
                                                "TaxExemptionReason": [
                                                    {
                                                        "_": request.form.get("details_of_tax_exemp")
                                                    }
                                                ],
                                                "TaxScheme": [
                                                    {
                                                        "ID": [
                                                            {
                                                                "_": "OTH",
                                                                "schemeID": "UN/ECE 5153",
                                                                "schemeAgencyID": "6"
                                                            }
                                                        ]
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "ItemPriceExtension": [
                            {
                                "Amount": [
                                    {
                                        "_": float(subtotal),
                                        "currencyID": "MYR"
                                    }
                                ]
                            }
                        ],
                        "LineExtensionAmount": [
                            {
                                "_": float(total_ex),
                                "currencyID": "MYR"
                            }
                        ],
                        "InvoicedQuantity": [
                            {
                                "_": float(qty),
                                "unitCode": measurement
                            }
                        ],
                        "AllowanceCharge": [
                            {
                                "ChargeIndicator": [
                                    {
                                        "_": True
                                    }
                                ],
                                "MultiplierFactorNumeric": [
                                    {
                                        "_": float(disc_rate)
                                    }
                                ],
                                "Amount": [
                                    {
                                        "_": float(disc_amount),
                                        "currencyID": "MYR"
                                    }
                                ],
                                "AllowanceChargeReason": [
                                    {
                                        "_": other_charges
                                    }
                                ]
                            }
                        ]
                    }]
                }

                products.append(product_data)
                print(
                    f"Added product {row_index}: {json.dumps(product_data, indent=4)}")
                row_index += 1

                print(f"Total products added: {len(products)}")

                invoice_data["Invoice"][0]["InvoiceLine"] = [
                    product["InvoiceLine"][0] for product in products
                ]

                print("Invoice data before cleaning:",
                      json.dumps(invoice_data, indent=4))

                # Remove null fields from invoice data
                for key in list(invoice_data.keys()):
                    if isinstance(invoice_data[key], dict):
                        for subkey in list(invoice_data[key].keys()):
                            if not invoice_data[key][subkey]:
                                print(
                                    f"Removing empty field: {subkey} from {key}")
                                del invoice_data[key][subkey]
                    elif isinstance(invoice_data[key], list):
                        for item in invoice_data[key]:
                            for subkey in list(item.keys()):
                                if not item[subkey]:
                                    print(
                                        f"Removing empty field: {subkey} from list item")
                                    del item[subkey]

                print("Invoice data after cleaning:",
                      json.dumps(invoice_data, indent=4))

                invoice_json_str = json.dumps(invoice_data)
                invoice_json_str = json.dumps(invoice_data)
        sha256_hash = hashlib.sha256(
            invoice_json_str.encode('utf-8')).hexdigest()

        base64_encoded = base64.b64encode(
            invoice_json_str.encode('utf-8')).decode('utf-8')

        payload = {
            "documents": [
                {
                    "format": "JSON",
                    "documentHash": sha256_hash,
                    "codeNumber": invoice_code,
                    "document": base64_encoded
                }
            ]
        }

        session['invoice_code'] = invoice_code
        json_filename = f'invoice_data_{invoice_code}.json'
        json_file_path = os.path.join(os.getcwd(), json_filename)
        with open(json_file_path, 'w') as json_file:
            json.dump(invoice_data, json_file, indent=4)
        print(f'Saved invoice data to {json_file_path}')

        api_url = os.getenv('SUBMIT_DOC_URL')
        if not api_url:
            print('API URL is not set in the environment variables.')
            flash('API URL is not set. Please contact the administrator.', 'error')
            return redirect(url_for('invoice'))

        headers = {
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json'
        }

        response = requests.post(
            api_url, headers=headers, data=json.dumps(payload))
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")

        if response.status_code == 202:
            submission_data = response.json()
            submission_uid = submission_data['submissionUid']
            document_uuid = submission_data['acceptedDocuments'][0]['uuid']

            if submission_uid and document_uuid:

                invoice_document = {
                    "payload": payload,
                    "submissionUid": submission_uid,
                    "documentUUID": document_uuid,
                    "sha256_hash": sha256_hash,
                    "base64_encoded": base64_encoded
                }

                user_collection = db[email]
                result = user_collection.update_one(
                    {"sup_email": email},
                    {"$set": {f"invoices.{invoice_code}": invoice_document}},
                    upsert=True
                )
                return jsonify(invoice_document)

                if result.modified_count > 0 or result.upserted_id:
                    print(
                        f"Invoice data saved in MongoDB under invoice code {invoice_code} for user {email}")
                    flash(
                        'Invoice submitted successfully and saved in MongoDB.', 'success')
                else:
                    flash('Invoice submission failed to save in MongoDB.', 'error')
            else:
                flash(
                    'Invoice submission failed due to missing submission UID or document UUID.', 'error')
        else:
            flash(
                f'Failed to submit invoice. Status code: {response.status_code}', 'error')

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        flash('An unexpected error occurred. Please try again later.', 'error')

    return redirect(url_for('get_submission', invoice_code=invoice_code, submission_uid=submission_uid, document_uuid=document_uuid))


@app.route('/debitNote', methods=['GET', 'POST'])

def debitNote():
    try:
        
        email = session.get('email')
        if not email:
            print('Please log in to access the invoice page.')
            flash('Please log in to access the invoice page.', 'error')
            return redirect(url_for('index'))

        

        
        user_collection = db[email]

        
        supplier_data = user_collection.find_one({"sup_email": email})
        supplier_info = supplier_data if supplier_data else {}
        sup_tin = supplier_info.get('sup_tin', '')
        sup_reg_no = supplier_info.get('sup_reg_no', '')

        print(f"Supplier Info: TIN={sup_tin}, BRN={sup_reg_no}")

        
        auth_token = session.get('auth_token')
        if not auth_token:
            print('Authentication token is missing or invalid.')
            flash('Authentication token is missing or invalid.', 'error')
            return redirect(url_for('index'))

        
        validation_url = os.getenv('VALIDATION_URL')
        if not validation_url:
            print('Validation URL is not set in the environment variables.')
            flash('Validation URL is not set. Please contact the administrator.', 'error')
            return redirect(url_for('index'))

        
        full_validation_url = f'{validation_url}{sup_tin}?idType=BRN&idValue={sup_reg_no}'
        headers = {'Authorization': f'Bearer {auth_token}'}
        print(f"Making GET request to Validation URL: {full_validation_url}")

        
        response = requests.get(full_validation_url, headers=headers)

        print(f"Validation URL: {full_validation_url}")
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.content}")

        if response.status_code != 200:
            print('Error validating supplier information.')
            flash('Error validating supplier information.', 'error')
            return render_template('invoice.html', supplier_info=supplier_info, sup_tin=sup_tin, sup_reg_no=sup_reg_no, error="Validation failed")

        if request.method == 'POST':
            print("Form submission detected.")
            required_fields = [
                "supplier_name", "sup_sst", 'sup_tin', "sup_contact", 'sup_reg_no', "sup_email",
                "tax_type", "bill_start_date", "bill_end_date", 'invoice_code',
                "invoice_currency",  "buy_contact",
                "buy_country", "buy_state", "buy_city", "buy_postal", "buy_addr2", "buy_addr1",
                "buy_addr0", "buy_email", "buy_reg_no", "buy_tin", "buyer_name",
                "sup_bis_act", "sup_country", "sup_state", "sup_msic", "sup_city", "sup_postal",
                "sup_addr1", "sup_addr2", "sup_tour_reg_no", "sup_addr0", "issueDate", "issueTime"
            ]

            
            missing_fields = [
                field for field in required_fields if not request.form.get(field)]
            if missing_fields:
                for field in missing_fields:
                    flash(f'{field} is required.', 'error')
                print(f"Missing required fields: {missing_fields}")
                return render_template('invoice.html', supplier_info=supplier_data)

            print("All required fields are present.")

            details_of_tax_exemp = request.form.get("details_of_tax_exemp")
            invoice_code = request.form.get("invoice_code")
            
            issue_date = request.form.get('issueDate')
            
            issue_time = request.form.get('issueTime')

            pay_date = request.form.get('pay_date')

            pay_time = request.form.get('pay_time')

            InvoiceTypeCode = "03"

            session['invoice_code'] = invoice_code


            #information fetched here below for showcasing them in preview invoice
            invoice_code = request.form.get("invoice_code")

            issue_date = request.form.get('issueDate')

            invoice_currency = request.form.get('invoice_currency')

            supplier_name = request.form.get('supplier_name')

            supplier_tin = request.form.get('sup_tin')

            supplier_brn = request.form.get('sup_reg_no')

            supplier_addr1 = request.form.get('sup_addr1')

            supplier_addr2 = request.form.get('sup_addr2')

            supplier_postal = request.form.get('sup_postal')

            supplier_city = request.form.get('sup_city')

            supplier_state = request.form.get('sup_state')

            supplier_country = request.form.get('sup_country')

            supplier_contact = request.form.get('sup_contact')

            buyer_name = request.form.get('buyer_name')

            buyer_tin = request.form.get('buy_tin')

            buyer_brn = request.form.get('buy_reg_no')

            buyer_addr1 = request.form.get('buy_addr1')

            buyer_addr2 = request.form.get('buy_addr2')

            buyer_postal = request.form.get('buy_postal')

            buyer_city = request.form.get('buy_city')

            buyer_state = request.form.get('buy_state')

            buyer_country = request.form.get('buy_country')

            buyer_contact = request.form.get('buy_contact')



            if issue_date and issue_time:
                #required 'Z' format
                formatted_time = issue_time + 'Z'

            if pay_date and pay_time:
                #required 'Z' format
                formatted_pay_time = pay_time + 'Z'
            print(f"Invoice Code: {invoice_code}")

            # Initialize the invoice data structure
            invoice_data = {
                "_D": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
                "_A": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                "_B": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                "Invoice": [{
                    "AccountingSupplierParty": [{
                        "AdditionalAccountID": [{"_": request.form.get("exp_auth_no"), "schemeAgencyName": "CertEx"}],
                        "Party": [{
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'sup_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_reg_no'), "schemeID": "BRN"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_sst'), "schemeID": "SST"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_tour_reg_no'), "schemeID": "TTX"}]}
                            ],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('sup_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('sup_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('sup_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('sup_postal')}],
                                "CityName": [{"_": request.form.get('sup_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('sup_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('sup_country')}]
                                }]
                            }],
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("supplier_name")}]
                            }],
                            "Contact": [{
                                "ElectronicMail": [{"_": request.form.get('sup_email')}],
                                "Telephone": [{"_": request.form.get('sup_contact')}]
                            }],
                            "IndustryClassificationCode": [
                                # Ensure only one item as per schema
                                {"_": request.form.get("sup_msic")}
                            ]
                        }]
                    }],
                    "AccountingCustomerParty": [{
                        "Party": [{
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'buy_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'buy_reg_no'), "schemeID": "BRN"}]},
                                {"ID": [{"_": request.form.get(
                                    'buy_sst'), "schemeID": "SST"}]}
                            ],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('buy_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('buy_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('buy_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('buy_postal')}],
                                "CityName": [{"_": request.form.get('buy_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('buy_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('buy_country')}]
                                }]
                            }],
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("buyer_name")}]
                            }],
                            "Contact": [{
                                "ElectronicMail": [{"_": request.form.get('buy_email')}],
                                "Telephone": [{"_": request.form.get('buy_contact')}]
                            }]
                        }]
                    }],
                    "InvoiceTypeCode": [{"_": "02", "listVersionID": "1.0"}],
                    "ID": [{"_": invoice_code}],
                    "IssueDate": [{"_": issue_date}],
                    "IssueTime": [{"_": formatted_time}],
                    "DocumentCurrencyCode": [{"_": request.form.get("invoice_currency")}],
                    "TaxExchangeRate": [{
                        "CalculationRate": [{"_": float(request.form.get("currency_rate", 0))}],
                        "SourceCurrencyCode": [{"_": request.form.get("invoice_currency")}],
                        "TargetCurrencyCode": [{"_": "MYR"}]
                    }],
                    "InvoicePeriod": [{
                        "Description": [{"_": request.form.get("freq_billing")}],
                        "StartDate": [{"_": request.form.get("bill_start_date")}],
                        "EndDate": [{"_": request.form.get("bill_end_date")}]
                    }],
                    "BillingReference": [{
                        "AdditionalDocumentReference": [{
                            "ID": [{"_": request.form.get("invoice_ref")}]
                        }]
                    }],
                    "Delivery": [{
                        "DeliveryParty": [{
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("shipping_res_name")}]
                            }],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('shipping_res_postal')}],
                                "CityName": [{"_": request.form.get('shipping_res_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('shipping_res_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('shipping_res_country')}]
                                }]
                            }],
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'shipping_res_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'shipping_res_id'), "schemeID": "BRN"}]}
                            ]
                        }],
                        "Shipment": [{
                            "ID": [{"_": invoice_code}],
                            "FreightAllowanceCharge": [{
                                "ChargeIndicator": [{"_": True}],
                                "Amount": [{
                                    "_": float(request.form.get('other_charges_amount', '0') or '0'),
                                    "currencyID": "MYR"
                                }]
                            }]
                        }]
                    }],
                    "PaymentMeans": [
                        {
                        "PaymentMeansCode": [
                            {
                            "_": request.form.get('Payment_mode')
                            }
                        ],
                        "PayeeFinancialAccount": [
                            {
                            "ID": [
                                {
                                "_": request.form.get('sup_bank_acc_no')
                                }
                            ]
                            }
                        ]
                        }
                    ],
                    "PaymentTerms": [
                        {
                        "Note": [
                            {
                            "_": request.form.get('pay_terms')
                            }
                        ]
                        }
                    ],
                    "PrepaidPayment": [
                        {
                        "ID": [
                            {
                            "_": request.form.get('pay_ref_no')
                            }
                        ],
                        "PaidAmount": [
                            {
                            "_": float(request.form.get('pay_amt')),
                            "currencyID": "MYR"
                            }
                        ],
                        "PaidDate": [
                            {
                            "_": pay_date
                            }
                        ],
                        "PaidTime": [
                            {
                            "_": formatted_pay_time
                            }
                        ]
                        }
                    ],
                    "AdditionalDocumentReference": [
                        {
                            "ID": [{"_": request.form.get("ref_no_custom_form")}],
                            "DocumentType": [{"_": "CustomsImportForm"}]
                        },
                        {
                            "DocumentDescription": [{"_": request.form.get("fta")}],
                            "DocumentType": [{"_": "FreeTradeAgreement"}],
                            "ID": [{"_": "FTA"}]
                        },
                        {
                            "ID": [{"_": request.form.get("ref_no_custom_form2")}],
                            "DocumentType": [{"_": "K2"}]
                        },
                        {
                            "ID": [{"_": request.form.get("incoterms")}]
                        }
                    ],
                    "TaxTotal": [{
                        "TaxAmount": [{
                            "_": float(request.form.get("tax_total_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxSubtotal": [{
                            "TaxableAmount": [{
                                "_": float(request.form.get("tax_subtotal_taxable_amount", 0)),
                                "currencyID": "MYR"
                            }],
                            "TaxAmount": [{
                                "_": float(request.form.get("tax_total_amount", 0)),
                                "currencyID": "MYR"
                            }],
                            "TaxCategory": [{
                                "ID": [{"_": request.form.get("tax_type")}],
                                "TaxExemptionReason": [{"_": request.form.get("details_of_tax_exemp")}],
                                "TaxScheme": [{
                                    "ID": [{"_": "OTH", "schemeID": "UN/ECE 5153", "schemeAgencyID": "6"}]
                                }]
                            }]
                        }]
                    }],
                    "LegalMonetaryTotal": [{
                        "LineExtensionAmount": [{
                            "_": float(request.form.get("legal_line_extension_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxExclusiveAmount": [{
                            "_": float(request.form.get("legal_line_extension_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxInclusiveAmount": [{
                            "_": float(request.form.get("legal_payable_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "PayableAmount": [{
                            "_": float(request.form.get("legal_payable_amount", 0)),
                            "currencyID": "MYR"
                        }]
                    }]
                    
                }]
            }

            print("Invoice data structure initialized.")

            row_index = 0


            products = []
            while request.form.get(f"classification_{row_index}"):
                classification = request.form.get(f"classification_{row_index}")
                description = request.form.get(f"description_{row_index}")
                unit_price = request.form.get(f"unit_price_{row_index}")
                tax_amt = request.form.get(f"tax_amt_{row_index}")
                tax_type = request.form.get("tax_type")
                qty = request.form.get(f"qyt_{row_index}")
                measurement = request.form.get(f"measurement_{row_index}")
                tax_rate = request.form.get(f"tax_rate_{row_index}")
                total_ex = request.form.get(f"total_ex_{row_index}")
                subtotal = request.form.get(f"subtotal_{row_index}")
                disc_rate = request.form.get(f"disc_rate_{row_index}")
                disc_amount = request.form.get(f"disc_amount_{row_index}")
                other_charges = request.form.get("other_charges")

                product_data = {
                    "InvoiceLine": [{
                        "ID": [{"_": f"{row_index + 1}"}],
                        "Item": [  
                            {
                                "CommodityClassification": [
                                    {
                                        "ItemClassificationCode": [
                                            {
                                                "_": classification,
                                                "listID": "CLASS"
                                            }
                                        ]
                                    }
                                ],
                                "Description": [
                                    {
                                        "_": description
                                    }
                                ]
                            }
                        ],
                        "Price": [  
                            {
                                "PriceAmount": [
                                    {
                                        "_": float(unit_price),
                                        "currencyID": "MYR"
                                    }
                                ]
                            }
                        ],
                        "TaxTotal": [
                            {
                                "TaxAmount": [
                                    {
                                        "_": float(tax_amt),
                                        "currencyID": "MYR"
                                    }
                                ],
                                "TaxSubtotal": [
                                    {
                                        "TaxableAmount": [
                                            {
                                                "_": float(total_ex),
                                                "currencyID": "MYR"
                                            }
                                        ],
                                        "TaxAmount": [
                                            {
                                                "_": float(tax_amt),
                                                "currencyID": "MYR"
                                            }
                                        ],
                                        "TaxCategory": [
                                            {
                                                "ID": [
                                                    {
                                                        "_": tax_type
                                                    }
                                                ],
                                                "TaxExemptionReason": [
                                                    {
                                                        "_": request.form.get("details_of_tax_exemp")
                                                    }
                                                ],
                                                "TaxScheme": [
                                                    {
                                                        "ID": [
                                                            {
                                                                "_": "OTH",
                                                                "schemeID": "UN/ECE 5153",
                                                                "schemeAgencyID": "6"
                                                            }
                                                        ]
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "ItemPriceExtension": [  
                            {
                                "Amount": [
                                    {
                                        "_": float(subtotal),
                                        "currencyID": "MYR"
                                    }
                                ]
                            }
                        ],
                        "LineExtensionAmount": [
                            {
                                "_": float(total_ex),
                                "currencyID": "MYR"
                            }
                        ],
                        "InvoicedQuantity": [
                            {
                                "_": float(qty),
                                "unitCode": measurement
                            }
                        ],
                        "AllowanceCharge": [
                            {
                                "ChargeIndicator": [
                                    {
                                        "_": True
                                    }
                                ],
                                "MultiplierFactorNumeric": [
                                    {
                                        "_": float(disc_rate)
                                    }
                                ],
                                "Amount": [
                                    {
                                        "_": float(disc_amount),
                                        "currencyID": "MYR"
                                    }
                                ],
                                "AllowanceChargeReason": [
                                    {
                                        "_": other_charges
                                    }
                                ]
                            }
                        ]
                    }]
                }

                products.append(product_data)
                print(f"Added product {row_index}: {json.dumps(product_data, indent=4)}")
                row_index += 1

                print(f"Total products added: {len(products)}")

                
                invoice_data["Invoice"][0]["InvoiceLine"] = [
                    product["InvoiceLine"][0] for product in products
                ]

                print("Invoice data before cleaning:", json.dumps(invoice_data, indent=4))

                # Remove null fields from invoice data
                for key in list(invoice_data.keys()):
                    if isinstance(invoice_data[key], dict):
                        for subkey in list(invoice_data[key].keys()):
                            if not invoice_data[key][subkey]:  
                                print(f"Removing empty field: {subkey} from {key}")
                                del invoice_data[key][subkey]
                    elif isinstance(invoice_data[key], list):
                        for item in invoice_data[key]:
                            for subkey in list(item.keys()):
                                if not item[subkey]: 
                                    print(f"Removing empty field: {subkey} from list item")
                                    del item[subkey]

                print("Invoice data after cleaning:", json.dumps(invoice_data, indent=4))

                
                invoice_json_str = json.dumps(invoice_data)
                invoice_json_str = json.dumps(invoice_data)
        sha256_hash = hashlib.sha256(
            invoice_json_str.encode('utf-8')).hexdigest()

        base64_encoded = base64.b64encode(
            invoice_json_str.encode('utf-8')).decode('utf-8')

        payload = {
            "documents": [
                {
                    "format": "JSON",
                    "documentHash": sha256_hash,
                    "codeNumber": invoice_code,
                    "document": base64_encoded
                }
            ]
        }

        session['invoice_code'] = invoice_code
        json_filename = f'invoice_data_{invoice_code}.json'
        json_file_path = os.path.join(os.getcwd(), json_filename)
        with open(json_file_path, 'w') as json_file:
            json.dump(invoice_data, json_file, indent=4)
        print(f'Saved invoice data to {json_file_path}')

        api_url = os.getenv('SUBMIT_DOC_URL')
        if not api_url:
            print('API URL is not set in the environment variables.')
            flash('API URL is not set. Please contact the administrator.', 'error')
            return redirect(url_for('invoice'))

        headers = {
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json'
        }

        response = requests.post(
            api_url, headers=headers, data=json.dumps(payload))
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")

        if response.status_code == 202:
            submission_data = response.json()
            submission_uid = submission_data['submissionUid']
            document_uuid = submission_data['acceptedDocuments'][0]['uuid']

            if submission_uid and document_uuid:

                invoice_document = {
                    "payload": payload,
                    "submissionUid": submission_uid,
                    "documentUUID": document_uuid,
                    "sha256_hash": sha256_hash,
                    "base64_encoded": base64_encoded
                }

                user_collection = db[email]
                result = user_collection.update_one(
                    {"sup_email": email},
                    {"$set": {f"invoices.{invoice_code}": invoice_document}},
                    upsert=True
                )
                return jsonify(invoice_document)

                if result.modified_count > 0 or result.upserted_id:
                    print(
                        f"Invoice data saved in MongoDB under invoice code {invoice_code} for user {email}")
                    flash(
                        'Invoice submitted successfully and saved in MongoDB.', 'success')
                else:
                    flash('Invoice submission failed to save in MongoDB.', 'error')
            else:
                flash(
                    'Invoice submission failed due to missing submission UID or document UUID.', 'error')
        else:
            flash(
                f'Failed to submit invoice. Status code: {response.status_code}', 'error')

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        flash('An unexpected error occurred. Please try again later.', 'error')

    return redirect(url_for('get_submission', invoice_code=invoice_code, submission_uid = submission_uid, document_uuid = document_uuid))



@app.route('/refundNote', methods=['GET', 'POST'])
def refundNote():
    if 'email' not in session:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('index'))

    # Check if profile is incomplete
    if session.get('profile_incomplete'):
        return redirect(url_for('profile'))
    try:
        # Retrieve user email from session
        email = session.get('email')
        if not email:
            print('Please log in to access the invoice page.')
            flash('Please log in to access the invoice page.', 'error')
            return redirect(url_for('index'))

        # Access user's collection in the database
        user_collection = db[email]

        # Fetch supplier data
        supplier_data = user_collection.find_one({"sup_email": email})
        supplier_info = supplier_data if supplier_data else {}
        sup_tin = supplier_info.get('sup_tin', '')
        sup_reg_no = supplier_info.get('sup_reg_no', '')

        print(f"Supplier Info: TIN={sup_tin}, BRN={sup_reg_no}")

        # Retrieve authentication token from session
        auth_token = session.get('auth_token')
        if not auth_token:
            print('Authentication token is missing or invalid.')
            flash('Authentication token is missing or invalid.', 'error')
            return redirect(url_for('index'))

        # Get validation URL from environment variables
        validation_url = os.getenv('VALIDATION_URL')
        if not validation_url:
            print('Validation URL is not set in the environment variables.')
            flash('Validation URL is not set. Please contact the administrator.', 'error')
            return redirect(url_for('index'))

        # Construct the full validation URL
        full_validation_url = f'{validation_url}{sup_tin}?idType=BRN&idValue={sup_reg_no}'
        headers = {'Authorization': f'Bearer {auth_token}'}
        print(f"Making GET request to Validation URL: {full_validation_url}")

        # Make the GET request to validate supplier information
        response = requests.get(full_validation_url, headers=headers)

        print(f"Validation URL: {full_validation_url}")
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.content}")

        if response.status_code != 200:
            print('Error validating supplier information.')
            flash('Error validating supplier information.', 'error')
            return render_template('invoice.html', supplier_info=supplier_info, sup_tin=sup_tin, sup_reg_no=sup_reg_no, error="Validation failed")

        if request.method == 'POST':
            print("Form submission detected.")
            required_fields = ['sup_tin', 'sup_reg_no',
                               'invoice_code', 'invoice_currency']
            missing_fields = [
                field for field in required_fields if not request.form.get(field)]
            if missing_fields:
                for field in missing_fields:
                    flash(f'{field} is required.', 'error')
                print(f"Missing required fields: {missing_fields}")
                return render_template('invoice.html', supplier_info=supplier_data)

            print("All required fields are present.")

            details_of_tax_exemp = request.form.get("details_of_tax_exemp")
            invoice_code = request.form.get("invoice_code")
            print(f"Invoice Code: {invoice_code}")

            # Initialize the invoice data structure
            invoice_data = {
                "_D": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
                "_A": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                "_B": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                "Invoice": [{
                    "AccountingSupplierParty": [{
                        "AdditionalAccountID": [{"_": request.form.get("exp_auth_no"), "schemeAgencyName": "CertEx"}],
                        "Party": [{
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'sup_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_reg_no'), "schemeID": "BRN"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_sst'), "schemeID": "SST"}]},
                                {"ID": [{"_": request.form.get(
                                    'sup_tour_reg_no'), "schemeID": "TTX"}]}
                            ],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('sup_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('sup_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('sup_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('sup_postal')}],
                                "CityName": [{"_": request.form.get('sup_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('sup_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('sup_country')}]
                                }]
                            }],
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("supplier_name")}]
                            }],
                            "Contact": [{
                                "ElectronicMail": [{"_": request.form.get('sup_email')}],
                                "Telephone": [{"_": request.form.get('sup_contact')}]
                            }],
                            "IndustryClassificationCode": [
                                # Ensure only one item as per schema
                                {"_": request.form.get("sup_msic")}
                            ]
                        }]
                    }],
                    "AccountingCustomerParty": [{
                        "Party": [{
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'buy_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'buy_reg_no'), "schemeID": "BRN"}]},
                                {"ID": [{"_": request.form.get(
                                    'buy_sst'), "schemeID": "SST"}]}
                            ],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('buy_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('buy_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('buy_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('buy_postal')}],
                                "CityName": [{"_": request.form.get('buy_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('buy_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('buy_country')}]
                                }]
                            }],
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("buyer_name")}]
                            }],
                            "Contact": [{
                                "ElectronicMail": [{"_": request.form.get('buy_email')}],
                                "Telephone": [{"_": request.form.get('buy_contact')}]
                            }]
                        }]
                    }],
                    "InvoiceTypeCode": [{"_": "04", "listVersionID": "1.1"}],
                    "ID": [{"_": invoice_code}],
                    "IssueDate": [{"_": datetime.now().strftime("%Y-%m-%d")}],
                    "IssueTime": [{"_": datetime.now().strftime("%H:%M:%SZ")}],
                    "DocumentCurrencyCode": [{"_": request.form.get("invoice_currency")}],
                    "TaxExchangeRate": [{
                        "CalculationRate": [{"_": float(request.form.get("currency_rate", 0))}],
                        "SourceCurrencyCode": [{"_": request.form.get("invoice_currency")}],
                        "TargetCurrencyCode": [{"_": "MYR"}]
                    }],
                    "InvoicePeriod": [{
                        "Description": [{"_": request.form.get("freq_billing")}],
                        "StartDate": [{"_": request.form.get("bill_start_date")}],
                        "EndDate": [{"_": request.form.get("bill_end_date")}]
                    }],
                    "BillingReference": [{
                        "AdditionalDocumentReference": [{
                            "ID": [{"_": request.form.get("invoice_ref")}]
                        }]
                    }],
                    "Delivery": [{
                        "DeliveryParty": [{
                            "PartyLegalEntity": [{
                                "RegistrationName": [{"_": request.form.get("shipping_res_name")}]
                            }],
                            "PostalAddress": [{
                                "AddressLine": [
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr0')}]},
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr1')}]},
                                    {"Line": [
                                        {"_": request.form.get('shipping_res_addr2')}]}
                                ],
                                "PostalZone": [{"_": request.form.get('shipping_res_postal')}],
                                "CityName": [{"_": request.form.get('shipping_res_city')}],
                                "CountrySubentityCode": [{"_": request.form.get('shipping_res_state')}],
                                "Country": [{
                                    "IdentificationCode": [{"_": request.form.get('shipping_res_country')}]
                                }]
                            }],
                            "PartyIdentification": [
                                {"ID": [{"_": request.form.get(
                                    'shipping_res_tin'), "schemeID": "TIN"}]},
                                {"ID": [{"_": request.form.get(
                                    'shipping_res_id'), "schemeID": "BRN"}]}
                            ]
                        }],
                        "Shipment": [{
                            "ID": [{"_": invoice_code}],
                            "FreightAllowanceCharge": [{
                                "ChargeIndicator": [{"_": True}],
                                "Amount": [{
                                    "_": float(request.form.get('other_charges_amount', '0') or '0'),
                                    "currencyID": "MYR"
                                }]
                            }]
                        }]
                    }],
                    "AdditionalDocumentReference": [
                        {
                            "ID": [{"_": request.form.get("ref_no_custom_form")}],
                            "DocumentType": [{"_": "CustomsImportForm"}]
                        },
                        {
                            "DocumentDescription": [{"_": request.form.get("fta")}],
                            "DocumentType": [{"_": "FreeTradeAgreement"}],
                            "ID": [{"_": "FTA"}]
                        },
                        {
                            "ID": [{"_": request.form.get("ref_no_custom_form2")}],
                            "DocumentType": [{"_": "K2"}]
                        },
                        {
                            "ID": [{"_": request.form.get("incoterms")}]
                        }
                    ],
                    "TaxTotal": [{
                        "TaxAmount": [{
                            "_": float(request.form.get("tax_total_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxSubtotal": [{
                            "TaxableAmount": [{
                                "_": float(request.form.get("tax_subtotal_taxable_amount", 0)),
                                "currencyID": "MYR"
                            }],
                            "TaxAmount": [{
                                "_": float(request.form.get("tax_total_amount", 0)),
                                "currencyID": "MYR"
                            }],
                            "TaxCategory": [{
                                "ID": [{"_": "01"}],
                                "TaxExemptionReasonCode": [{"_": request.form.get("tax_exemption_code")}],
                                "TaxScheme": [{
                                    "ID": [{"_": "OTH", "schemeID": "UN/ECE 5153", "schemeAgencyID": "6"}]
                                }]
                            }]
                        }]
                    }],
                    "LegalMonetaryTotal": [{
                        "LineExtensionAmount": [{
                            "_": float(request.form.get("legal_line_extension_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxExclusiveAmount": [{
                            "_": float(request.form.get("legal_charge_total_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "TaxInclusiveAmount": [{
                            "_": float(request.form.get("tax_subtotal_taxable_amount", 0)),
                            "currencyID": "MYR"
                        }],
                        "PayableAmount": [{
                            "_": float(request.form.get("legal_payable_amount", 0)),
                            "currencyID": "MYR"
                        }]
                    }]

                }]
            }

            print("Invoice data structure initialized.")

            row_index = 0

            products = []
            while request.form.get(f"classification_{row_index}"):
                classification = request.form.get(
                    f"classification_{row_index}")
                description = request.form.get(f"description_{row_index}")
                unit_price = request.form.get(f"unit_price_{row_index}")
                tax_amt = request.form.get(f"tax_amt_{row_index}")
                tax_type = request.form.get("tax_type")
                qty = request.form.get(f"qyt_{row_index}")
                measurement = request.form.get(f"measurement_{row_index}")
                tax_rate = request.form.get(f"tax_rate_{row_index}")
                total_ex = request.form.get(f"total_ex_{row_index}")
                subtotal = request.form.get(f"subtotal_{row_index}")
                disc_rate = request.form.get(f"disc_rate_{row_index}")
                disc_amount = request.form.get(f"disc_amount_{row_index}")

                product_data = {
                    "InvoiceLine": [{
                        "ID": [{"_": f"{row_index + 1}"}],
                        "Item": [  # Ensure Item is an array
                            {
                                "CommodityClassification": [
                                    {
                                        "ItemClassificationCode": [
                                            {
                                                "_": classification,
                                                "listID": "CLASS"
                                            }
                                        ]
                                    }
                                ],
                                "Description": [
                                    {
                                        "_": description
                                    }
                                ]
                            }
                        ],
                        "Price": [  # Ensure Price is an array
                            {
                                "PriceAmount": [
                                    {
                                        "_": float(unit_price),
                                        "currencyID": "MYR"
                                    }
                                ]
                            }
                        ],
                        "TaxTotal": [
                            {
                                "TaxAmount": [
                                    {
                                        "_": float(tax_amt),
                                        "currencyID": "MYR"
                                    }
                                ],
                                "TaxSubtotal": [
                                    {
                                        "TaxableAmount": [
                                            {
                                                "_": float(total_ex),
                                                "currencyID": "MYR"
                                            }
                                        ],
                                        "TaxAmount": [
                                            {
                                                "_": float(tax_amt),
                                                "currencyID": "MYR"
                                            }
                                        ],
                                        "TaxCategory": [
                                            {
                                                "ID": [
                                                    {
                                                        "_": "E"
                                                    }
                                                ],
                                                "TaxExemptionReason": [
                                                    {
                                                        "_": "Exempt New Means of Transport"  # Adjust this if needed
                                                    }
                                                ],
                                                "TaxScheme": [
                                                    {
                                                        "ID": [
                                                            {
                                                                "_": "OTH",
                                                                "schemeID": "UN/ECE 5153",
                                                                "schemeAgencyID": "6"
                                                            }
                                                        ]
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "ItemPriceExtension": [  # Ensure ItemPriceExtension is an array
                            {
                                "Amount": [
                                    {
                                        "_": float(subtotal),
                                        "currencyID": "MYR"
                                    }
                                ]
                            }
                        ],
                        "LineExtensionAmount": [
                            {
                                "_": float(total_ex),
                                "currencyID": "MYR"
                            }
                        ],
                        "InvoicedQuantity": [
                            {
                                "_": float(qty),
                                "unitCode": measurement
                            }
                        ],
                        "AllowanceCharge": [
                            {
                                "ChargeIndicator": [
                                    {
                                        "_": True
                                    }
                                ],
                                "MultiplierFactorNumeric": [
                                    {
                                        "_": float(disc_rate)
                                    }
                                ],
                                "Amount": [
                                    {
                                        "_": float(disc_amount),
                                        "currencyID": "MYR"
                                    }
                                ],
                                "AllowanceChargeReason": [
                                    {
                                        "_": "Discount"
                                    }
                                ]
                            }
                        ]
                    }]
                }

                products.append(product_data)
                print(
                    f"Added product {row_index}: {json.dumps(product_data, indent=4)}")
                row_index += 1

            print(f"Total products added: {len(products)}")

            # Add the collected products to the invoice data
            invoice_data["Invoice"][0]["InvoiceLine"] = [
                product["InvoiceLine"][0] for product in products
            ]

            print("Invoice data with products:",
                  json.dumps(invoice_data, indent=4))

            session['invoice_data'] = invoice_data

            # Save the combined invoice data as a JSON file
            file_name = f'refundNote_{invoice_code}.json'
            try:
                with open(file_name, 'w') as json_file:
                    json.dump(invoice_data, json_file, indent=4)
                print(f"Invoice data saved to {file_name}.")
                flash('Invoice data has been saved successfully.', 'success')
            except Exception as e:
                print(f"Error saving invoice data to {file_name}: {e}")
                flash(f'Error saving invoice data: {e}', 'error')

            return render_template('refundNote.html', supplier_info=supplier_info, sup_tin=sup_tin, sup_reg_no=sup_reg_no)

        # For GET requests, render the invoice page
        return render_template('refundNote.html', supplier_info=supplier_info, sup_tin=sup_tin, sup_reg_no=sup_reg_no)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        flash('An unexpected error occurred while processing your request. Please try again later.', 'error')
        return redirect(url_for('refundNote'))






if __name__ == '__main__':
    app.run(debug=True)

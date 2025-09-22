from flask import Flask, render_template, request, redirect, url_for, session
import re, hashlib, os
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename

# Set up connection
client = MongoClient("mongodb://localhost:27017")
db = client["pythonlogin"]
accounts = db['accounts']

# Define the upload folder and allowed file extensions
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# This is the secret key below, can be anything
app.secret_key = 'Trendxyz'

# Design sample document to put in the database
sample_account = {
    'username' : 'testuser',
    'email' : 'test@example.com',
    'password' : 'testuser',
    'profile_picture': 'placeholder.jpg'  # Added a placeholder
}

# Check if sample account exists and add it if it's not there
query = {
    'username' : 'testuser'
}
found_account = accounts.find_one(query)
if not found_account:
    # Hash the password for the sample account
    hash_object = hashlib.sha1(sample_account['password'].encode() + app.secret_key.encode())
    sample_account['password'] = hash_object.hexdigest()
    accounts.insert_one(sample_account)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# This route redirects the base URL to the login page
@app.route('/')
def root():
    return redirect(url_for('login'))

# localhost:5000/pythonlogin/ will be the login page which will use both GET and POST requests
@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password
        hash_object = hashlib.sha1(password.encode() + app.secret_key.encode())
        hashed_password = hash_object.hexdigest()

        query = {
            'username': username,
            'password': hashed_password
            }
        
        account = accounts.find_one(query)
        
        if account:
            session['loggedin'] = True
            session['username'] = account['username']
            session['id'] = str(account['_id'])
            return redirect(url_for('home'))
        else:
            msg = 'Incorrect username/password!'
            
    return render_template('index.html', msg=msg)

@app.route('/pythonlogin/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        query = {
            'username' : username
        }
        account = accounts.find_one(query)
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = "Invalid email address!"
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = "Username must contain only characters and numbers!"
        elif not username or not password or not email:
            msg = "Please fill out the form!"
        else:
            # Hash the password
            hash_object = hashlib.sha1(password.encode() + app.secret_key.encode())
            hashed_password = hash_object.hexdigest()

            accounts.insert_one(
                {
                    "username" : username,
                    "password" : hashed_password,
                    "email" : email,
                    "profile_picture": 'placeholder.jpg'
                }
            )
            msg = 'You have successfully registered!'
            return redirect(url_for('login'))
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
            
    return render_template('register.html', msg=msg)

@app.route('/pythonlogin/home')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/pythonlogin/profile')
def profile():
    if 'loggedin' in session:
        account = accounts.find_one({"_id": ObjectId(session['id'])})
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))

@app.route('/pythonlogin/profile_update', methods=['GET', 'POST'])
def profile_update():
    if 'loggedin' in session:
        msg = ''
        account = accounts.find_one({"_id": ObjectId(session['id'])})

        if request.method == 'POST':
            # Check if the post request has the file part
            if 'profile_picture' not in request.files:
                msg = 'No file part'
                return render_template('profile_update.html', msg=msg, account=account)
            file = request.files['profile_picture']
            
            # If the user does not select a file, the browser submits an empty file without a filename
            if file.filename == '':
                msg = 'No selected file'
                return render_template('profile_update.html', msg=msg, account=account)

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Save the file
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                # Update the profile picture path in the database
                accounts.update_one(
                    {"_id": ObjectId(session['id'])},
                    {"$set": {"profile_picture": filename}}
                )
                
                return redirect(url_for('profile'))
            else:
                msg = 'Invalid file type'

        return render_template('profile_update.html', msg=msg, account=account)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)

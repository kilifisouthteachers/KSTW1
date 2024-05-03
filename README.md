from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def index():
    return 'Welcome to KSTW Membership Registration!'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Handle form submission here
        pass
    else:
        # Render registration form
        return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Create a table for members if it doesn't exist
def create_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS members (
                        id INTEGER PRIMARY KEY,
                        name TEXT,
                        email TEXT UNIQUE,
                        password_hash TEXT
                    )''')
    conn.commit()
    conn.close()

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Registration code here...
    pass

# Login route (problematic function)
def login():
# ^ This line should be properly indented
    # Login code here...
    pass    
    
from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

login_manager = LoginManager()
login_manager.init_app(app)

# User class representing a member
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Function to load user from database
@login_manager.user_loader
def load_user(user_id):
    # Retrieve user from the database based on user_id
    # Replace this with your actual logic to load user from the database
    return User(user_id)

@app.route('/')
def index():
    return 'Welcome to KSTW Membership Registration!'

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Registration code goes here (as previously implemented)

   @app.route('/login', methods=['GET', 'POST'])
   @app.route('/logout')
   @login_required
   def login():
    return redirect(url_for('index'))
def loginout():
    if request.method == 'POST':
        # Authenticate user (you need to replace this with your actual authentication logic)
        user_id = authenticate_user(request.form['membership_number'], request.form['password']) # type: ignore
        if user_id:
            # Log user in and redirect to the home page
            user = User(user_id)
            login_user(user)
            return redirect(url_for('index'))
        else:
            # Invalid credentials, redirect back to login page
            return redirect(url_for('login'))
    else:
        # Render login form
        return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
    
from twilio.rest import Client
from flask import Flask

app = Flask(__name__)

# Twilio credentials
account_sid = 'ACf4de79b0b4a3ec11b43bd22f99d96bc9'
auth_token = 'ffa13db3d66bf27f37e85a232f3e83e6'
twilio_phone_number = 'your_twilio_phone_number'

# Initialize Twilio client
client = Client(account_sid, auth_token)

# Function to send SMS notification
def send_sms(to, body):
    message = client.messages.create(
        body=body,
        from_=twilio_phone_number,
        to=to
    )
    return message.sid

# Example route to send SMS notification
@app.route('/send-sms')
def send_sms_route():
    to = '+1234567890'  # Replace with recipient's phone number
    body = 'This is a test SMS notification from Twilio!'
    send_sms(to, body)
    return 'SMS notification sent successfully!'

if __name__ == '__main__':
    app.run(debug=True)
    
from twilio.rest import Client
from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

# Twilio credentials
account_sid = 'ACf4de79b0b4a3ec11b43bd22f99d96bc9'
auth_token = 'ffa13db3d66bf27f37e85a232f3e83e6'
twilio_phone_number = 'your_twilio_phone_number'

# Initialize Twilio client
client = Client(account_sid, auth_token)

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Function to send SMS notification
def send_sms(to, body):
    message = client.messages.create(
        body=body,
        from_=twilio_phone_number,
        to=to
    )
    return message.sid

# Other routes and login code (as previously implemented)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Registration code (as previously implemented)

        # Handle contribution
        handle_contribution(membership_number, amount) # type: ignore

        # Send SMS notification
        send_sms(phone, f"Thank you for registering with KSTW. Your membership number is {membership_number}.")  # type: ignore # Modify the message as needed

        return redirect(url_for('index'))  # Redirect to home page after registration
    else:
        # Render registration form
        return render_template('register.html')

# Contribution handling code (as previously implemented)

# Login and logout code (as previously implemented)

if __name__ == '__main__':
    app.run(debug=True)
    
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, send_file
import sqlite3

app = Flask(__name__)

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/generate-report')
@login_required
def generate_report():
    # Query database to retrieve member information and contributions
    conn = connect_db()
    df = pd.read_sql_query("SELECT * FROM members", conn)
    conn.close()

    # Export DataFrame to Excel
    excel_file = 'members_report.xlsx'
    df.to_excel(excel_file, index=False)

    # Send the Excel file as a response
    return send_file(excel_file, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/reset-password', methods=['GET', 'POST'])
@login_required
def reset_password():
    if request.method == 'POST':
        # Retrieve form data
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        # Verify current password
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM members WHERE id = ?", (current_user.id,)) # type: ignore
        result = cursor.fetchone()
        conn.close()

        if result and check_password_hash(result[0], current_password):
            # Hash and update new password
            hashed_password = generate_password_hash(new_password)
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute("UPDATE members SET password_hash = ? WHERE id = ?", (hashed_password, current_user.id)) # type: ignore
            conn.commit()
            conn.close()
            flash('Password reset successfully!', 'success')
        else:
            flash('Incorrect current password!', 'error')

        return redirect(url_for('reset_password'))
    else:
        return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from random import randint
from twilio.rest import Client
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Twilio credentials
account_sid = 'your_account_sid'
auth_token = 'your_auth_token'
twilio_phone_number = 'your_twilio_phone_number'

# Initialize Twilio client
client = Client(account_sid, auth_token)

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Retrieve phone number from form
        phone = request.form['phone']

        # Generate OTP
        otp = str(randint(1000, 9999))

        # Save OTP to session for verification
        session['reset_otp'] = otp # type: ignore

        # Send OTP via SMS
        send_sms(phone, f'Your OTP for password reset is: {otp}')

        flash('An OTP has been sent to your phone number for password reset.', 'info')
        return redirect(url_for('verify_otp'))
    else:
        return render_template('forgot_password.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        # Retrieve OTP from form
        otp = request.form['otp']

        # Verify OTP
        if 'reset_otp' in session and session['reset_otp'] == otp: # type: ignore
            # Password reset successful, redirect to reset password page
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
            return redirect(url_for('verify_otp'))
    else:
        return render_template('verify_otp.html')

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from random import randint
from twilio.rest import Client
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Twilio credentials
account_sid = 'your_account_sid'
auth_token = 'your_auth_token'
twilio_phone_number = 'your_twilio_phone_number'

# Initialize Twilio client
client = Client(account_sid, auth_token)

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Retrieve new password from form
        new_password = request.form['new_password']

        # Update password in database
        hashed_password = generate_password_hash(new_password)
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE members SET password_hash = ? WHERE phone_number = ?", (hashed_password, session['reset_phone']))
        conn.commit()
        conn.close()

        # Clear reset OTP and phone number from session
        session.pop('reset_otp', None)
        session.pop('reset_phone', None)

        flash('Password reset successfully!', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from random import randint
from twilio.rest import Client
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Twilio credentials
account_sid = 'your_account_sid'
auth_token = 'your_auth_token'
twilio_phone_number = 'your_twilio_phone_number'

# Initialize Twilio client
client = Client(account_sid, auth_token)

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Retrieve new password from form
        new_password = request.form['new_password']

        # Update password in database
        hashed_password = generate_password_hash(new_password)
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE members SET password_hash = ? WHERE phone_number = ?", (hashed_password, session['reset_phone']))
        conn.commit()
        conn.close()

        # Send confirmation SMS
        send_sms(session['reset_phone'], 'Your password has been successfully reset.')

        # Clear reset OTP and phone number from session
        session.pop('reset_otp', None)
        session.pop('reset_phone', None)

        flash('Password reset successfully! You will receive a confirmation SMS shortly.', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/profile')
@login_required
def profile():
    # Query database to retrieve member information
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name, institution, cluster, phone_number FROM members WHERE id = ?", (current_user.id,)) # type: ignore
    member_info = cursor.fetchone()
    conn.close()

    if member_info:
        return render_template('profile.html', member_info=member_info)
    else:
        flash('Failed to retrieve member information.', 'error')
        return redirect(url_for('index'))

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # Retrieve form data
        name = request.form['name']
        institution = request.form['institution']
        cluster = request.form['cluster']
        phone = request.form['phone']

        # Update member information in the database
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE members SET name = ?, institution = ?, cluster = ?, phone_number = ? WHERE id = ?", (name, institution, cluster, phone, current_user.id)) # type: ignore
        conn.commit()
        conn.close()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    else:
        # Query database to retrieve member information
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT name, institution, cluster, phone_number FROM members WHERE id = ?", (current_user.id,)) # type: ignore
        member_info = cursor.fetchone()
        conn.close()

        if member_info:
            return render_template('edit_profile.html', member_info=member_info)
        else:
            flash('Failed to retrieve member information.', 'error')
            return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    # Delete member account from the database
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM members WHERE id = ?", (current_user.id,)) # type: ignore
    conn.commit()
    conn.close()

    # Clear session and log out
    session.clear()
    flash('Your account has been deleted successfully.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Twilio credentials
account_sid = 'your_account_sid'
auth_token = 'your_auth_token'
twilio_phone_number = 'your_twilio_phone_number'

# Initialize Twilio client
client = Client(account_sid, auth_token)

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    # Delete member account from the database
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM members WHERE id = ?", (current_user.id,)) # type: ignore
    conn.commit()
    conn.close()

    # Send confirmation SMS
    send_sms(session['phone_number'], 'Your account has been successfully deleted.')

    # Clear session and log out
    session.clear()
    flash('Your account has been deleted successfully. You will receive a confirmation SMS shortly.', 'success')
    return redirect(url_for('index'))

def send_sms(to, body):
    message = client.messages.create(
        body=body,
        from_=twilio_phone_number,
        to=to
    )
    return message.sid

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Twilio credentials
account_sid = 'your_account_sid'
auth_token = 'your_auth_token'
twilio_phone_number = 'your_twilio_phone_number'

# Initialize Twilio client
client = Client(account_sid, auth_token)

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/contribute', methods=['POST'])
@login_required
def contribute():
    # Retrieve form data
    amount = request.form['amount']

    # Update amount contributed in the database
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE members SET amount_contributed = amount_contributed + ? WHERE id = ?", (amount, current_user.id)) # type: ignore
    conn.commit()

    # Send confirmation SMS
    send_sms(session['phone_number'], f'Thank you for your contribution of {amount} KSTW!')

    flash('Contribution successful! You will receive a confirmation SMS shortly.', 'success')
    return redirect(url_for('index'))

def send_sms(to, body):
    message = client.messages.create(
        body=body,
        from_=twilio_phone_number,
        to=to
    )
    return message.sid

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Twilio credentials
account_sid = 'your_account_sid'
auth_token = 'your_auth_token'
twilio_phone_number = 'your_twilio_phone_number'

# Initialize Twilio client
client = Client(account_sid, auth_token)

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/register', methods=['POST'])
def register():
    # Retrieve form data
    name = request.form['name']
    institution = request.form['institution']
    cluster = request.form['cluster']
    phone = request.form['phone']

    # Generate membership number
    # Code for generating membership number (e.g., incrementing from the last membership number) goes here

    # Save member information in the database
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO members (name, institution, cluster, phone_number) VALUES (?, ?, ?, ?)", (name, institution, cluster, phone))
    conn.commit()

    # Send confirmation SMS
    send_sms(phone, f'Thank you for registering with KSTW. Your membership number is {membership_number}.') # type: ignore

    flash('Registration successful! You will receive a confirmation SMS shortly.', 'success')
    return redirect(url_for('index'))

def send_sms(to, body):
    message = client.messages.create(
        body=body,
        from_=twilio_phone_number,
        to=to
    )
    return message.sid

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
import sqlite3
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Twilio credentials
account_sid = 'your_account_sid'
auth_token = 'your_auth_token'
twilio_phone_number = 'your_twilio_phone_number'

# Initialize Twilio client
client = Client(account_sid, auth_token)

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Function to generate membership number
def generate_membership_number():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM members")
    count = cursor.fetchone()[0]
    conn.close()
    year = datetime.date.today().year
    return f'KSTW{year}{count + 1:04d}'

# Other routes and login code (as previously implemented)

@app.route('/register', methods=['POST'])
def register():
    # Retrieve form data
    name = request.form['name']
    institution = request.form['institution']
    cluster = request.form['cluster']
    phone = request.form['phone']

    # Generate membership number
    membership_number = generate_membership_number()

    # Save member information in the database
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO members (name, institution, cluster, phone_number, membership_number) VALUES (?, ?, ?, ?, ?)", (name, institution, cluster, phone, membership_number))
    conn.commit()

    # Send confirmation SMS
    send_sms(phone, f'Thank you for registering with KSTW. Your membership number is {membership_number}.')

    flash('Registration successful! You will receive a confirmation SMS shortly.', 'success')
    return redirect(url_for('index'))

def send_sms(to, body):
    message = client.messages.create(
        body=body,
        from_=twilio_phone_number,
        to=to
    )
    return message.sid

if __name__ == '__main__':
    app.run(debug=True)
    
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and login code (as previously implemented)

@app.route('/generate-report')
@login_required
def generate_report():
    # Query database to retrieve member information and contributions
    conn = connect_db()
    df = pd.read_sql_query("SELECT membership_number, name, institution, cluster, amount_contributed FROM members", conn)
    conn.close()

    # Export DataFrame to the desired format (Excel, Google Sheets, or PDF)
    report_file = 'members_report.xlsx'  # Change file extension based on desired format

    # For Excel format
    df.to_excel(report_file, index=False)

    # For Google Sheets format
    # df.to_csv(report_file, index=False)

    # For PDF format
    # df.to_pdf(report_file)

    # Send the file as a response
    return send_file(report_file, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and functions (as previously implemented)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve username (membership number) and password from form
        username = request.form['username']
        password = request.form['password']

        # Query database to retrieve password hash for the given username
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM members WHERE membership_number = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and check_password_hash(result[0], password):
            # Authentication successful, set session variables and redirect to dashboard
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Authentication failed, display error message
            flash('Invalid username or password. Please try again.', 'error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Render the dashboard template
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and functions (as previously implemented)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve registration form data
        name = request.form['name']
        institution = request.form['institution']
        cluster = request.form['cluster']
        phone = request.form['phone']
        password = request.form['password']

        # Hash the password for security
        hashed_password = generate_password_hash(password)

        # Save member information to the database
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO members (name, institution, cluster, phone_number, password_hash) VALUES (?, ?, ?, ?, ?)", (name, institution, cluster, phone, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
    
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You need to log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Other routes and functions (as previously implemented)

@app.route('/dashboard')
@login_required
def dashboard():
    # Render the dashboard template
    return render_template('dashboard.html')

@app.route('/contribute')
@login_required
def contribute():
    # Render the contribution page
    return render_template('contribute.html')

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Other routes and functions (as previously implemented)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve registration form data
        username = request.form['username']
        password = request.form['password']

        # Hash the password for security
        hashed_password = generate_password_hash(password)

        # Save username and hashed password to the database
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve login form data
        username = request.form['username']
        password = request.form['password']

        # Query the database to retrieve the hashed password for the given username
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and check_password_hash(result[0], password):
            # Password is correct, set session variable and redirect to dashboard
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Incorrect username or password, display error message
            flash('Incorrect username or password. Please try again.', 'error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve registration form data
        username = request.form['username']
        password = request.form['password']

        # Save username and password to the database (you may need to create the table 'users' in your database)
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve login form data
        username = request.form['username']
        password = request.form['password']

        # Check if the username and password match what's stored in the database (you may need to adjust this query based on your database structure)
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Store the username in the session to keep the user logged in
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')

# Dashboard route (requires login)
@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in (you may want to move this check to a decorator for better reusability)
    if 'username' in session:
        return render_template('dashboard.html')
    else:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    # Clear the session to log the user out
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Create table for members if it doesn't exist
def create_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS members (
                        id INTEGER PRIMARY KEY,
                        name TEXT,
                        institution TEXT,
                        cluster TEXT,
                        phone_number TEXT,
                        membership_number TEXT UNIQUE
                    )''')
    conn.commit()
    conn.close()

# Registration route
@app.route('/register', methods=['POST'])
def register():
    # Retrieve registration form data
    name = request.form['name']
    institution = request.form['institution']
    cluster = request.form['cluster']
    phone_number = request.form['phone_number']

    # Generate membership number (you can implement your own logic here)
    membership_number = 'KSTW0001'  # Example membership number

    # Insert member data into the database
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO members (name, institution, cluster, phone_number, membership_number) VALUES (?, ?, ?, ?, ?)",
                   (name, institution, cluster, phone_number, membership_number))
    conn.commit()
    conn.close()

    flash('Registration successful! Your membership number is ' + membership_number, 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    create_table()  # Create members table when the application starts
    app.run(debug=True)
    
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Create a table for members if it doesn't exist
def create_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS members (
                        id INTEGER PRIMARY KEY,
                        name TEXT,
                        email TEXT UNIQUE,
                        password_hash TEXT
                    )''')
    conn.commit()
    conn.close()

# Registration route (unchanged)
# Login route (unchanged)
# Logout route (unchanged)
# Dashboard route (unchanged)
# Function decorator (unchanged)

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Hash the password before storing it in the database
        password_hash = generate_password_hash(password)

        # Store the user's information in the database
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO members (name, email, password_hash) VALUES (?, ?, ?)", (name, email, password_hash))
        conn.commit()
        conn.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('register.html')

if __name__ == '__main__':
    create_table()  # Create members table when the application starts
    app.run(debug=True)
    
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for session security

# Database connection function
def connect_db():
    return sqlite3.connect('members.db')

# Create a table for members if it doesn't exist
def create_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS members (
                        id INTEGER PRIMARY KEY,
                        name TEXT,
                        email TEXT UNIQUE,
                        password_hash TEXT
                    )''')
    conn.commit()
    conn.close()

# Registration route (unchanged)
# Login route (unchanged)

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# Dashboard route (protected)
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        # User is logged in, render the dashboard
        return render_template('dashboard.html')
    else:
        # User is not logged in, redirect to login page
        flash('You must be logged in to access the dashboard.', 'error')
        return redirect(url_for('login'))

# Function decorator (unchanged)

if __name__ == '__main__':
    create_table()  # Create members table when the application starts
    app.run(debug=True)                                                        

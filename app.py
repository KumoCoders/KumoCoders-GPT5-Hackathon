from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import os
import openai
import firebase_admin
from firebase_admin import credentials, firestore, auth
from dotenv import load_dotenv
import json
import logging
from functools import wraps
from werkzeug.exceptions import HTTPException
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key-for-development-only")

# Initialize OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")

# Initialize Firebase with error handling
db = None
try:
    cred_path = os.getenv("FIREBASE_CREDENTIALS_PATH")
    if not cred_path:
        logger.warning("FIREBASE_CREDENTIALS_PATH not set, running without Firebase")
    elif not os.path.exists(cred_path):
        logger.error(f"Firebase credentials file not found at: {cred_path}")
    else:
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        logger.info("Firebase initialized successfully")
except Exception as e:
    logger.error(f"Firebase initialization failed: {str(e)}")

# -----------------------------
# AUTHENTICATION DECORATOR
# -----------------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------

def get_user_profile(user_id):
    """Safely retrieve user profile from Firestore"""
    if not db:
        return {}
    try:
        profile_ref = db.collection('profiles').document(user_id)
        profile_doc = profile_ref.get()
        if profile_doc.exists:
            return profile_doc.to_dict()
        return {}
    except Exception as e:
        logger.error(f"Error retrieving user profile: {str(e)}")
        return {}

def save_user_profile(user_id, profile_data):
    """Safely save user profile to Firestore"""
    if not db:
        return False
    try:
        db.collection('profiles').document(user_id).set(profile_data)
        return True
    except Exception as e:
        logger.error(f"Error saving user profile: {str(e)}")
        return False

# -----------------------------
# ROUTES
# -----------------------------

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Firebase web configuration
    firebase_config = {
        'apiKey': os.getenv("FIREBASE_API_KEY", ""),
        'authDomain': os.getenv("FIREBASE_AUTH_DOMAIN", ""),
        'projectId': os.getenv("FIREBASE_PROJECT_ID", ""),
        'storageBucket': os.getenv("FIREBASE_STORAGE_BUCKET", ""),
        'messagingSenderId': os.getenv("FIREBASE_MESSAGING_SENDER_ID", ""),
        'appId': os.getenv("FIREBASE_APP_ID", "")
    }
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            session['user'] = user['idToken']
            flash("Successfully logged in!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Login failed: {error_msg}")
            flash("Invalid email or password. Please try again.", "danger")
            return render_template('login.html', firebase_config=json.dumps(firebase_config) if firebase_config['apiKey'] else None)
    
    # Only pass config if it has valid values
    if firebase_config['apiKey'] and len(firebase_config['apiKey']) > 20:
        return render_template('login.html', firebase_config=json.dumps(firebase_config))
    else:
        return render_template('login.html', firebase_config=None)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Firebase web configuration
    firebase_config = {
        'apiKey': os.getenv("FIREBASE_API_KEY", ""),
        'authDomain': os.getenv("FIREBASE_AUTH_DOMAIN", ""),
        'projectId': os.getenv("FIREBASE_PROJECT_ID", ""),
        'storageBucket': os.getenv("FIREBASE_STORAGE_BUCKET", ""),
        'messagingSenderId': os.getenv("FIREBASE_MESSAGING_SENDER_ID", ""),
        'appId': os.getenv("FIREBASE_APP_ID", "")
    }

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            user = auth.create_user_with_email_and_password(email, password)
            session['user'] = user['idToken']
            flash("Account created successfully! Please complete your profile.", "success")
            return redirect(url_for('onboard'))
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Signup failed: {error_msg}")
            flash("Signup failed. Please try again with a different email.", "danger")
            return render_template('signup.html', firebase_config=json.dumps(firebase_config) if firebase_config['apiKey'] else None)

    # Only pass config if it has valid values
    if firebase_config['apiKey'] and len(firebase_config['apiKey']) > 20:
        return render_template('signup.html', firebase_config=json.dumps(firebase_config))
    else:
        return render_template('signup.html', firebase_config=None)

@app.route('/phone-signup', methods=['GET', 'POST'])
def phone_signup():
    if request.method == 'POST':
        # Handle phone signup logic here
        return redirect(url_for('onboard'))
    
    return render_template('phone_signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("You have been successfully logged out.", "info")
    return redirect(url_for('index'))

@app.route('/onboard', methods=['GET', 'POST'])
@login_required
def onboard():
    if request.method == 'POST':
        # Save profile to Firestore
        try:
            user_id = auth.get_account_info(session['user'])['users'][0]['localId']
            profile = {
                'skill_level': request.form['skill_level'],
                'resource_preference': request.form['resource_preference'],
                'learning_goal': request.form['learning_goal']
            }
            if save_user_profile(user_id, profile):
                flash("Profile saved successfully!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Failed to save profile. Please try again.", "danger")
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Onboarding failed: {error_msg}")
            flash("Onboarding failed. Please try again.", "danger")

    return render_template('onboard.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user_id = auth.get_account_info(session['user'])['users'][0]['localId']
        profile = get_user_profile(user_id)
        return render_template('dashboard.html', profile=profile)
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Dashboard loading failed: {error_msg}")
        flash("Failed to load dashboard. Please try again.", "danger")
        return render_template('dashboard.html', profile={})

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    try:
        user_id = auth.get_account_info(session['user'])['users'][0]['localId']
        profile = get_user_profile(user_id)

        if request.method == 'POST':
            user_input = request.form['message']
            context = f"You are an AI tutor for a {profile.get('skill_level', 'beginner')} learning {profile.get('learning_goal', 'programming')}. They prefer {profile.get('resource_preference', 'varied')} resources."

            # Call OpenAI
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",  # or "gpt-5" if available
                messages=[
                    {"role": "system", "content": context},
                    {"role": "user", "content": user_input}
                ]
            )
            ai_reply = response['choices'][0]['message']['content']

            # Save chat to Firestore
            if db:
                db.collection('chat_history').add({
                    'user_id': user_id,
                    'user_message': user_input,
                    'ai_reply': ai_reply,
                    'timestamp': firestore.SERVER_TIMESTAMP
                })

            return jsonify({'reply': ai_reply})

        # Load chat history
        history = []
        if db:
            chats = db.collection('chat_history').where('user_id', '==', user_id).order_by('timestamp').stream()
            history = [(chat.to_dict()['user_message'], chat.to_dict()['ai_reply']) for chat in chats]

        return render_template('chat.html', history=history)
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Chat failed: {error_msg}")
        flash("Chat service is currently unavailable. Please try again later.", "danger")
        return render_template('chat.html', history=[])

@app.route('/debug', methods=['GET', 'POST'])
@login_required
def debug():
    result = None
    if request.method == 'POST':
        code = request.form['code']
        prompt = f"Find the bug in this Python code and explain how to fix it:\n\n{code}"

        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}]
            )
            result = response['choices'][0]['message']['content']
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Debug failed: {error_msg}")
            result = f"Debug service is currently unavailable: {error_msg}"
            flash("Debug service is temporarily unavailable. Please try again later.", "danger")

    return render_template('debug.html', result=result)

@app.route('/challenges')
@login_required
def challenges():
    try:
        user_id = auth.get_account_info(session['user'])['users'][0]['localId']
        profile = get_user_profile(user_id)

        prompt = f"Create a {profile.get('skill_level', 'beginner')}-level coding challenge about Python. Include one hint and a sample solution."

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        challenge_text = response['choices'][0]['message']['content']

        return render_template('challenges.html', challenge=challenge_text)
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Challenges failed: {error_msg}")
        flash("Challenge service is temporarily unavailable. Please try again later.", "danger")
        return render_template('challenges.html', challenge="Challenge service is currently unavailable.")

@app.route('/progress')
@login_required
def progress():
    try:
        user_id = auth.get_account_info(session['user'])['users'][0]['localId']
        progress_data = get_user_profile(user_id) or {}

        return render_template('progress.html', progress=progress_data)
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Progress failed: {error_msg}")
        flash("Failed to load progress data. Please try again later.", "danger")
        return render_template('progress.html', progress={})

# -----------------------------
# NEW ROUTES FOR NAVBAR/FOOTER LINKS
# -----------------------------

@app.route('/profile')
@login_required
def profile():
    try:
        user_id = auth.get_account_info(session['user'])['users'][0]['localId']
        profile = get_user_profile(user_id)
        return render_template('profile.html', profile=profile)
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Profile failed: {error_msg}")
        flash("Failed to load profile. Please try again later.", "danger")
        return render_template('profile.html', profile={})

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/testimonials')
def testimonials():
    return render_template('testimonials.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/cookie-policy')
def cookie_policy():
    return render_template('cookie-policy.html')

# -----------------------------
# ERROR HANDLERS
# -----------------------------

@app.errorhandler(400)
def bad_request(error):
    return render_template('errors/400.html'), 400

@app.errorhandler(401)
def unauthorized(error):
    return render_template('errors/401.html'), 401

@app.errorhandler(403)
def forbidden(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('errors/405.html'), 405

@app.errorhandler(429)
def too_many_requests(error):
    return render_template('errors/429.html'), 429

# @app.errorhandler(500)
# def internal_error(error):
#     app.logger.error(f"Server Error: {error}")
#     return render_template('errors/500.html'), 500

@app.errorhandler(502)
def bad_gateway(error):
    return render_template('errors/502.html'), 502

@app.errorhandler(503)
def service_unavailable(error):
    return render_template('errors/503.html'), 503

@app.errorhandler(504)
def gateway_timeout(error):
    return render_template('errors/504.html'), 504

# Generic error handler for all other exceptions
@app.errorhandler(Exception)
def handle_exception(e):
    # Pass through HTTP errors
    if isinstance(e, HTTPException):
        return e
    
    # Log the error
    app.logger.error(f"Unhandled Exception: {e}")
    app.logger.error(traceback.format_exc())
    
    # Return 500 error page for all other errors
    return render_template('errors/500.html'), 500

# -----------------------------
# RUN APP
# -----------------------------
if __name__ == '__main__':
    
    # Check environment variables
    required_vars = [
        "SECRET_KEY",
        "OPENAI_API_KEY"
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("WARNING: Missing environment variables:")
        for var in missing_vars:
            print(f"  - {var}")
        print("Please check your .env file")
    
    # Run the app
    app.run(host='0.0.0.0', port=80, debug=True)
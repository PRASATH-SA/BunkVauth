import os
import json
import base64
import time
import math
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from fido2 import cbor
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, AuthenticatorSelectionCriteria, UserVerificationRequirement, RegistrationResponse, AuthenticationResponse, webauthn_json_mapping, Aaguid, AttestedCredentialData, PublicKeyCredentialDescriptor, PublicKeyCredentialType
webauthn_json_mapping.enabled = True
from fido2.cose import CoseKey
from fido2.utils import websafe_decode, websafe_encode
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///bunkvauth.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# --- FIDO2 Configuration ---
RP_ID = "localhost"
RP_NAME = "BunkVauth"
# List of allowed origins for development
ALLOWED_ORIGINS = ["http://localhost:5000", "http://127.0.0.1:5000"]

rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
# Initialize server with a permissive origin validator for development
server = Fido2Server(rp, verify_origin=lambda x: True)

# --- Helper Functions ---
def encode_base64(data):
    return websafe_encode(data)

def decode_base64(data):
    return websafe_decode(data)

# --- Database Models ---

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    credentials = db.relationship('Credential', backref='user', lazy=True)
    profile = db.relationship('BehavioralProfile', backref='user', uselist=False)

class Credential(db.Model):
    __tablename__ = 'credentials'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    credential_id = db.Column(db.LargeBinary, unique=True, nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)

class BehavioralProfile(db.Model):
    __tablename__ = 'behavioral_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    baseline_features = db.Column(db.Text) # JSON string of averaged features
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class BehavioralEvent(db.Model):
    __tablename__ = 'behavioral_events'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_type = db.Column(db.String(50))
    features = db.Column(db.Text) # JSON string
    risk_score = db.Column(db.Float, default=0.0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AuthSession(db.Model):
    __tablename__ = 'auth_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True)
    risk_score = db.Column(db.Float, default=0.0)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

import pickle

@app.route('/register/begin', methods=['POST'])
def register_begin():
    try:
        username = request.json.get('username')
        if not username:
            return jsonify({'error': 'Username required'}), 400
        
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        
        options, state = server.register_begin(
            {
                'id': str(user.id).encode(),
                'name': user.username,
                'displayName': user.username,
            },
            [PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, c.credential_id) for c in user.credentials],
            user_verification=UserVerificationRequirement.PREFERRED
        )

        # Manual serialization to avoid circular references
        serializable_options = {
            'challenge': encode_base64(options.public_key.challenge),
            'rp': {'id': options.public_key.rp.id, 'name': options.public_key.rp.name},
            'user': {
                'id': encode_base64(options.public_key.user.id),
                'name': options.public_key.user.name,
                'displayName': options.public_key.user.display_name
            },
            'pubKeyCredParams': [{'type': p.type.value if hasattr(p.type, 'value') else str(p.type), 'alg': p.alg} for p in options.public_key.pub_key_cred_params],
            'timeout': options.public_key.timeout,
            'excludeCredentials': [{'type': c.type.value if hasattr(c.type, 'value') else str(c.type), 'id': encode_base64(c.id)} for c in (options.public_key.exclude_credentials or [])],
            'attestation': options.public_key.attestation.value if hasattr(options.public_key.attestation, 'value') else (options.public_key.attestation or 'none'),
            'authenticatorSelection': {
                'userVerification': options.public_key.authenticator_selection.user_verification.value if hasattr(options.public_key.authenticator_selection.user_verification, 'value') else 'preferred',
                'residentKey': options.public_key.authenticator_selection.resident_key.value if hasattr(options.public_key.authenticator_selection.resident_key, 'value') else 'discouraged',
                'requireResidentKey': options.public_key.authenticator_selection.require_resident_key if options.public_key.authenticator_selection else False
            }
        }
        
        # Robustly serialize state object for session
        session['fido_state'] = base64.b64encode(pickle.dumps(state)).decode('utf-8')
        session['register_username'] = username
        
        return jsonify(serializable_options)
    except Exception as e:
        import traceback
        traceback.print_exc() # Print to server logs
        return jsonify({'error': str(e)}), 500

@app.route('/register/complete', methods=['POST'])
def register_complete():
    try:
        username = session.get('register_username')
        state_b64 = session.get('fido_state')
        if not username or not state_b64:
            return jsonify({'error': 'Session expired'}), 400
        
        state = pickle.loads(base64.b64decode(state_b64))
        user = User.query.filter_by(username=username).first()
        
        reg_response = RegistrationResponse.from_dict(request.json)
        auth_data = server.register_complete(state, reg_response)
        new_cred = Credential(
            user_id=user.id,
            credential_id=auth_data.credential_data.credential_id,
            public_key=cbor.encode(auth_data.credential_data.public_key),
            sign_count=auth_data.counter
        )
        db.session.add(new_cred)
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 400

@app.route('/login/begin', methods=['POST'])
def login_begin():
    try:
        username = request.json.get('username')
        user = User.query.filter_by(username=username).first()
        if not user or not user.credentials:
            return jsonify({'error': 'User not found or no credentials registered'}), 404
        
        options, state = server.authenticate_begin(
            [PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, c.credential_id) for c in user.credentials],
            user_verification=UserVerificationRequirement.PREFERRED
        )
        
        serializable_options = {
            'challenge': encode_base64(options.public_key.challenge),
            'rpId': options.public_key.rp_id,
            'allowCredentials': [{'type': c.type.value if hasattr(c.type, 'value') else str(c.type), 'id': encode_base64(c.id)} for c in options.public_key.allow_credentials],
            'userVerification': options.public_key.user_verification.value if hasattr(options.public_key.user_verification, 'value') else 'preferred',
            'timeout': options.public_key.timeout
        }
        
        session['fido_state'] = base64.b64encode(pickle.dumps(state)).decode('utf-8')
        session['login_username'] = username
        
        return jsonify(serializable_options)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/login/complete', methods=['POST'])
def login_complete():
    try:
        username = session.get('login_username')
        state_b64 = session.get('fido_state')
        if not username or not state_b64:
            return jsonify({'error': 'Session expired'}), 400
        
        state = pickle.loads(base64.b64decode(state_b64))
        user = User.query.filter_by(username=username).first()
        
        # In newer fido2, authenticate_complete handles the verification
        auth_response = AuthenticationResponse.from_dict(request.json)
        # Load credentials as AttestedCredentialData objects for fido2
        user_creds = [AttestedCredentialData.create(Aaguid.NONE, c.credential_id, CoseKey.parse(cbor.decode(c.public_key))) for c in user.credentials]
        
        server.authenticate_complete(state, user_creds, auth_response)
        
        # Update sign count
        credential_id = auth_response.id
        matching_cred = next(c for c in user.credentials if c.credential_id == credential_id)
        matching_cred.sign_count = auth_response.response.authenticator_data.counter
        matching_cred.last_used = datetime.utcnow()
        db.session.commit()
        login_user(user)
        return jsonify({'status': 'success'})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 400

import joblib
import pandas as pd

# Load ML Model
MODEL_PATH = 'models/bunkvauth_model.joblib'
ml_model = None
if os.path.exists(MODEL_PATH):
    try:
        ml_model = joblib.load(MODEL_PATH)
        print("ML Behavioral Model loaded successfully.")
    except Exception as e:
        print(f"Failed to load ML model: {e}")

@app.route('/behavioral/analyze', methods=['POST'])
@login_required
def behavioral_analyze():
    features = request.json
    user_id = current_user.id
    
    # --- Distance-Based Scoring (Baseline) ---
    profile = BehavioralProfile.query.filter_by(user_id=user_id).first()
    dist_risk = 0.0
    
    if not profile or not profile.baseline_features:
        new_profile = profile or BehavioralProfile(user_id=user_id)
        new_profile.baseline_features = json.dumps(features)
        new_profile.updated_at = datetime.utcnow()
        if not profile: db.session.add(new_profile)
        db.session.commit()
        return jsonify({'risk_score': 0.0, 'action': 'continue'})

    baseline = json.loads(profile.baseline_features)
    keys = ['avg_dwell_time', 'std_dwell_time', 'avg_flight_time', 'std_flight_time', 'typing_speed', 'avg_mouse_speed']
    
    distance = 0
    for key in keys:
        b_val = baseline.get(key, 0)
        f_val = features.get(key, 0)
        if b_val != 0:
            distance += math.pow((f_val - b_val) / b_val, 2)
    dist_risk = math.sqrt(distance) * 2

    # --- ML-Based Scoring (Optional) ---
    ml_risk = 0.0
    if ml_model:
        try:
            # Prepare data for prediction
            feat_df = pd.DataFrame([features])[keys]
            # Probabilities for all users
            probs = ml_model.predict_proba(feat_df)[0]
            # In a real app, we'd map user_id to model index. 
            # Here we check the max probability as a proxy for "confidence in current user"
            max_prob = max(probs)
            ml_risk = (1 - max_prob) * 10 # High risk if low confidence
        except Exception as e:
            print(f"ML Prediction failed: {e}")

    # Final weighted risk score
    final_risk = (dist_risk * 0.7) + (ml_risk * 0.3)
    final_risk = min(max(final_risk, 0.0), 10.0)

    action = "continue"
    if final_risk > 7.0: action = "terminate"
    elif final_risk > 4.0: action = "step_up"
    
    # Log and update baseline
    event = BehavioralEvent(user_id=user_id, features=json.dumps(features), risk_score=final_risk)
    db.session.add(event)
    
    alpha = 0.1
    new_baseline = {k: (baseline.get(k, 0)*(1-alpha)) + (features.get(k, 0)*alpha) for k in keys}
    profile.baseline_features = json.dumps(new_baseline)
    db.session.commit()
    
    return jsonify({'risk_score': final_risk, 'action': action})

@app.route('/behavioral/risk', methods=['GET'])
@login_required
def get_risk():
    last_event = BehavioralEvent.query.filter_by(user_id=current_user.id).order_by(BehavioralEvent.timestamp.desc()).first()
    score = last_event.risk_score if last_event else 0.0
    return jsonify({'risk_score': score})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)

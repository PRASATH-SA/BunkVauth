# BunkVauth: Hybrid Biometric-Behavioral Auth

BunkVauth is a zero-trust authentication system that combines **FIDO2/WebAuthn** (something you are - biometrics) with **Continuous Behavioral Verification** (how you behave - keystrokes and mouse dynamics).

## Features
- **FIDO2 Passwordless Login**: Use fingerprint or security keys via WebAuthn.
- **AI Behavioral Profiling**: Monitors typing rhythm and mouse precision.
- **Real-time Risk Scoring**: Dynamically calculates session risk using Euclidean distance and Random Forest classification.
- **Session Continuity**: Terminate sessions automatically if behavioral anomalies are detected.

## Tech Stack
- **Backend**: Python (Flask, SQLAlchemy, python-fido2)
- **Frontend**: Vanilla JS, WebAuthn API
- **Machine Learning**: Scikit-Learn (Random Forest)
- **Database**: SQLite

## Setup Instructions
1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Train the ML Model**:
   ```bash
   python ml_train.py
   ```
3. **Run the Application**:
   ```bash
   python app.py
   ```
4. **Access**: Open `http://localhost:5000` in a browser that supports WebAuthn (Chrome, Edge, Safari).

## Testing Steps
1. Enter a username and click **Register Device**. Follow browser prompts for fingerprint/PIN.
2. Click **Login** to enter the dashboard.
3. Observe the **Risk Level** on the dashboard.
4. Try typing at different speeds or using your mouse erratically to see the risk score update.
5. If the risk score exceeds 7.0, the session will automatically terminate for security.

## ML Evaluation Results (Synthetic)
Based on `ml_train.py` output:
- **Accuracy**: ~69-98% (varies by synthetic distribution)
- **Top Features**: Typing Speed, Avg Flight Time, Avg Mouse Speed.
- **FAR/FRR**: Optimized for low False Acceptance Rate to prevent unauthorized access.

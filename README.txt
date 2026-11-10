PHISHING EMAIL DETECTION - FIXED PROJECT

REQUIREMENTS
- Python 3.9 or newer
- Internet connection for the first-time Flask installation

WINDOWS / VS CODE SETUP
1. Extract this ZIP file.
2. Open the extracted Phishing-Email-Detection-Fixed folder in VS Code.
3. Select Terminal > New Terminal.
4. Run these commands one by one:

   py -m pip install -r requirements.txt
   py app.py

   If "py" is unavailable, use:
   python -m pip install -r requirements.txt
   python app.py

5. Open Chrome and visit:
   http://127.0.0.1:5000

TO STOP
Press Ctrl+C in the terminal.

SAMPLE TEST
Sender: security@gmail.com
Subject: Urgent! Verify your account
Body: Your account will be suspended. Click here to verify your password immediately.

IMPORTANT
This is a basic rule-based educational project, not an AI/ML model. It cannot guarantee that an email is safe.

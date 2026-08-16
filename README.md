# PhishGuard 🔐


PhishGuard is a phishing link risk analyzer that checks URLs for suspicious patterns and combines local URL analysis with VirusTotal threat intelligence to provide a risk score.


## Features


- URL risk analysis
- HTTPS check
- IP address detection
- Suspicious keyword detection
- URL length analysis
- Suspicious URL pattern detection
- VirusTotal threat intelligence
- Final risk score
- Low, Medium and High risk classification
- Scan history
- Security dashboard
- SQLite database for storing scan results


## Tech Stack


- Python
- Flask
- HTML
- CSS
- SQLite
- VirusTotal API


## How It Works


```text
User enters URL
       ↓
Flask Backend
       ↓
Local URL Analysis
       ↓
VirusTotal Scan
       ↓
Risk Score Calculation
       ↓
Final Result
       ↓
Database
```

## Project Structure

PhishGuard/
│
├── app.py
├── analyzer.py
├── threat_api.py
├── database.py
├── test_api.py
├── requirements.txt
├── .gitignore
├── README.md
│
├── templates/
│   ├── index.html
│   ├── result.html
│   ├── history.html
│   └── dashboard.html
│
└── static/
    └── style.css

## Installation

git clone https://github.com/Suryansh971/PhishGuard.git

cd PhishGuard

python -m venv venv

venv\Scripts\activate

pip install -r requirements.txt

## API Setup

PhishGuard uses the VirusTotal API for threat intelligence.

Create a .env file in the project root:

THREAT_API_KEY=your_api_key_here

Do not share or upload your API key.

## Run the Project

python app.py

Open the application in your browser:

http://127.0.0.1:5000

## Main Pages

URL Analyzer

Enter a URL and analyze its security risk.

Scan History

View previously analyzed URLs along with their risk scores and scan times.

Dashboard

View overall scan statistics including total scans, high-risk scans, medium-risk scans, low-risk scans and malicious detections.

Risk Analysis

PhishGuard combines locally detected URL indicators with VirusTotal analysis to calculate a custom risk score.

The score is intended as a security indicator and should not be treated as a guaranteed determination that a URL is malicious.

## Future Improvements

User authentication
Improved URL analysis
Domain age and WHOIS checks
Additional threat intelligence sources
Improved risk scoring
Exportable scan reports
Detailed security explanations
Real-time URL monitoring

## Author

Suryansh

GitHub: https://github.com/Suryansh971/PhishGuard

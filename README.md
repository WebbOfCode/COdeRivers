# 🌊 COdeRivers – Phishing URL Detector

COdeRivers is a database-driven tool for detecting potentially malicious URLs.  
It uses a Python FastAPI backend with simple heuristics to analyze links, stores results in MySQL, and provides an API for querying verdicts.

---

## 🚀 Features (current milestone)
- ✅ FastAPI app with `/check` endpoint
- ✅ Heuristic URL scoring (dots in host, suspicious TLDs, IP in domain, etc.)
- ✅ MySQL schema to store:
  - URLs
  - Scan results (verdict, score, reason)
  - Extracted features
- ✅ Environment variables for database config

---

## 📂 Project Structure
COdeRivers/
│ README.md
│ requirements.txt
│ .env.example
│ .gitignore
│
├───db
│ schema.sql # database tables
│ seed.sql # optional test data
│
├───src
│ │ app.py # FastAPI entrypoint
│ │ init.py
│ └───url_checks
│ heuristics.py # scoring logic
│ init.py
│
├───scripts
│ run_api.ps1 # helper script (PowerShell)
│
├───tests # future unit tests
│
├───docs # design notes, slides, diagrams
└───notebooks # data experiments

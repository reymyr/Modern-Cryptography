@ECHO OFF
CALL venv\Scripts\activate
explorer "http://localhost:5000"
python app.py

PAUSE
@echo off
echo Starting FastAPI Backend...
start cmd /k ".\venv\Scripts\activate && uvicorn dbapp.main:app --host 127.0.0.1 --port 8000 --reload"

echo Starting Frontend on port 5500...
start cmd /k "python -m http.server 5500"

echo =======================================
echo.
echo Project is running in new windows!
echo Backend API is at http://127.0.0.1:8000
echo Frontend is at http://127.0.0.1:5500/
echo.
echo Please open http://127.0.0.1:5500/ in your browser.
echo =======================================

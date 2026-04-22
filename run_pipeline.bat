run_pipeline.bat

@echo off

REM ---- Project root ----
cd /d C:\Users\Chandan\Threat-Intelligence-Tool

REM ---- Activate venv ----
call .venv\Scripts\activate.bat

REM ---- Make project root visible to Python ----
set PYTHONPATH=C:\Users\Chandan\Threat-Intelligence-Tool

REM ---- Run pipeline ----
python dbapp\api_json\run_pipeline.py >> pipeline.log 2>&1
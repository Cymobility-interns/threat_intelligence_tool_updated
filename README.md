# 🛡️ Threat Intelligence Tool

<p align="center">
  <img src="https://img.shields.io/badge/Frontend-HTML%20%7C%20Vanilla%20JS-F16529?style=for-the-badge&logo=html5&logoColor=white" alt="Frontend">
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Database-SQLAlchemy-4479A1?style=for-the-badge&logo=mysql&logoColor=white" alt="Database">
  <img src="https://img.shields.io/badge/AI-Grok%20INTEGRATED-111111?style=for-the-badge&logo=x&logoColor=white" alt="AI">
</p>

A full-stack, end-to-end **Threat Intelligence** application designed specifically for tracking, categorizing, and visualizing continuous automotive and IoT vulnerabilities. The project serves as an aggregator, utilizing a scheduled AI pipeline to ingest live security intelligence (CVEs and non-CVEs) and render the analytics on a swift, modern dashboard.

---

## 📑 Table of Contents
1. [Features](#-features)
2. [Tech Stack](#️-tech-stack)
3. [Architecture & Folder Structure](#-architecture--folder-structure)
4. [Component Deep Dive](#-component-deep-dive)
5. [Database Schema Map](#-database-schema-map)
6. [Getting Started (Local Execution)](#️-getting-started-local-execution)
7. [The AI Ingestion Pipeline](#-the-ai-ingestion-pipeline)
8. [API Reference](#-api-reference-endpoints)
9. [Troubleshooting & Developer Notes](#-troubleshooting--developer-notes)

---

## 🚀 Features

- **Automated Intelligence Pipeline**: Background scripts (`run_pipeline.py`) integrated with the Grok API efficiently scrape, ingest, and dissect unstructured cyber intelligence data into robust localized database formats.
- **Interactive Dashboard & Ledger**: A modern HTML5 dashboard leveraging **Chart.js** locally categorizes data by *Interface* (CAN, Wi-Fi, Ethernet), *ECU Context*, and *Protocol Configuration*, turning thousands of threat lines into readable graphics.
- **Lightning-Fast API Engine**: A **FastAPI** backbone queries massive SQL states instantly. Capable of processing RegEx boundary logic precisely targeted for edge-case query searches (e.g., distinguishing real "CAN" protocol threats from "ZDI-CAN" artifact text).
- **Tabular Data Viewing**: Detailed supplier/Tier 1 and brand-associated logs accessible across the `tier1.html`, `company.html`, and `ledger.html` views.
- **Secure Authentication**: Built-in HTTP-only session management routing, with Passlib (Bcrypt) utilized for strict password hashing protocols.

---

## 🛠️ Tech Stack

### 🎨 Frontend
- **Languages:** HTML5, Vanilla JavaScript (ES Module-Based UI Structure), CSS3
- **Styling:** Bootstrap 5.3.2 layout components & responsive grids
- **Iconography:** Font Awesome 6.5.0 & Bootstrap Icons
- **Data Visualization:** Chart.js 4.4.0

### ⚙️ Backend
- **Framework:** Python 3.x (FastAPI Server)
- **Database Architecture:** SQLAlchemy (ORM Setup) + Active Alembic Migrations
- **Auth Engine:** Starlette Session Cookies, CryptContext (bcrypt) schemas
- **Pipeline:** Native Subprocess handling, integrated Grok/OSINT scraping Python scripts

---

## 📁 Architecture & Folder Structure

```text
Threat-Intelligence-Tool/
├── .env
├── .gitignore
├── README.md
├── alembic
│   ├── README
│   ├── env.py
│   ├── script.py.mako
│   └── versions
├── alembic.ini
├── dbapp
│   ├── __init__.py
│   ├── api_json
│   │   ├── __init__.py
│   │   ├── custom_ingest_api.py
│   │   ├── custom_utils.py
│   │   └── modified_ingest_api.py
│   ├── automotive_ai
│   │   ├── aigeneration.py
│   │   ├── aigeneration2.py
│   │   ├── usinggrok.py
│   │   └── usinggrok2.py
│   ├── check_db.py
│   ├── config.py
│   ├── database.py
│   ├── main.py
│   ├── models.py
│   └── webscraping
│       └── webscraping_script.py
├── frontendapp
│   ├── assets
│   │   ├── css
│   │   │   ├── brand.css
│   │   │   ├── branddetails.css
│   │   │   ├── company.css
│   │   │   ├── dashboard.css
│   │   │   ├── details.css
│   │   │   ├── ledger.css
│   │   │   ├── login.css
│   │   │   ├── signup.css
│   │   │   └── tier1.css
│   │   ├── images
│   │   │   ├── All Images with .png and .jpg
│   │   └── js
│   │       ├── api.js
│   │       ├── auth.js
│   │       ├── brand.js
│   │       ├── branddetails.js
│   │       ├── dashboard.js
│   │       ├── details.js
│   │       ├── ledger.js
│   │       ├── login.js
│   │       ├── main.js
│   │       ├── protected.js
│   │       ├── signup.js
│   │       └── tier1.js
│   ├── brand.html
│   ├── branddetails.html
│   ├── company.html
│   ├── components
│   │   ├── navbar.html
│   │   ├── navbar.js
│   │   └── searchbar.html
│   ├── dashboard.html
│   ├── details.html
│   ├── ledger.html
│   ├── login.html
│   ├── signup.html
│   └── tier1.html
├── index.html
├── models
│   ├── config.json
│   ├── special_tokens_map.json
│   ├── tokenizer_config.json
│   └── vocab.json
├── requirements.txt
├── results
│   └── checkpoint-102
│       ├── config.json
│       ├── special_tokens_map.json
│       ├── tokenizer.json
│       ├── tokenizer_config.json
│       └── trainer_state.json
├── run_pipeline.bat
├── run_pipeline.py
├── start_project.bat
└── tree.txt
```

---

## 🧩 Component Deep Dive

If you are just getting started in the `frontendapp/` code, here is what each major module accomplishes:
- `index.html`: Base entry point that redirects traffic immediately out to `/login.html` security wall.
- `login.html` / `signup.html`: Captures and sanitizes basic user data, handing parameters back to `assets/js/auth.js` for session fetching.
- `dashboard.html`: The core visualization view. Leverages layout slots where `dashboard.js` loops through thousands of CVEs globally to sum pie metrics against interface and ECU parameters dynamically.
- `api.js`: All frontend logic bridges here. You will trace all `fetch()` queries routed explicitly to the FastAPI instance via `export const API_BASE`.
- `protected.js`: Attached to sensitive views; immediately bounces users lacking active local sessions back to the login screen.

---

## 🗄️ Database Schema Map
The backend is structured to hold deeply categorized variants of system security flaws. Below are the primary SQL Models tracked inside `dbapp/models.py`.

* **`vulnerabilities`**: The global pool processing CVSS scores, raw source text, severity rankings, and boolean state flags tracking whether it's processed.
* **`automotive_vulnerabilities`**: Deep-dive vehicle vulnerabilities categorizing context metadata: `company`, `attack_path`, `interface`, `tools_used`, `ecu_name`, `library_name`, and `damage_scenario`.
* **`iot_embedded_vulnerabilities`**: Mirrors automotive, but specializes metadata for smart devices parsing fields like `product_name`, `vendor`, `firmware_version` and specific IoT `protocol` standards.
* **`users`**: Isolated identity state tracking standard strings and securely hashed `password` blocks via Bcrypt. 

---

## ⚙️ Getting Started (Local Execution)

### Prerequisites
- Python 3.x installed (System-wide or via pyenv/conda).
- Ensure your network can handle outbound API traffic during pipeline operations.

### 1. Installation

Create/use the virtual environment to enforce dependency control:

```cmd
:: Activate the virtual environment
.\venv\Scripts\activate

:: Extract dependencies
pip install -r requirements.txt
```

### 2. Standard Boot Sequence

We have included a convenience script to fire up all necessary servers on a Windows machine in one fell swoop.

```cmd
:: Launch both nodes simultaneously
.\start_project.bat
```

**What this does:**
1. Spawns the internal **Backend Python Engine** globally to `http://127.0.0.1:8000`.
2. Serves the **HTML UI Node** natively referencing `http://127.0.0.1:5500`.

Once initialized, navigate your primary browser to **[http://127.0.0.1:5500/](http://127.0.0.1:5500/)**.

---

## 🧠 The AI Ingestion Pipeline

To populate your dashboard with current CVEs or zero-day threats, you must manually run the overarching pipeline command. 

```cmd
python run_pipeline.py
```
* **Phase 1**: Script fires sequential background routines stored in `dbapp/automotive_ai/`.
* **Phase 2**: Unstructured outputs are fed through integrated conversational AI models (like Grok).
* **Phase 3**: Clean intelligence instances are systematically classified and loaded into your local SQL schemas (`AutomotiveVulnerabilities` and `IotEmbeddedVulnerabilities`).

---

## 📡 API Reference Endpoints

The FastAPI app natively ships all RESTful requests below on `/`. For localized interactive documentation, route to `http://127.0.0.1:8000/docs` while the server is active.

### Data Endpoints
* `GET /automotive_vulnerabilities` - Main threat query module. Accepts strict arguments: `from` & `to` (date matching), `search` (text parsing), and `cve_type`.
* `GET /automotive_vulnerabilities/cve/{cve_id}` - Resolves singular specific data payloads mapping to a certified CVE ID.
* `GET /automotive_vulnerabilities/id/{id}` - Native database key search.

### Authentication Endpoints
* `POST /signup` - Registers standard users. Expects `name`, `username`, `email`, `password`, `confirm_password` in JSON payload.
* `POST /login` - Leverages session cookies internally natively binding logic payload. 
* `POST /logout` - Flushes Starlette session cookies.
* `GET /me` - State verification route reflecting logged-in user JSON blocks.

---

## 🚨 Troubleshooting & Developer Notes

> **CORS Origin Requirements**  
> The internal authentication mechanism restricts CORS bridging intentionally. Currently, `dbapp/main.py(allow_origins)` expects web data **exclusively** from `<host>:5500`. Proceed with extreme caution when mutating frontend web ports — if updating ports, you must concurrently change the allowed CORS array in your FastAPI setup to avoid `CORS Validation Block` runtime errors.

**Common Issues:**
- **Script Activation Fails**: If `.\venv\Scripts\activate` fails on Windows, run PowerShell as Administrator and execute `Set-ExecutionPolicy Unrestricted -Force`.
- **Port Conflicts**: If the dashboard fails to load API data, verify `uvicorn` successfully bound to port `8000` via your terminal output. If `8000` is consumed by another background app, edit `start_project.bat` to launch on `8001` and update `API_BASE` in `frontendapp/assets/js/api.js`.
- **Database Missing Errors**: Ensure Alembic tracking is up to date or run basic SQLAlchemy `Base.metadata.create_all` scripts if transitioning to a fresh physical SQL instance.

---
*Built with logic handling to support expansive future-proof zero-day and digital threat intelligence operations.*

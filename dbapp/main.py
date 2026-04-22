# from fastapi import FastAPI

# from .routers import vulnerabilities
# from .database import Base, engine

# # Create tables
# Base.metadata.create_all(bind=engine)

# app = FastAPI()

# # Allow React frontend
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:5173"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # Include routers
# app.include_router(vulnerabilities.router)


# from http.client import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dbapp.models import AutomotiveVulnerability, User
from dbapp.database import get_db
from fastapi import FastAPI, Depends, Query, HTTPException, Request, Response
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from datetime import datetime
from typing import Optional
from passlib.context import CryptContext
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
import requests

from contextlib import asynccontextmanager

import sys
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from automation.scheduler import start_scheduler, stop_scheduler
except ImportError:
    start_scheduler = stop_scheduler = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    if start_scheduler:
        start_scheduler()
    yield
    if stop_scheduler:
        stop_scheduler()

app = FastAPI(lifespan=lifespan)

# app.add_middleware(SessionMiddleware, secret_key="super-secret-key")  # use env var in prod


# ----------------- CORS Setup -----------------
origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key="super-secret-key",
    same_site="lax",   # allow cross-site
    https_only=False    # must be False if you’re on HTTP.
)

import re
from sqlalchemy import func

def normalize_sql(field):
    """
    Normalizes database text for flexible matching:
    - lower case
    - removes hyphens, spaces, underscores
    - removes unicode dashes
    """
    return func.replace(
        func.replace(
            func.replace(
                func.replace(
                    func.lower(field),
                    "-", ""
                ),
                " ", ""
            ),
            "_", ""
        ),
        "–", ""  # optional: remove en-dash
    )


@app.get("/")
def read_root():
    return {"message": "Hello, FastAPI from VS Code!"}

# @app.get("/automotive_vulnerabilities")
# def get_vulnerabilities(db: Session = Depends(get_db)):
#     return db.query(AutomotiveVulnerability).all()


@app.get("/automotive_vulnerabilities")
def get_vulnerabilities(
    db: Session = Depends(get_db),
    from_date: str | None = Query(None, alias="from"),
    to_date: str | None = Query(None, alias="to"),
    search: str | None = None,
    cve_type: str | None = Query(None),
):
    query = db.query(AutomotiveVulnerability)

    # -------------------------
    # DATE FILTER
    # -------------------------
    if from_date and to_date:
        try:
            from_dt = datetime.strptime(from_date, "%Y-%m-%d")
            to_dt = datetime.strptime(to_date, "%Y-%m-%d")
            query = query.filter(
                AutomotiveVulnerability.published_date.between(from_dt, to_dt)
            )
        except ValueError:
            pass

    # -------------------------
    # SEARCH FILTER
    # -------------------------
    if search:

        # =============================================
        # OPTION-D CASE SENSITIVE WORD MATCH FOR "CAN"
        # =============================================
        if search == "CAN":
            # Postgres regex word boundary: \m or \y
            regex = r"(?<!ZDI-)\yCAN\y"

            query = query.filter(
                or_(
                    AutomotiveVulnerability.title.op("~")(regex),
                    AutomotiveVulnerability.description.op("~")(regex),
                    AutomotiveVulnerability.interface.op("~")(regex),
                    AutomotiveVulnerability.ecu_name.op("~")(regex),
                )
            )

        # =============================================
        # NORMAL SEARCH FOR ALL OTHER TERMS (KEEP YOUR LOGIC)
        # =============================================
        else:
            search_norm = re.sub(r"[-_\s]", "", search.lower())

            query = query.filter(
                or_(
                    normalize_sql(AutomotiveVulnerability.title).contains(search_norm),
                    normalize_sql(AutomotiveVulnerability.description).contains(search_norm),
                    normalize_sql(AutomotiveVulnerability.company).contains(search_norm),
                    normalize_sql(AutomotiveVulnerability.interface).contains(search_norm),
                    normalize_sql(AutomotiveVulnerability.ecu_name).contains(search_norm),
                    normalize_sql(AutomotiveVulnerability.cve_id).contains(search_norm),
                )
            )

    # -------------------------
    # CVE TYPE FILTER
    # -------------------------
    if cve_type == "CVE":
        query = query.filter(AutomotiveVulnerability.cve_id.like("CVE-%"))
    elif cve_type == "Non-CVE":
        query = query.filter(
            or_(
                AutomotiveVulnerability.cve_id == None,
                AutomotiveVulnerability.cve_id == "Not Available",
            )
        )

    return query.all()




@app.get("/automotive_vulnerabilities/cve/{cve_id}")
def get_vulnerability_by_cve(cve_id: str, db: Session = Depends(get_db)):
    vuln = db.query(AutomotiveVulnerability).filter(AutomotiveVulnerability.cve_id == cve_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Not Found")
    return vuln

@app.get("/automotive_vulnerabilities/id/{id}")
def get_vulnerability_by_id(id: int, db: Session = Depends(get_db)):
    vuln = db.query(AutomotiveVulnerability).get(id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Not Found")
    return vuln

#password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----------------- Pydantic Models -----------------
class UserSignup(BaseModel):
    name: str
    username: str
    email: str
    password: str
    confirm_password: str

class UserLogin(BaseModel):
    username: str
    password: str

# ----------------- SIGNUP -----------------
@app.post("/signup")
def signup(user: UserSignup, db: Session = Depends(get_db)):
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    existing_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_pw = pwd_context.hash(user.password)
    new_user = User(
        name=user.name,
        username=user.username,
        email=user.email,
        password=hashed_pw
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"success": True, "message": "Signup successful. Please Login"}

# ----------------- LOGIN -----------------
# @app.post("/login")
# def login(user: UserLogin, db: Session = Depends(get_db)):
#     db_user = db.query(User).filter(User.username == user.username).first()
#     if not db_user or not pwd_context.verify(user.password, db_user.password):
#         raise HTTPException(status_code=400, detail="Invalid credentials")

#     return {"success": True, "message": "Login successful"}

@app.post("/login")
def login(user: UserLogin, request: Request, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Store user info in session
    request.session["user"] = {"id": db_user.id, "username": db_user.username, "name": db_user.name}

    return {"success": True, "message": "Login successful", "username": db_user.username, "name": db_user.name}


# ----------------- LOGOUT -----------------
@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"success": True, "message": "Logged out"}


# ----------------- GET CURRENT USER -----------------
@app.get("/me")
def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {
        "username": user["username"],
        "name": user["name"]
        }

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
from fastapi import FastAPI, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from datetime import datetime
from typing import Optional
from passlib.context import CryptContext
from pydantic import BaseModel

app = FastAPI()


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
):
    query = db.query(AutomotiveVulnerability)

    # Date filter
    if from_date and to_date:
        try:
            from_dt = datetime.strptime(from_date, "%Y-%m-%d")
            to_dt = datetime.strptime(to_date, "%Y-%m-%d")
            query = query.filter(
                AutomotiveVulnerability.published_date.between(from_dt, to_dt)
            )
        except ValueError:
            pass  # ignore bad dates, return all

    # Search filter
    if search:
        search_like = f"%{search}%"
        query = query.filter(
            or_(
                AutomotiveVulnerability.cve_id.ilike(search_like),
                AutomotiveVulnerability.title.ilike(search_like),
                AutomotiveVulnerability.description.ilike(search_like),
                AutomotiveVulnerability.company.ilike(search_like),
                AutomotiveVulnerability.interface.ilike(search_like),
                AutomotiveVulnerability.ecu_name.ilike(search_like),
            )
        )

    return query.all()



@app.get("/automotive_vulnerabilities/cve/{cve_id}")
def get_vulnerability_by_cve(cve_id: str, db: Session = Depends(get_db)):
    vuln = db.query(AutomotiveVulnerability).filter(AutomotiveVulnerability.cve_id == cve_id).first()
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
@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    return {"success": True, "message": "Login successful"}

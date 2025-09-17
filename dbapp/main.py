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


from http.client import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dbapp.models import AutomotiveVulnerability
from dbapp.database import get_db
from fastapi import FastAPI, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from datetime import datetime
from typing import Optional

app = FastAPI()

origins = [
    "http://127.0.0.1:5500",  # replace with your frontend URL/port
    "http://localhost:5500",
    "*",  # allow all origins for testing
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    # allow_origins=origins,
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

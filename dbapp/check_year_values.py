import sys
import os
from pathlib import Path

# Add the project directory to sys.path to import dbapp modules
sys.path.append(str(Path(__file__).resolve().parent.parent))

from dbapp.database import get_session
from dbapp.models import AutomotiveVulnerability
from sqlalchemy import extract

session = get_session()

# Total count for source
total_count = session.query(AutomotiveVulnerability).filter(
    AutomotiveVulnerability.source == "https://github.com/IEEM-HsKA/AAD"
).count()
print(f"Total count for source: {total_count}")

# Distinct model_years
model_years = session.query(AutomotiveVulnerability.model_year).filter(
    AutomotiveVulnerability.source == "https://github.com/IEEM-HsKA/AAD"
).distinct().all()
print(f"Distinct model_years: {model_years}")

# Distinct published_date years
pub_years = session.query(extract('year', AutomotiveVulnerability.published_date)).filter(
    AutomotiveVulnerability.source == "https://github.com/IEEM-HsKA/AAD"
).distinct().all()
print(f"Distinct pub_years: {pub_years}")

session.close()

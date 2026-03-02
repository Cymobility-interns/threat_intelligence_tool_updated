from sqlalchemy import Column, Integer, String, Text, Float, TIMESTAMP, func, Date, DateTime, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from dbapp.database import Base

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = Column(String, nullable=True, index=True)  
    source = Column(String, nullable=False)  
    description = Column(Text, nullable=True)
    published_date = Column(TIMESTAMP(timezone=True), nullable=True)
    modified_date = Column(TIMESTAMP(timezone=True), nullable=True)
    severity = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    reference_links = Column(JSONB, nullable=True)
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    updated_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    processed = Column(Boolean, nullable=False, server_default="false")

    

class SyncState(Base):
    __tablename__ = "sync_state"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source = Column(String, nullable=False, unique=True)   # e.g., "NVD"
    # last_synced = Column(TIMESTAMP(timezone=True), nullable=True)
    last_synced = Column(DateTime(timezone=True), nullable=True)
    last_run = Column(DateTime(timezone=True), nullable=True)



class ClassifiedVulnerability(Base):
    __tablename__ = "classified_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = Column(String, nullable=True, index=True)  
    source = Column(String, nullable=False)  
    description = Column(Text, nullable=True)
    published_date = Column(TIMESTAMP(timezone=True), nullable=True)
    modified_date = Column(TIMESTAMP(timezone=True), nullable=True)
    severity = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    reference_links = Column(JSONB, nullable=True)
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    updated_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    processed = Column(Boolean, nullable=False, server_default="false")



class AutomotiveVulnerability(Base):
    __tablename__ = "automotive_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = Column(String, nullable=True, index=True)
    source = Column(String, nullable=False)
    published_date = Column(TIMESTAMP(timezone=True), nullable=True)
    company = Column(String, nullable=True)
    title = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    attack_path = Column(Text, nullable=True)
    interface = Column(String, nullable=True)
    tools_used = Column(String, nullable=True)
    types_of_attack = Column(String, nullable=True)
    level_of_attack = Column(String, nullable=True)
    damage_scenario = Column(String, nullable=True)
    cia = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    impact = Column(String, nullable=True)
    feasibility = Column(String, nullable=True)
    countermeasures = Column(String, nullable=True)
    model_name = Column(String, nullable=True)
    model_year = Column(String, nullable=True)
    ecu_name = Column(String, nullable=True)
    library_name = Column(String, nullable=True)


    
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, nullable=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)


class ClassifiedIotVulnerability(Base):
    __tablename__ = "classified_iot_embedded_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = Column(String, nullable=True, index=True)  
    source = Column(String, nullable=False)  
    description = Column(Text, nullable=True)
    published_date = Column(TIMESTAMP(timezone=True), nullable=True)
    modified_date = Column(TIMESTAMP(timezone=True), nullable=True)
    severity = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    reference_links = Column(JSONB, nullable=True)
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    updated_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    processed = Column(Boolean, nullable=False, server_default="false")


class IotEmbeddedVulnerability(Base):
    __tablename__ = "iot_embedded_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = Column(String, nullable=True, index=True)
    source = Column(String, nullable=False)
    published_date = Column(TIMESTAMP(timezone=True), nullable=True)
    vendor = Column(String, nullable=True)
    title = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    attack_path = Column(Text, nullable=True)
    interface = Column(String, nullable=True)
    protocol = Column(String, nullable=True)
    tools_used = Column(String, nullable=True)
    types_of_attack = Column(String, nullable=True)
    level_of_attack = Column(String, nullable=True)
    affected_component = Column(String, nullable=True)
    damage_scenario = Column(String, nullable=True)
    cia = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    impact = Column(String, nullable=True)
    feasibility = Column(String, nullable=True)
    countermeasures = Column(String, nullable=True)
    product_name = Column(String, nullable=True)
    library_name = Column(String, nullable=True)
    firmware_version = Column(String, nullable=True)
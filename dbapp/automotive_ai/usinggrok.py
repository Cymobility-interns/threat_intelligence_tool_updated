import os
import time
import psycopg2
from psycopg2.extras import execute_values
from openai import OpenAI  # using OpenAI SDK but pointing to Grok endpoint
from dotenv import load_dotenv
load_dotenv()
import re

# ---------------- DB CONFIG ----------------
DB_NAME = os.getenv("PG_DB", "vuldb")
DB_USER = os.getenv("PG_USER", "postgres")
DB_PASS = os.getenv("PG_PASS", "123456")
DB_HOST = os.getenv("PG_HOST", "localhost")
DB_PORT = os.getenv("PG_PORT", "5432")

# ---------------- GROK / XAI CONFIG ----------------
GROK_API_KEY = os.getenv("XAI_API_KEY", None)
if not GROK_API_KEY:
    raise RuntimeError("GROK_API_KEY (XAI_API_KEY) not set in environment")

# Create client pointing to Grok (xAI) API endpoint
client = OpenAI(
    api_key=GROK_API_KEY,
    base_url="https://api.x.ai/v1"
)

# Labels for classification
LABELS = [
    "Automotive Vulnerability",
    "IT Vulnerability",
    "Web Application Vulnerability",
    "IoT Vulnerability",
    "Network Vulnerability",
    "Operational Technology (OT) Vulnerability"
]

SCHEMA_FIELDS = ["id", "cve_id", "source", "published_date", "description", "cvss_score"]
 
def connect_db():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT
    )

def fetch_unprocessed_batch(batch_size=50):
    sql = f"""
        SELECT id, cve_id, source, published_date, description, cvss_score
        FROM vulnerabilities
        WHERE processed = FALSE
        ORDER BY id ASC
        LIMIT {batch_size}
    """
    with connect_db() as conn, conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()
        colnames = [desc[0] for desc in cur.description]
        return [dict(zip(colnames, row)) for row in rows]

def insert_into_automotive(records):
    if not records:
        return 0
    cols = list(SCHEMA_FIELDS)
    values = [[rec.get(col) for col in cols] for rec in records]
    sql = f"""
        INSERT INTO classified_vulnerabilities ({','.join(cols)})
        VALUES %s
        ON CONFLICT DO NOTHING
    """
    with connect_db() as conn, conn.cursor() as cur:
        execute_values(cur, sql, values)
    return len(records)

def mark_processed(ids):
    if not ids:
        return
    sql = "UPDATE vulnerabilities SET processed = TRUE WHERE id = ANY(%s)"
    with connect_db() as conn, conn.cursor() as cur:
        cur.execute(sql, (ids,))

def preprocess_description(text: str) -> str:
    """
    Cleans CVE descriptions before classification to avoid misleading tokens.
    - Removes internal tracking IDs like (ZDI-CAN-12345), (ZDI-AUTO-12345)
    - Normalizes whitespace
    - Strips leading/trailing junk
    """
    if not text:
        return ""

    # Remove patterns like (ZDI-CAN-12345), [ZDI-CAN-12345], etc.
    text = re.sub(r'\(?ZDI-[A-Z]+-\d+\)?', '', text, flags=re.IGNORECASE)

    # Remove extra spaces and normalize newlines
    text = re.sub(r'\s+', ' ', text).strip()

    return text


def classify_text_grok(text: str) -> str:
    """
    Classify text using Grok API.
    Returns one of the LABELS exactly as string.
    """
    prompt = f"""
Classify the following CVE description into one of these labels:
{', '.join(LABELS)}

Description:
{text}

Rules:
- If the description states that the CVE is "REJECTED", "RESERVED", or "DUPLICATE", classify it as "IT Vulnerability".
- "Automotive Vulnerability" → anything directly related to vehicles or in-vehicle systems (e.g., ECUs, infotainment, headunits, CAN bus, telematics, sensors, EV charging) or automotive manufacturing equipment. Do not classify general software tools or product names that only reference automotive terms as automotive.
- "IT Vulnerability" → general software, OS, servers, enterprise systems.
- "Web Application Vulnerability" → websites, APIs, web frameworks.
- "IoT Vulnerability" → consumer or embedded smart devices (non-automotive).
- "Network Vulnerability" → routers, switches, VPNs, or network protocols.
- "Operational Technology (OT) Vulnerability" → industrial control or automation systems not specific to automotive.
-If the record is related to Linux, Then Check if the vulnerability is affecting to automotive systems or components. If yes, classify it as "Automotive Vulnerability".
Return only one label exactly as written.
"""

    response = client.chat.completions.create(
        model="grok-3-mini",  # or "grok-4", "grok-3" etc depending on your access
        messages=[
            {"role": "system", "content": "You are a strict classifier."},
            {"role": "user", "content": prompt}
        ],
        temperature=0,
        top_p=1,
    )
    # The return may include the chosen label in response.choices[0].message.content
    return response.choices[0].message.content.strip()

def classify_batch(records):
    automotive_records = []
    for rec in records:
        raw_description = rec.get("description", "").strip() or "N/A"
        description = preprocess_description(raw_description)

        # Optional logging if something changed
        # if raw_description != description:
        #     print(f"Preprocessed description for ID {rec['id']}: removed tracking tokens.")

        try:
            label = classify_text_grok(description)
            if label.lower().startswith("automotive"):
                automotive_records.append(rec)
                print(f"[AUTOMOTIVE] ID {rec['id']}, CVE {rec['cve_id']}, label={label}")
            else:
                print(f"[NON-AUTOMOTIVE] ID {rec['id']}, CVE {rec['cve_id']}, label={label}")
        except Exception as e:
            print(f"Classification failed for ID {rec['id']}: {e}")
    return automotive_records

def run_full_pipeline(batch_size=50):
    total_fetched = total_inserted = total_processed = 0

    while True:
        source_rows = fetch_unprocessed_batch(batch_size=batch_size)
        if not source_rows:
            print("No unprocessed records found. Pipeline finished.")
            break

        print(f"\nFetched {len(source_rows)} records.")

        automotive_records = classify_batch(source_rows)

        inserted = insert_into_automotive(automotive_records)
        processed_ids = [rec["id"] for rec in source_rows]
        mark_processed(processed_ids)

        total_fetched += len(source_rows)
        total_inserted += inserted
        total_processed += len(processed_ids)

        print(f"Batch summary: Inserted {inserted}/{len(source_rows)} records.")
        time.sleep(0.5)

    print("\nFinal Run Summary:")
    print(f"Fetched: {total_fetched} | Inserted: {total_inserted} | Processed: {total_processed}")
    print("Pipeline complete.")

if __name__ == "__main__":
    run_full_pipeline(batch_size=50)

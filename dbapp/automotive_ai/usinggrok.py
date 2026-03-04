import os
import time
import json
import re
import psycopg2
from psycopg2.extras import execute_values
from openai import OpenAI
from dotenv import load_dotenv
load_dotenv()

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

# ---------------- DATABASE FUNCTIONS ----------------
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
        WHERE processed_automotive = FALSE
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
    sql = "UPDATE vulnerabilities SET processed_automotive = TRUE WHERE id = ANY(%s)"
    with connect_db() as conn, conn.cursor() as cur:
        cur.execute(sql, (ids,))

# ---------------- TEXT PREPROCESSING ----------------
def preprocess_description(text: str) -> str:
    """
    Cleans CVE descriptions before classification to avoid misleading tokens.
    - Removes internal tracking IDs like (ZDI-CAN-12345)
    - Normalizes whitespace
    - Strips leading/trailing junk
    """
    if not text:
        return ""
    text = re.sub(r'\(?ZDI-[A-Z]+-\d+\)?', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# ---------------- CLASSIFICATION (BATCHED) ----------------
def classify_batch(records, sub_batch_size=10):
    automotive_records = []

    for i in range(0, len(records), sub_batch_size):
        sub_batch = records[i:i + sub_batch_size]

        # Preprocess + optional logging
        batch_lines = []
        for idx, rec in enumerate(sub_batch):
            raw_description = rec.get("description", "").strip()
            description = preprocess_description(raw_description)

            # Optional logging if something changed
            # if raw_description != description:
            #     print(f"Preprocessed description for ID {rec['id']}: removed tracking tokens.")

            batch_lines.append(f"{idx+1}. {rec['cve_id']}: {description}")

        batch_text = "\n".join(batch_lines)

        # Build Grok classification prompt
        prompt = f"""
You are a strict vulnerability classifier.
Classify each CVE description into one of these labels:
{', '.join(LABELS)}

Classification rules (semantic, not keyword-based):

1. "Automotive Vulnerability" ONLY if the vulnerability clearly affects
   systems that operate inside vehicles or automotive infrastructure,
   such as in-vehicle communication, ECUs, infotainment/IVI, telematics,
   ADAS functions, or any component directly involved in vehicle operation or safety.

2. Vulnerabilities involving mobile operating systems, smartphone features,
   general embedded chipsets, audio/camera/display drivers, SoCs, kernel 
   memory bugs, generic firmware logic, cloud services, websites, APIs,
   or consumer IoT devices are NOT automotive unless the description
   explicitly states that the affected component is used in a vehicle system.

3. If the description contains "REJECTED", "RESERVED", or "DUPLICATE",
   classify it as "IT Vulnerability".

4. Ambiguous descriptions are NEVER classified as automotive. The model
   must default to a non-automotive label unless the automotive context
   is explicit and undeniable.

Return only JSON in this format:
[
  {{ "cve_id": "CVE-XXXX-YYYY", "label": "..." }},
  {{ "cve_id": "CVE-XXXX-ZZZZ", "label": "..." }}
]

Descriptions:
{batch_text}
"""

        try:
            response = client.chat.completions.create(
                model="grok-3-mini",
                messages=[
                    {"role": "system", "content": "You are a precise JSON-only vulnerability classifier."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0,
                top_p=1,
            )

            output = response.choices[0].message.content.strip()

            # Try to parse JSON response
            try:
                parsed = json.loads(output)
            except json.JSONDecodeError:
                print(f" JSON parse failed, fallback to line parsing for batch {i//sub_batch_size+1}")
                parsed = []
                for line in output.splitlines():
                    match = re.match(r".*?(CVE-\d{4}-\d+).*?:\s*(.+)", line)
                    if match:
                        parsed.append({"cve_id": match.group(1), "label": match.group(2).strip()})

            for item in parsed:
                cve_id = item.get("cve_id")
                label = item.get("label", "").strip()
                rec = next((r for r in sub_batch if r["cve_id"] == cve_id), None)
                if not rec:
                    continue

                if label.lower().startswith("automotive"):
                    automotive_records.append(rec)
                    print(f"[AUTOMOTIVE] ID {rec['id']}, {cve_id} => {label}")
                else:
                    print(f"[NON-AUTOMOTIVE] ID {rec['id']}, {cve_id} => {label}")

        except Exception as e:
            print(f" Batch classification failed: {e}")

        time.sleep(0.3)  # polite pacing

    return automotive_records

# ---------------- MAIN PIPELINE ----------------
def run_full_pipeline(batch_size=50):
    total_fetched = total_inserted = total_processed = 0

    while True:
        source_rows = fetch_unprocessed_batch(batch_size=batch_size)
        if not source_rows:
            print(" No unprocessed records found. Pipeline finished.")
            break

        print(f"\nFetched {len(source_rows)} records.")

        automotive_records = classify_batch(source_rows, sub_batch_size=10)

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
    print(" Pipeline complete.")

if __name__ == "__main__":
    run_full_pipeline(batch_size=50)

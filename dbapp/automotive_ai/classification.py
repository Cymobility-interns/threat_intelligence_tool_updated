import os
import time
import psycopg2
from psycopg2.extras import execute_values
from transformers import pipeline

# ---------------- DB CONFIG ----------------
DB_NAME = os.getenv("PG_DB", "vuldb")
DB_USER = os.getenv("PG_USER", "postgres")
DB_PASS = os.getenv("PG_PASS", "123456")
DB_HOST = os.getenv("PG_HOST", "192.168.0.11")
DB_PORT = os.getenv("PG_PORT", "5432")

# ---------------- MODEL CONFIG ----------------
print("Loading zero-shot classifier model...")
classifier = pipeline(
    "zero-shot-classification",
    model="facebook/bart-large-mnli",
    device=0  # use GPU if available
)

# Labels for zero-shot
LABELS = ["Automotive Vulnerability", "IT Vulnerability", "Web application Vulnerability", "Network Vulnerability", "IOT Vulnerability", "Operational Technology Vulnerability", "Other Vulnerability"]


# ---------------- SCHEMA ----------------
SCHEMA_FIELDS = [
    "id", "cve_id", "source", "published_date",  "description"
]

# ---------------- DB FUNCTIONS ----------------
def connect_db():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT
    )

def fetch_unprocessed_batch(batch_size=50):
    """
    Fetch a batch of unprocessed records.
    """
    sql = f"""
        SELECT id, cve_id, source, published_date, description
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
    """
    Insert automotive-related records into the automotive_vulnerabilities table.
    """
    if not records:
        return 0

    cols = list(SCHEMA_FIELDS)
    values = [[rec.get(col) for col in cols] for rec in records]

    sql = f"""
        INSERT INTO classified_vulnerabilities ({','.join(cols)})
        VALUES %s
        ON CONFLICT DO NOTHING;
    """
    with connect_db() as conn, conn.cursor() as cur:
        execute_values(cur, sql, values)
    return len(records)

def mark_processed(ids):
    """
    Mark records in the vulnerabilities table as processed.
    """
    if not ids:
        return
    sql = "UPDATE vulnerabilities SET processed = TRUE WHERE id = ANY(%s)"
    with connect_db() as conn, conn.cursor() as cur:
        cur.execute(sql, (ids,))

# ---------------- CLASSIFICATION ----------------
def classify_batch(records, threshold=0.55):
    """
    Classify a batch of vulnerability records using zero-shot classification.
    """
    descriptions = [rec.get("description", "").strip() or "N/A" for rec in records]

    try:
        results = classifier(descriptions, LABELS, multi_label=True)
    except Exception as e:
        print(f"Batch classification failed: {e}")
        return []

    automotive_records = []
    for rec, res in zip(records, results):
        top_label = res["labels"][0]
        top_score = res["scores"][0]

        if top_label.lower().startswith("automotive") and top_score >= threshold:
            automotive_records.append(rec)
            print(f"[AUTOMOTIVE] ID {rec['id']}, CVE {rec['cve_id']}, score={top_score:.2f}")
        else:
            print(f"[NON-AUTOMOTIVE] ID {rec['id']}, CVE {rec['cve_id']}, score={top_score:.2f}")

    return automotive_records

# ---------------- PIPELINE (Batch-wise) ----------------
def run_full_pipeline(batch_size=50):
    """
    Continuously process vulnerabilities in batches until none are left.
    """
    total_fetched, total_inserted, total_processed = 0, 0, 0

    while True:
        source_rows = fetch_unprocessed_batch(batch_size=batch_size)
        if not source_rows:
            print("No unprocessed records found. Pipeline completed.")
            break

        print(f"\nFetched {len(source_rows)} records.")

        # Classify batch
        automotive_records = classify_batch(source_rows)

        # Insert automotive records
        inserted = insert_into_automotive(automotive_records)

        # Mark processed
        processed_ids = [rec["id"] for rec in source_rows]
        mark_processed(processed_ids)

        # Update stats
        total_fetched += len(source_rows)
        total_inserted += inserted
        total_processed += len(processed_ids)

        print(f"Batch summary: Inserted {inserted}/{len(source_rows)} records.")

        # Small sleep to reduce DB/model overload
        time.sleep(0.5)

    print("\nFinal Run Summary:")
    print(f"Fetched: {total_fetched} | Inserted: {total_inserted} | Processed: {total_processed}")
    print("Pipeline finished successfully!")

# ---------------- MAIN ----------------
if __name__ == "__main__":
    run_full_pipeline(batch_size=50)

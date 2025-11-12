import os
import json5  # <- using json5 for robust JSON parsing
import psycopg2
from psycopg2.extras import execute_values
from openai import OpenAI
from dotenv import load_dotenv

# ---------------- LOAD ENV ----------------
load_dotenv()

DB_NAME = os.getenv("PG_DB", "vuldb")
DB_USER = os.getenv("PG_USER", "postgres")
DB_PASS = os.getenv("PG_PASS", "123456")
DB_HOST = os.getenv("PG_HOST", "192.168.0.28")
DB_PORT = os.getenv("PG_PORT", "5432")

GROK_API_KEY = os.getenv("XAI_API_KEY")
if not GROK_API_KEY:
    raise RuntimeError("GROK_API_KEY (XAI_API_KEY) not set in environment")

# ---------------- INIT GROK CLIENT ----------------
client = OpenAI(
    api_key=GROK_API_KEY,
    base_url="https://api.x.ai/v1"
)

# ---------------- PROMPT TEMPLATE ----------------
PROMPT_TEMPLATE = """
You are a cybersecurity AI for automotive vulnerabilities.
From the numbered descriptions below, generate a JSON array where each element corresponds to the same number, containing exactly 16 fields.

Rules:
- Output only valid JSON array (no markdown).
- Each element must have all 16 fields.
- Use "Unknown" for missing data.
- attack_path: 1–3 numbered steps from attacker entry to impact (how, action, result).
- level_of_attack: One of "Physical", "Local", "Remote", "Network-based", "Supply-chain" or other suitable terms.
- cia: Confidentiality, Integrity, Availability, or combinations.
- impact: Negligible, Moderate, Major, Severe.
- feasibility: Low, Medium, High.
- Use automotive context (ECUs, CAN, infotainment, sensors, etc.).

Numbered Input Descriptions:
{description_block}

Output JSON Array:
[
  {{
    "company": "", "title": "", "attack_path": "", "interface": "", "tools_used": "",
    "types_of_attack": "", "level_of_attack": "", "damage_scenario": "", "cia": "",
    "impact": "", "feasibility": "", "countermeasures": "", "model_name": "",
    "model_year": "", "ecu_name": "", "library_name": ""
  }}
]
"""

EXPECTED_FIELDS = [
    "company", "title", "attack_path", "interface", "tools_used", "types_of_attack",
    "level_of_attack", "damage_scenario", "cia", "impact", "feasibility",
    "countermeasures", "model_name", "model_year", "ecu_name", "library_name"
]

# ---------------- GROK CALL ----------------
def generate_fields_batch(descriptions: list[str]) -> list[dict]:
    """Call Grok once for multiple descriptions and return a list of dicts."""
    # Build numbered input block
    description_block = "\n".join([f"{i+1}. {desc}" for i, desc in enumerate(descriptions)])
    prompt = PROMPT_TEMPLATE.format(description_block=description_block)
    try:
        response = client.chat.completions.create(
            model="grok-3-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=2000  # enough room for multiple JSON objects
        )
        raw_output = response.choices[0].message.content.strip()

        # Clean formatting
        if raw_output.startswith("```"):
            raw_output = raw_output.strip("`").replace("json", "")

        # Parse JSON array
        try:
            data_list = json5.loads(raw_output)
        except Exception as e:
            print(f"❌ Failed to parse JSON5 batch: {e}")
            data_list = []

        # Ensure list shape and fill defaults
        cleaned = []
        for data in data_list:
            obj = {}
            for field in EXPECTED_FIELDS:
                val = data.get(field, "unknown") if isinstance(data, dict) else "unknown"
                obj[field] = val if val else "unknown"
            cleaned.append(obj)

        return cleaned

    except Exception as e:
        print(f"❌ Model batch call failed: {e}")
        return []


# ---------------- DB INSERT/UPDATE ----------------
def insert_and_update(cur, conn, batch_data):
    """Insert generated data and mark rows as processed."""
    if not batch_data:
        return

    insert_query = """
    INSERT INTO automotive_vulnerabilities (
        id, cve_id, source, description, published_date, cvss_score,
        company, title, attack_path, interface, tools_used, types_of_attack,
        level_of_attack, damage_scenario, cia, impact, feasibility,
        countermeasures, model_name, model_year, ecu_name, library_name
    ) VALUES %s
    """
    execute_values(cur, insert_query, batch_data)

    ids = [row[0] for row in batch_data]
    cur.execute(
        "UPDATE classified_vulnerabilities SET processed = true WHERE id = ANY(%s);",
        (ids,)
    )
    conn.commit()
    print(f"✅ Inserted {len(batch_data)} rows & updated processed flags.")

# ---------------- MAIN PIPELINE ----------------
def main():
    try:
        with psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASS,
            host=DB_HOST, port=DB_PORT
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, cve_id, source, description, published_date, cvss_score
                    FROM classified_vulnerabilities
                    WHERE processed = false;
                """)
                rows = cur.fetchall()
                print(f"ℹ️    Fetched {len(rows)} unprocessed rows.")

                all_data = []

                BATCH_SIZE = 5  # tune this (5–10 is optimal)
                for i in range(0, len(rows), BATCH_SIZE):
                    batch_rows = rows[i:i + BATCH_SIZE]
                    descriptions = [r[3] for r in batch_rows]  # description field
                    cve_ids = [r[1] for r in batch_rows]

                    print(f"\n🔎 Processing batch {i//BATCH_SIZE + 1} ({len(batch_rows)} records)...")
                    results = generate_fields_batch(descriptions)

                    if not results:
                        print("⚠️ No results from Grok for this batch — skipping.")
                        continue


                    # Handle mismatch safety
                    if len(results) != len(batch_rows):
                        print(f"⚠️ Mismatch: expected {len(batch_rows)}, got {len(results)} — filling unknowns.")
                        results = results + [{field: "unknown" for field in EXPECTED_FIELDS}] * (len(batch_rows) - len(results))

                    for row, fields in zip(batch_rows, results):
                        id_val, cve_id, source, description, published_date, cvss_score = row
                        all_data.append((
                            id_val, cve_id, source, description, published_date, cvss_score,
                            fields["company"], fields["title"], fields["attack_path"], fields["interface"],
                            fields["tools_used"], fields["types_of_attack"], fields["level_of_attack"],
                            fields["damage_scenario"], fields["cia"], fields["impact"], fields["feasibility"],
                            fields["countermeasures"], fields["model_name"], fields["model_year"],
                            fields["ecu_name"], fields["library_name"]
                        ))

                    # Optional: commit after each batch to avoid losing progress
                    insert_and_update(cur, conn, all_data)
                    all_data = []  # reset after inserting


    except Exception as e:
        print(f"❌ Error in pipeline: {e}")

# ---------------- RUN ----------------
if __name__ == "__main__":
    main()

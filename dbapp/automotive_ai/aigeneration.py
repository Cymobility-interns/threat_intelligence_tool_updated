import os
import json
import time
import psycopg2
from psycopg2.extras import execute_values
from openai import OpenAI

# ---------------- CONFIG ----------------
DB_NAME = os.getenv("PG_DB", "vuldb")
DB_USER = os.getenv("PG_USER", "postgres")
DB_PASS = os.getenv("PG_PASS", "123456")
DB_HOST = os.getenv("PG_HOST", "192.168.0.25")
DB_PORT = os.getenv("PG_PORT", "5432")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "your_openai_api_key")

# Init OpenAI
client = OpenAI(api_key=OPENAI_API_KEY)

PROMPT_TEMPLATE = """
You are an AI that generates structured automotive vulnerability information.
Always respond with a valid JSON object (16 fields, no explanations, no markdown).

Rules:
- If description contains info → extract directly.
- If not present → make best logical guess (based on cybersecurity knowledge).
- Never leave a field blank or null.
- Use realistic automotive context (e.g. ECUs, CAN bus, infotainment).

Input Description:
{description}

JSON Response (16 fields exactly):
{{
    "company": "",
    "title": "",
    "attack_path": "",
    "interface": "",
    "tools_used": "",
    "types_of_attack": "",
    "level_of_attack": "",
    "damage_scenario": "",
    "cia": "",
    "impact": "",
    "feasibility": "",
    "countermeasures": "",
    "model_name": "",
    "model_year": "",
    "ecu_name": "",
    "library_name": ""
}}
"""

EXPECTED_FIELDS = [
    "company", "title", "attack_path", "interface", "tools_used", "types_of_attack",
    "level_of_attack", "damage_scenario", "cia", "impact", "feasibility",
    "countermeasures", "model_name", "model_year", "ecu_name", "library_name"
]

# ---------------- OPENAI CALL ----------------
def generate_fields(description: str) -> dict:
    prompt = PROMPT_TEMPLATE.format(description=description)

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=400
        )

        raw_output = response.choices[0].message.content.strip()

        if raw_output.startswith("```"):
            raw_output = raw_output.strip("`").replace("json", "")

        data = json.loads(raw_output)

        for field in EXPECTED_FIELDS:
            if field not in data or not data[field]:
                data[field] = "unknown"

        return data

    except Exception as e:
        print(f" Model returned invalid JSON or failed: {e}")
        return {field: "unknown" for field in EXPECTED_FIELDS}

# ---------------- MAIN ----------------
def main():
    conn = None
    cur = None

    try:
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASS,
            host=DB_HOST, port=DB_PORT
        )
        cur = conn.cursor()

        #  Fetch only unprocessed rows
        cur.execute("""
            SELECT id, cve_id, source, description, published_date
            FROM classified_vulnerabilities
            WHERE processed = false;
        """)
        rows = cur.fetchall()

        generated_data = []
        request_count = 0

        for row in rows:
            id_val, cve_id, source, description, published_date = row
            print(f"\n🔎 Processing CVE {cve_id}...")

            fields = generate_fields(description)

            generated_data.append((
                id_val, cve_id, source, description, published_date,
                fields["company"], fields["title"], fields["attack_path"],
                fields["interface"], fields["tools_used"], fields["types_of_attack"],
                fields["level_of_attack"], fields["damage_scenario"], fields["cia"],
                fields["impact"], fields["feasibility"], fields["countermeasures"],
                fields["model_name"], fields["model_year"], fields["ecu_name"], fields["library_name"]
            ))

            request_count += 1

            #  Once 3 requests are done → insert & update
            if request_count == 3:
                insert_and_update(cur, conn, generated_data)
                generated_data = []
                request_count = 0
                print("  Inserted 3 rows. Sleeping for 60s...")
                time.sleep(60)

        #  Insert remaining data (if less than 3)
        if generated_data:
            insert_and_update(cur, conn, generated_data)

    except Exception as e:
        print(f" Error: {e}")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ---------------- INSERT & UPDATE ----------------
def insert_and_update(cur, conn, batch_data):
    # Insert into automotive_vulnerabilities
    insert_query = """
    INSERT INTO automotive_vulnerabilities (
        id, cve_id, source, description, published_date,
        company, title, attack_path, interface, tools_used, types_of_attack,
        level_of_attack, damage_scenario, cia, impact, feasibility,
        countermeasures, model_name, model_year, ecu_name, library_name
    ) VALUES %s
    """
    execute_values(cur, insert_query, batch_data)

    # Update processed flag for classified_vulnerabilities
    ids = [row[0] for row in batch_data]
    cur.execute(
        "UPDATE classified_vulnerabilities SET processed = true WHERE id = ANY(%s);",
        (ids,)
    )

    conn.commit()
    print(f"  Inserted {len(batch_data)} rows & updated processed flags.")


# ---------------- RUN ----------------
if __name__ == "__main__":
    main()

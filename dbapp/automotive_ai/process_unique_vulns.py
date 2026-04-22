#!/usr/bin/env python3
import os
import time
import argparse
from typing import List, Dict, Any, Tuple, Optional
import json5
from openai import OpenAI
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
import traceback
import sys

# Fix console encoding for Windows
sys.stdout.reconfigure(encoding='utf-8')

load_dotenv()

# ---------------- CONFIG ----------------
DB_NAME = "vuldbtest"
DB_USER = os.getenv("PG_USER", "postgres")
DB_PASS = os.getenv("PG_PASS", "123456")
DB_HOST = os.getenv("PG_HOST", "localhost")
DB_PORT = os.getenv("PG_PORT", "5432")

GROK_API_KEY = os.getenv("XAI_API_KEY")
if not GROK_API_KEY:
    raise RuntimeError("XAI_API_KEY (GROK_API_KEY) not set in environment")

# Client
client = OpenAI(api_key=GROK_API_KEY, base_url="https://api.x.ai/v1")

SOURCE_TABLE = '"Unique_Automotive_Vulnerability_database"'
TARGET_TABLE = '"Automotive_Vulnerability_database_perfect-one"'

# ---------------- PROMPT (UNCHANGED from aigeneration.py) ----------------
PROMPT_TEMPLATE = """
You are an Automotive Cybersecurity Threat Analysis AI.
For each numbered automotive vulnerability description, generate one JSON object
with exactly the following 16 fields:

["company","title","attack_path","interface","tools_used","types_of_attack",
 "level_of_attack","damage_scenario","cia","impact","feasibility",
 "countermeasures","model_name","model_year","ecu_name","library_name"]

Strict rules:
- Output ONLY a valid JSON array (no markdown, no commentary).
- Use "Unknown" when the description does not provide enough information.
- Do NOT hallucinate automotive details. Only mention ECUs, CAN, IVI, ADAS, sensors,
  or vehicle components when the description clearly supports it.
- If automotive relevance is unclear, keep all automotive-specific fields
  (model_name, model_year, ecu_name, library_name) as "Unknown".

Field rules:
- attack_path = 1–3 steps (attacker entry(attack surface) → action → impact).
- level_of_attack = one of: Physical, Local, Remote, Network-based, Supply-chain, or Unknown.
- cia = any appropriate subset of: Confidentiality, Integrity, Availability.
- impact = Negligible, Moderate, Major, or Severe.
- feasibility = Low, Medium, or High.
- damage_scenario = concise real-world vehicle/system safety impact.
- countermeasures = practical, cybersecurity-focused mitigations.

Numbered Input Descriptions:
{description_block}

Output JSON Array:
[
  {{
    "company": "", "title": "", "attack_path": "", "interface": "",
    "tools_used": "", "types_of_attack": "", "level_of_attack": "",
    "damage_scenario": "", "cia": "", "impact": "", "feasibility": "",
    "countermeasures": "", "model_name": "", "model_year": "",
    "ecu_name": "", "library_name": ""
  }}
]
"""

EXPECTED_FIELDS = [
    "company", "title", "attack_path", "interface", "tools_used", "types_of_attack",
    "level_of_attack", "damage_scenario", "cia", "impact", "feasibility",
    "countermeasures", "model_name", "model_year", "ecu_name", "library_name"
]

DEFAULT_BATCH_SIZE = 5
MAX_RETRIES = 4
INITIAL_BACKOFF = 1.0
MAX_BACKOFF = 30.0
TEMPERATURE = 0.3
MAX_TOKENS = 2000

# ---------------- Helpers ----------------
def make_description_block(descriptions: List[str]) -> str:
    return "\n".join(f"{i+1}. {desc}" for i, desc in enumerate(descriptions))

def call_grok_with_retry(prompt: str) -> Optional[str]:
    backoff = INITIAL_BACKOFF
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = client.chat.completions.create(
                model="grok-3-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
            )
            raw = resp.choices[0].message.content
            if isinstance(raw, dict):
                raw = raw.get("content", "") if raw else ""
            return (raw or "").strip()
        except Exception as exc:
            print(f" Grok call failed (attempt {attempt}/{MAX_RETRIES}): {exc}")
            if attempt == MAX_RETRIES:
                return None
            time.sleep(min(backoff, MAX_BACKOFF))
            backoff *= 2.0
    return None

def extract_json_objects_via_balanced_braces(text: str) -> List[str]:
    objs = []
    stack = 0
    start = None
    for i, ch in enumerate(text):
        if ch == '{':
            if stack == 0: start = i
            stack += 1
        elif ch == '}':
            if stack > 0:
                stack -= 1
                if stack == 0 and start is not None:
                    objs.append(text[start:i+1])
                    start = None
    return objs

def parse_json5_array(raw: str) -> List[Dict[str, Any]]:
    if not raw: return []
    try:
        parsed = json5.loads(raw)
        if isinstance(parsed, list): return parsed
        if isinstance(parsed, dict): return [parsed]
    except Exception: pass

    try:
        first = raw.find('[')
        last = raw.rfind(']')
        if first != -1 and last != -1 and last > first:
            sub = raw[first:last+1]
            parsed = json5.loads(sub)
            if isinstance(parsed, list): return parsed
            if isinstance(parsed, dict): return [parsed]
    except Exception: pass

    objects = extract_json_objects_via_balanced_braces(raw)
    results = []
    for obj_text in objects:
        try:
            parsed = json5.loads(obj_text)
            if isinstance(parsed, dict): results.append(parsed)
        except Exception:
            cleaned = obj_text.strip().rstrip(', \n\r')
            try:
                parsed = json5.loads(cleaned)
                if isinstance(parsed, dict): results.append(parsed)
            except Exception: continue
    return results

def normalize_result_fields(data: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k in EXPECTED_FIELDS:
        val = data.get(k) if isinstance(data, dict) else None
        if val is None:
            out[k] = "Unknown"
        else:
            if isinstance(val, (dict, list)):
                try: out[k] = json5.dumps(val)
                except Exception: out[k] = str(val)
            else:
                s = str(val).strip()
                out[k] = s if s else "Unknown"
    return out

# ---------------- DB helpers ----------------
def connect_db():
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT
    )

def init_target_db(conn):
    """Creates the target table if it doesn't exist."""
    print(f"Ensuring target table {TARGET_TABLE} exists...")
    with conn.cursor() as cur:
        create_sql = f"""
        CREATE TABLE IF NOT EXISTS {TARGET_TABLE} (
            id INTEGER PRIMARY KEY,
            cve_id TEXT,
            source TEXT,
            description TEXT,
            published_date TEXT,
            cvss_score TEXT,
            company TEXT,
            title TEXT,
            attack_path TEXT,
            interface TEXT,
            tools_used TEXT,
            types_of_attack TEXT,
            level_of_attack TEXT,
            damage_scenario TEXT,
            cia TEXT,
            impact TEXT,
            feasibility TEXT,
            countermeasures TEXT,
            model_name TEXT,
            model_year TEXT,
            ecu_name TEXT,
            library_name TEXT
        );
        """
        cur.execute(create_sql)
    conn.commit()

def fetch_unprocessed_rows(conn, limit: int) -> List[Tuple]:
    """Reads rows from source table whose IDs are not yet in target table."""
    with conn.cursor() as cur:
        query = f"""
            SELECT id, cve_id, original_database, year, cvss_score, description 
            FROM {SOURCE_TABLE}
            WHERE id NOT IN (SELECT id FROM {TARGET_TABLE})
            ORDER BY id ASC
            LIMIT %s;
        """
        cur.execute(query, (limit,))
        rows = cur.fetchall()
    return rows

def insert_batch(conn, rows_with_fields: List[Tuple]):
    if not rows_with_fields: return 0
    with conn.cursor() as cur:
        insert_query = f"""
        INSERT INTO {TARGET_TABLE} (
            id, cve_id, source, description, published_date, cvss_score,
            company, title, attack_path, interface, tools_used, types_of_attack,
            level_of_attack, damage_scenario, cia, impact, feasibility,
            countermeasures, model_name, model_year, ecu_name, library_name
        ) VALUES %s
        ON CONFLICT (id) DO NOTHING;
        """
        execute_values(cur, insert_query, rows_with_fields)
    conn.commit()
    return len(rows_with_fields)

# ---------------- Main pipeline ----------------
def generate_fields_for_batch(descriptions: List[str]) -> List[Dict[str, str]]:
    description_block = make_description_block(descriptions)
    prompt = PROMPT_TEMPLATE.format(description_block=description_block)
    raw = call_grok_with_retry(prompt)
    if raw is None: return []
    parsed = parse_json5_array(raw)
    normalized = [normalize_result_fields(p) for p in parsed]
    return normalized

def run_pipeline(batch_size: int = DEFAULT_BATCH_SIZE, dry_run: bool = False):
    print(f" Starting pipeline (BATCH_SIZE={batch_size}, DRY_RUN={dry_run})")
    try:
        conn = connect_db()
    except Exception as e:
        print(f" DB connection failed: {e}")
        return

    # Create target table automatically if needed
    init_target_db(conn)

    total_processed = 0
    total_inserted = 0
    try:
        while True:
            rows = fetch_unprocessed_rows(conn, limit=batch_size)
            if not rows:
                print(" No unprocessed rows found. Done.")
                break

            ids = [r[0] for r in rows]
            print(f"\\n Processing batch of {len(rows)} rows (IDs: {ids})")
            
            # Extract description text exactly like previous scripts
            descriptions = [str(r[5]) if r[5] else "Unknown" for r in rows]

            try:
                results = generate_fields_for_batch(descriptions)
            except Exception as exc:
                print(f" Unexpected error during generation: {exc}")
                traceback.print_exc()
                results = []

            if not results:
                print(" No valid JSON results returned for this batch. Retrying in 1s.")
                time.sleep(1)
                continue

            # Safety: pad/truncate to match rows length
            if len(results) < len(rows):
                print(f" Mismatch: got {len(results)} results for {len(rows)} rows. Padding with Unknown objects.")
                for _ in range(len(rows) - len(results)):
                    results.append({k: "Unknown" for k in EXPECTED_FIELDS})
            elif len(results) > len(rows):
                results = results[:len(rows)]

            # Build rows for DB insert
            rows_to_insert = []
            for row, res in zip(rows, results):
                id_val = row[0]
                cve_id = str(row[1]) if row[1] else "Unknown"
                source_db = str(row[2]) if row[2] else "Unknown"
                
                # Treat '0' year as 'Unknown'
                pd = str(row[3])
                published_date = "Unknown" if pd == "0" or not pd else pd
                
                cvss_sc = str(row[4]).strip() if row[4] else "Unknown"
                if not cvss_sc or cvss_sc == "-\n-": cvss_sc = "Unknown"
                
                desc = str(row[5]) if row[5] else "Unknown"

                nf = normalize_result_fields(res)
                var_tuple = (
                    id_val, cve_id, source_db, desc, published_date, cvss_sc,
                    nf["company"], nf["title"], nf["attack_path"], nf["interface"],
                    nf["tools_used"], nf["types_of_attack"], nf["level_of_attack"],
                    nf["damage_scenario"], nf["cia"], nf["impact"], nf["feasibility"],
                    nf["countermeasures"], nf["model_name"], nf["model_year"],
                    nf["ecu_name"], nf["library_name"]
                )
                rows_to_insert.append(var_tuple)

            if dry_run:
                print("DRY RUN — Sample row to insert:")
                print(rows_to_insert[0])
                total_processed += len(rows_to_insert)
                total_inserted += len(rows_to_insert)
                print(f" Batch complete (DRY RUN). Total processed: {total_processed}")
                # We break after one batch in dry run since DB isn't updated
                break

            try:
                inserted = insert_batch(conn, rows_to_insert)
                total_processed += len(rows)
                total_inserted += inserted
                print(f" Batch complete: inserted {inserted} records. Total processed so far: {total_processed}")
            except Exception as exc:
                print(f" DB insert failed for this batch: {exc}")
                traceback.print_exc()
                time.sleep(1)
                continue

            time.sleep(0.5)

    except KeyboardInterrupt:
        print(" Interrupted by user. Exiting gracefully.")
    except Exception as exc:
        print(f" Pipeline error: {exc}")
        traceback.print_exc()
    finally:
        try: conn.close()
        except: pass
    print(" Pipeline finished. Total rows inserted:", total_inserted)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="process_unique_vulns.py", description="Pipeline to process Unique Automotive DB")
    parser.add_argument("--dry-run", action="store_true", help="Do not write to DB; just simulate")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Batch size (default 5)")
    args = parser.parse_args()
    run_pipeline(batch_size=args.batch_size, dry_run=args.dry_run)

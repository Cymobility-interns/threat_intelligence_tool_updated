#!/usr/bin/env python3
"""
Refactored Grok-based automotive data enhancer (robust JSON parsing).

- Prompt is unchanged from your provided prompt (kept exactly).
- Improved JSON parsing fallback (balanced-brace extractor).
- Uses "Unknown" as the default fill value for missing fields.
- CLI: --dry-run and --batch-size supported.

Usage:
    python refactored_generate_fixed.py
    python refactored_generate_fixed.py --dry-run --batch-size 5
"""

import os
import time
import argparse
from typing import List, Dict, Any, Tuple, Optional
import json5
from openai import OpenAI
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
import sys
import traceback

load_dotenv()

# ---------------- CONFIG ----------------
DB_NAME = os.getenv("PG_DB", "vuldb")
DB_USER = os.getenv("PG_USER", "postgres")
DB_PASS = os.getenv("PG_PASS", "123456")
DB_HOST = os.getenv("PG_HOST", "localhost")
DB_PORT = os.getenv("PG_PORT", "5432")

GROK_API_KEY = os.getenv("XAI_API_KEY")
if not GROK_API_KEY:
    raise RuntimeError("XAI_API_KEY (GROK_API_KEY) not set in environment")

# Client
client = OpenAI(api_key=GROK_API_KEY, base_url="https://api.x.ai/v1")

# ---------------- PROMPT (UNCHANGED) ----------------
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
- level_of_attack = one of: Physical, Local, Remote, Network-based,
  Supply-chain, or Unknown.
- cia = any appropriate subset of: Confidentiality, Integrity, Availability.
  Use only what the description actually justifies.
- impact = Negligible, Moderate, Major, or Severe.
- feasibility = Low, Medium, or High.
- damage_scenario = concise real-world vehicle/system safety impact.
- countermeasures = practical, cybersecurity-focused mitigations.

Numbered Input Descriptions:
{description_block}

Output JSON Array:
[
  {{
    "cve_id":"",
    "source": "",
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
]
"""

EXPECTED_FIELDS = [
    "cve_id",
    "source", 
    "company", 
    "title", 
    "attack_path", 
    "interface", 
    "tools_used", 
    "types_of_attack",
    "level_of_attack", 
    "damage_scenario", 
    "cia", 
    "impact", 
    "feasibility",
    "countermeasures", 
    "model_name", 
    "model_year", 
    "ecu_name", 
    "library_name"
]

# Runtime configs (CLI can override batch size and dry-run)
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
                # some SDKs return structure; convert safely
                raw = raw.get("content", "") if raw else ""
            return (raw or "").strip()
        except Exception as exc:
            print(f" Grok call failed (attempt {attempt}/{MAX_RETRIES}): {exc}")
            if attempt == MAX_RETRIES:
                print(" Max retries reached for Grok call.")
                return None
            time.sleep(min(backoff, MAX_BACKOFF))
            backoff *= 2.0
    return None


def extract_json_objects_via_balanced_braces(text: str) -> List[str]:
    """
    Extract JSON object substrings by scanning for balanced braces.
    This captures {...} occurrences even if the surrounding output isn't a valid array.
    Returns list of object strings (including braces).
    """
    objs = []
    stack = 0
    start = None
    for i, ch in enumerate(text):
        if ch == '{':
            if stack == 0:
                start = i
            stack += 1
        elif ch == '}':
            if stack > 0:
                stack -= 1
                if stack == 0 and start is not None:
                    objs.append(text[start:i+1])
                    start = None
    return objs


def parse_json5_array(raw: str) -> List[Dict[str, Any]]:
    """
    Robust parsing of Grok raw output:
    1) Try json5.loads(raw)
    2) If fails, try to extract substring between first '[' and last ']' and parse
    3) If still fails, extract individual {...} objects by balanced-brace scan and parse each
    Returns list of dicts (may be empty).
    """
    if not raw:
        return []
    # 1) direct parse
    try:
        parsed = json5.loads(raw)
        if isinstance(parsed, list):
            return parsed
        # if it's a dict (single object), wrap it
        if isinstance(parsed, dict):
            return [parsed]
    except Exception:
        pass

    # 2) try array substring
    try:
        first = raw.find('[')
        last = raw.rfind(']')
        if first != -1 and last != -1 and last > first:
            sub = raw[first:last+1]
            parsed = json5.loads(sub)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
    except Exception:
        pass

    # 3) fallback: extract {...} groups using balanced braces
    objects = extract_json_objects_via_balanced_braces(raw)
    results = []
    for obj_text in objects:
        try:
            parsed = json5.loads(obj_text)
            if isinstance(parsed, dict):
                results.append(parsed)
        except Exception:
            # best-effort: attempt to fix simple trailing commas
            cleaned = obj_text.strip().rstrip(', \n\r')
            try:
                parsed = json5.loads(cleaned)
                if isinstance(parsed, dict):
                    results.append(parsed)
            except Exception:
                # can't parse this object - skip but save raw for debugging
                continue
    return results


def normalize_result_fields(data: Dict[str, Any]) -> Dict[str, str]:
    """
    Ensure all EXPECTED_FIELDS exist and return string values.
    Use 'Unknown' for missing/empty values (capitalized per your instruction).
    """
    out: Dict[str, str] = {}
    for k in EXPECTED_FIELDS:
        val = data.get(k) if isinstance(data, dict) else None
        if val is None:
            out[k] = "Unknown"
        else:
            # convert lists/dicts to JSON string, primitives to str
            if isinstance(val, (dict, list)):
                try:
                    out[k] = json5.dumps(val)
                except Exception:
                    out[k] = str(val)
            else:
                s = str(val).strip()
                out[k] = s if s else "Unknown"
    return out


# ---------------- DB helpers ----------------
def connect_db():
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT
    )


def fetch_unprocessed_rows(conn, limit: int) -> List[Tuple]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, cve_id, source, description, published_date, cvss_score "
            "FROM classified_vulnerabilities WHERE processed = false ORDER BY id ASC LIMIT %s;",
            (limit,)
        )
        rows = cur.fetchall()
    return rows


def insert_batch_and_mark_processed(conn, rows_with_fields: List[Tuple]):
    if not rows_with_fields:
        return 0
    with conn.cursor() as cur:
        insert_query = """
        INSERT INTO automotive_vulnerabilities (
            id, cve_id, source, description, published_date, cvss_score,
            company, title, attack_path, interface, tools_used, types_of_attack,
            level_of_attack, damage_scenario, cia, impact, feasibility,
            countermeasures, model_name, model_year, ecu_name, library_name
        ) VALUES %s
        ON CONFLICT (id) DO NOTHING;
        """
        execute_values(cur, insert_query, rows_with_fields)
        ids = [r[0] for r in rows_with_fields]
        cur.execute("UPDATE classified_vulnerabilities SET processed = true WHERE id = ANY(%s);", (ids,))
    conn.commit()
    return len(rows_with_fields)


# ---------------- Main pipeline ----------------
def generate_fields_for_batch(descriptions: List[str]) -> List[Dict[str, str]]:
    description_block = make_description_block(descriptions)
    prompt = PROMPT_TEMPLATE.format(description_block=description_block)
    raw = call_grok_with_retry(prompt)
    if raw is None:
        print(" Grok returned no output (None).")
        return []
    # Save raw for debug if parse fails later
    parsed = parse_json5_array(raw)
    if not parsed:
        # Save debug file for investigation
        try:
            ts = int(time.time())
            debug_file = f"grok_debug_{ts}.txt"
            with open(debug_file, "w", encoding="utf-8") as f:
                f.write(raw)
            print(f" Parsing returned no objects; raw output saved to {debug_file}")
        except Exception:
            pass
    normalized = [normalize_result_fields(p) for p in parsed]
    return normalized


def run_pipeline(batch_size: int = DEFAULT_BATCH_SIZE, dry_run: bool = False):
    print(f" Starting pipeline (BATCH_SIZE={batch_size}, DRY_RUN={dry_run})")
    try:
        conn = connect_db()
    except Exception as e:
        print(f" DB connection failed: {e}")
        return

    total_processed = 0
    try:
        while True:
            rows = fetch_unprocessed_rows(conn, limit=batch_size)
            if not rows:
                print(" No unprocessed rows found. Done.")
                break

            ids = [r[0] for r in rows]
            print(f"\n Processing batch of {len(rows)} rows (IDs: {ids})")
            descriptions = [r[3] or "Unknown" for r in rows]

            try:
                results = generate_fields_for_batch(descriptions)
            except Exception as exc:
                print(f" Unexpected error during generation: {exc}")
                traceback.print_exc()
                results = []

            if not results:
                print(" No results returned for this batch. Skipping these rows for now.")
                # optional: implement retry counter per-row in DB to avoid infinite loop
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
                id_val, cve_id, source, description, published_date, cvss_score = row
                nf = normalize_result_fields(res)
                rows_to_insert.append((
                    id_val, cve_id, source, description, published_date, cvss_score,
                    nf["company"], nf["title"], nf["attack_path"], nf["interface"],
                    nf["tools_used"], nf["types_of_attack"], nf["level_of_attack"],
                    nf["damage_scenario"], nf["cia"], nf["impact"], nf["feasibility"],
                    nf["countermeasures"], nf["model_name"], nf["model_year"],
                    nf["ecu_name"], nf["library_name"]
                ))

            if dry_run:
                print("DRY RUN — sample rows that would be inserted (first 3):")
                for r in rows_to_insert[:3]:
                    print(r)
                total_processed += len(rows_to_insert)
                # In dry-run we do not update DB, but continue to next batch
                continue

            try:
                inserted = insert_batch_and_mark_processed(conn, rows_to_insert)
                total_processed += inserted
                print(f" Batch complete: inserted {inserted} records. Total processed so far: {total_processed}")
            except Exception as exc:
                print(f" DB insert failed for this batch: {exc}")
                traceback.print_exc()
                # safety: do not mark processed if insert failed; move on or retry later
                time.sleep(1)
                continue

            time.sleep(0.5)

    except KeyboardInterrupt:
        print(" Interrupted by user. Exiting gracefully.")
    except Exception as exc:
        print(f" Pipeline error: {exc}")
        traceback.print_exc()
    finally:
        try:
            conn.close()
        except Exception:
            pass
    print(" Pipeline finished.")


# ---------------- CLI ----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="refactored_generate_fixed.py", description="Refactored Grok pipeline (fixed)")
    parser.add_argument("--dry-run", action="store_true", help="Do not write to DB; just simulate")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Batch size (default 5)")
    args = parser.parse_args()
    run_pipeline(batch_size=args.batch_size, dry_run=args.dry_run)

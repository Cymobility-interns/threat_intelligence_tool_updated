#!/usr/bin/env python3
"""
re_enrich_missing.py
--------------------
Targets rows in `automotive_vulnerabilities` where AI-generated fields are
NULL or "Unknown" (i.e., never processed by aigeneration.py), and re-runs
them through Grok to fill in:
  company, title, attack_path, interface, tools_used, types_of_attack,
  level_of_attack, damage_scenario, cia, impact, feasibility,
  countermeasures, model_name, model_year, ecu_name, library_name

Typical use-case: recently ingested 2026 CVEs that skipped the AI pipeline.

Usage:
    python reenrich_missing.py
    python reenrich_missing.py --batch-size 10 --dry-run
    python reenrich_missing.py --year 2026          # only target a specific year
"""

import os
import sys
import time
import argparse
import traceback
from typing import List, Dict, Any, Tuple, Optional

import psycopg2
from psycopg2.extras import execute_values
import json5
from openai import OpenAI
from dotenv import load_dotenv

# ── add project root so dbapp imports work when run standalone ──
_script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.abspath(os.path.join(_script_dir, '..', '..')))

# ── Search for .env in script dir and up to 3 parent dirs ──
def _find_and_load_dotenv():
    search = _script_dir
    for _ in range(4):
        candidate = os.path.join(search, '.env')
        if os.path.isfile(candidate):
            load_dotenv(candidate)
            print(f"[INFO] Loaded .env from: {candidate}")
            return
        search = os.path.dirname(search)
    load_dotenv()  # fallback: try CWD
    print("[WARN] .env not found in parent dirs, tried CWD fallback.")

_find_and_load_dotenv()

# ── DB CONFIG ──
DB_NAME = os.getenv("PG_DB", "vuldbtest")
DB_USER = os.getenv("PG_USER", "postgres")
DB_PASS = os.getenv("PG_PASS", "123456")
DB_HOST = os.getenv("PG_HOST", "localhost")
DB_PORT = os.getenv("PG_PORT", "5432")

# ── GROK CONFIG ──
GROK_API_KEY = os.getenv("XAI_API_KEY")
if not GROK_API_KEY:
    raise RuntimeError("XAI_API_KEY not set in environment")

client = OpenAI(api_key=GROK_API_KEY, base_url="https://api.x.ai/v1")

# ── PIPELINE SETTINGS ──
DEFAULT_BATCH_SIZE = 5
MAX_RETRIES = 4
INITIAL_BACKOFF = 1.0
MAX_BACKOFF = 30.0
TEMPERATURE = 0.3
MAX_TOKENS = 2500

# ── Fields that Grok fills ──
AI_FIELDS = [
    "company", "title", "attack_path", "interface", "tools_used",
    "types_of_attack", "level_of_attack", "damage_scenario", "cia",
    "impact", "feasibility", "countermeasures", "model_name",
    "model_year", "ecu_name", "library_name"
]

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
- attack_path = 1-3 steps (attacker entry(attack surface) -> action -> impact).
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


# ───────────────────────── DB helpers ─────────────────────────

def connect_db():
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASS,
        host=DB_HOST, port=DB_PORT
    )


def fetch_unenriched_rows(conn, limit: int, year: Optional[str] = None) -> List[Tuple]:
    """
    Fetch rows from automotive_vulnerabilities where AI fields are NULL or 'Unknown'.
    Optionally filter by CVE year or published_date year.
    """
    year_filter = ""
    params: list = []

    if year:
        year_filter = """
          AND (
            cve_id ILIKE %s
            OR EXTRACT(YEAR FROM published_date)::TEXT = %s
          )
        """
        params = [f"CVE-{year}-%", year]

    params.append(limit)

    sql = f"""
        SELECT id, cve_id, source, description, published_date, cvss_score
        FROM automotive_vulnerabilities
        WHERE (
            title IS NULL OR title = 'Unknown' OR title = ''
            OR attack_path IS NULL OR attack_path = 'Unknown' OR attack_path = ''
            OR company IS NULL OR company = 'Unknown' OR company = ''
        )
        {year_filter}
        ORDER BY id ASC
        LIMIT %s;
    """
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def update_enriched_row(conn, row_id: int, fields: Dict[str, str]):
    """UPDATE the existing row with the AI-generated fields."""
    set_clause = ", ".join(f"{k} = %s" for k in AI_FIELDS)
    values = [fields.get(k, "Unknown") for k in AI_FIELDS]
    values.append(row_id)
    sql = f"UPDATE automotive_vulnerabilities SET {set_clause} WHERE id = %s;"
    with conn.cursor() as cur:
        cur.execute(sql, values)
    conn.commit()


# ───────────────────────── Grok helpers ─────────────────────────

def call_grok(prompt: str) -> Optional[str]:
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
            return (raw or "").strip()
        except Exception as exc:
            print(f"  Grok call failed (attempt {attempt}/{MAX_RETRIES}): {exc}")
            if attempt == MAX_RETRIES:
                return None
            time.sleep(min(backoff, MAX_BACKOFF))
            backoff *= 2.0
    return None


def extract_json_objects(text: str) -> List[str]:
    """Extract balanced {...} blocks from text."""
    objs, stack, start = [], 0, None
    for i, ch in enumerate(text):
        if ch == '{':
            if stack == 0:
                start = i
            stack += 1
        elif ch == '}' and stack > 0:
            stack -= 1
            if stack == 0 and start is not None:
                objs.append(text[start:i + 1])
                start = None
    return objs


def parse_grok_output(raw: str) -> List[Dict[str, Any]]:
    if not raw:
        return []
    # Try direct parse
    try:
        parsed = json5.loads(raw)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except Exception:
        pass
    # Try array substring
    try:
        first, last = raw.find('['), raw.rfind(']')
        if first != -1 and last > first:
            parsed = json5.loads(raw[first:last + 1])
            if isinstance(parsed, list):
                return parsed
    except Exception:
        pass
    # Balanced-brace fallback
    results = []
    for obj_text in extract_json_objects(raw):
        try:
            parsed = json5.loads(obj_text)
            if isinstance(parsed, dict):
                results.append(parsed)
        except Exception:
            pass
    return results


def normalize(data: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k in AI_FIELDS:
        val = data.get(k)
        if val is None:
            out[k] = "Unknown"
        elif isinstance(val, (dict, list)):
            try:
                out[k] = json5.dumps(val)
            except Exception:
                out[k] = str(val)
        else:
            s = str(val).strip()
            out[k] = s if s else "Unknown"
    return out


def enrich_batch(descriptions: List[str]) -> List[Dict[str, str]]:
    block = "\n".join(f"{i + 1}. {d}" for i, d in enumerate(descriptions))
    prompt = PROMPT_TEMPLATE.format(description_block=block)
    raw = call_grok(prompt)
    if raw is None:
        return []
    parsed = parse_grok_output(raw)
    if not parsed:
        print("  [WARN] Grok returned unparseable output.")
        return []
    return [normalize(p) for p in parsed]


# ───────────────────────── Main pipeline ─────────────────────────

def run_reenrichment(batch_size: int = DEFAULT_BATCH_SIZE,
                     dry_run: bool = False,
                     year: Optional[str] = None):
    target_msg = f"year={year}" if year else "all missing"
    print(f"\n Re-Enrichment Pipeline starting (batch={batch_size}, dry_run={dry_run}, target={target_msg})\n")

    try:
        conn = connect_db()
    except Exception as e:
        print(f" DB connection failed: {e}")
        return

    total_updated = 0
    try:
        while True:
            rows = fetch_unenriched_rows(conn, limit=batch_size, year=year)
            if not rows:
                print(" No more unenriched rows found. Done!")
                break

            ids = [r[0] for r in rows]
            print(f" Processing {len(rows)} rows | IDs: {ids}")
            descriptions = [r[3] or "No description available." for r in rows]

            try:
                results = enrich_batch(descriptions)
            except Exception as exc:
                print(f" Batch error: {exc}")
                traceback.print_exc()
                results = []

            if not results:
                print(" No results from Grok. Skipping batch.")
                time.sleep(2)
                continue

            # Pad if Grok returned fewer results than rows
            if len(results) < len(rows):
                print(f" Padding {len(rows) - len(results)} missing results with 'Unknown'")
                for _ in range(len(rows) - len(results)):
                    results.append({k: "Unknown" for k in AI_FIELDS})
            results = results[:len(rows)]

            for row, res in zip(rows, results):
                id_val, cve_id = row[0], row[1]
                if dry_run:
                    print(f"  [DRY-RUN] Would update ID={id_val} ({cve_id}) → title={res.get('title','?')}")
                else:
                    try:
                        update_enriched_row(conn, id_val, res)
                        total_updated += 1
                        print(f"  [UPDATED] ID={id_val} ({cve_id}) → title: {res.get('title', 'Unknown')}")
                    except Exception as exc:
                        print(f"  [ERROR] Failed to update ID={id_val}: {exc}")

            if dry_run:
                total_updated += len(rows)

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n Interrupted. Exiting.")
    except Exception as exc:
        print(f" Pipeline error: {exc}")
        traceback.print_exc()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    print(f"\n Re-enrichment complete. Total records updated: {total_updated}")


# ───────────────────────── CLI ─────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Re-enrich automotive_vulnerabilities rows where AI fields are missing/Unknown"
    )
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                        help="Number of rows per Grok call (default: 5)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate without writing to DB")
    parser.add_argument("--year", type=str, default=None,
                        help="Filter by CVE year (e.g. 2026). Matches CVE-2026-* or published_date year")
    args = parser.parse_args()
    run_reenrichment(batch_size=args.batch_size, dry_run=args.dry_run, year=args.year)

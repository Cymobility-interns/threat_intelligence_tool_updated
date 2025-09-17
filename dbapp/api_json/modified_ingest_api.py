import requests
import time
from datetime import datetime, timezone, timedelta, date
from sqlalchemy.orm import Session
from dbapp.database import get_session
from dbapp.models import Vulnerability, SyncState
from dbapp.api_json.custom_utils import parse_cve_item, chunk_date_ranges
from dbapp.config import settings


BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_modified_cves():
    """
    Incremental ingestion.
    Fetches CVEs modified since the last successful sync.
    Includes new and updated CVEs.
    """

    session: Session = get_session()

    # --- Get last sync state ---
    sync_state = session.query(SyncState).filter_by(source="NVD").first()
    if not sync_state or not sync_state.last_synced:
        print("⚠️ No previous sync found. Run custom_ingest_api first.")
        session.close()
        return

    # Assume sync_state.last_synced is a date
    start_date = sync_state.last_synced

    # Convert date → datetime with UTC
    if isinstance(start_date, date) and not isinstance(start_date, datetime):
        start_date = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc)

    # Add 1 second to avoid refetching the same last record
    start_date += timedelta(seconds=1)

    # End date is current UTC datetime
    end_date = datetime.now(timezone.utc)


    print(f" Fetching CVEs modified from {start_date} → {end_date}")

    # Split into 120-day chunks
    date_ranges = chunk_date_ranges(start_date, end_date, chunk_size_days=120)
    total_chunks = len(date_ranges)
    total_updated = 0

    for i, (chunk_start, chunk_end) in enumerate(date_ranges, start=1):
        print(f"\n🔹 Processing chunk {i}/{total_chunks} "
              f"({chunk_start.date()} → {chunk_end.date()})")

        params = {
            "lastModStartDate": chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "lastModEndDate": chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "resultsPerPage": 2000,
            "startIndex": 0,
        }

        total_results = None
        fetched = 0

        while True:
            print(f"  Fetching {params['resultsPerPage']} CVEs "
                  f"starting at index {params['startIndex']}...")

            # --- Robust request with retries ---
            retries = 5
            for attempt in range(retries):
                try:
                    headers = {"X-ApiKey": settings.NVD_API_KEY}
                    response = requests.get(BASE_URL, params=params, headers=headers, timeout=30)
                    response.raise_for_status()
                    break
                except requests.exceptions.HTTPError as e:
                    if response.status_code == 429:  # Rate limit
                        wait_time = int(response.headers.get("Retry-After", 60))
                        print(f"     Rate limited. Waiting {wait_time} seconds...")
                        time.sleep(wait_time)
                    elif response.status_code == 404:
                        print(f"     404 Not Found for URL: {response.url}")
                        return
                    else:
                        print(f"     HTTP error {response.status_code}: {e}")
                        return
                except requests.exceptions.RequestException as e:
                    wait_time = 2 ** attempt
                    print(f"     Request failed (attempt {attempt+1}/{retries}): {e}. "
                          f"Retrying in {wait_time}s...")
                    time.sleep(wait_time)
            else:
                print("     Max retries reached. Skipping this chunk.")
                break

            # --- Process JSON response ---
            data = response.json()

            if total_results is None:
                total_results = data.get("totalResults", 0)
                print(f"  Total CVEs in this chunk: {total_results}")

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                print("  No vulnerabilities returned. Stopping chunk.")
                break

            # Parse & insert/update CVEs
            objects = []
            for item in vulnerabilities:
                vuln_dict = parse_cve_item(item)
                if vuln_dict:
                    obj = Vulnerability(**vuln_dict)
                    objects.append(obj)

            for obj in objects:
                if obj.cve_id:
                    existing = session.query(Vulnerability).filter_by(cve_id=obj.cve_id).first()
                    if existing:
                        # Update fields
                        for key, value in obj.__dict__.items():
                            if key not in ("id", "_sa_instance_state"):
                                setattr(existing, key, value)
                    else:
                        session.add(obj)
                else:
                    session.add(obj)
            session.commit()

            fetched += len(objects)
            total_updated += len(objects)
            print(f"  Inserted/Updated {fetched}/{total_results} CVEs so far in this chunk")

            if fetched >= total_results:
                break

            params["startIndex"] += params["resultsPerPage"]

        print(f" Finished chunk {i}/{total_chunks}: Updated {fetched} CVEs")

        # --- Update sync_state after successful chunk ---
        # sync_state.last_successful_sync = chunk_end
        # sync_state.last_run = datetime.now(timezone.utc)
        # session.commit()

        sync_state.last_synced = chunk_end.date()
        sync_state.last_run = datetime.now(timezone.utc)
        session.commit()

    session.close()
    print(f"\n Incremental sync complete! Total CVEs inserted/updated: {total_updated}")


if __name__ == "__main__":
    fetch_modified_cves()

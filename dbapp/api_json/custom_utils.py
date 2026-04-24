from datetime import datetime, timedelta


def parse_date(date_str):
    """Convert API date string to datetime (UTC)."""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        return None


def parse_cve_item(item):
    """Map NVD CVE item (wrapped or raw) to our DB schema."""
    if not item:
        return None

    cve = item.get("cve") if "cve" in item else item
    cve_id = cve.get("id")

    description = None
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value")
            break

    metrics = cve.get("metrics", {})
    severity, cvss_score = None, None
    try:
        if "cvssMetricV40" in metrics:
            metric = metrics["cvssMetricV40"][0]["cvssData"]
        elif "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            metric = metrics["cvssMetricV30"][0]["cvssData"]
        elif "cvssMetricV2" in metrics:
            metric = metrics["cvssMetricV2"][0]["cvssData"]
        else:
            metric = None
        if metric:
            severity = metric.get("baseSeverity")
            cvss_score = metric.get("baseScore")
    except Exception:
        pass

    refs = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]

    return {
        "cve_id": cve_id,
        "source": "NVD",
        "description": description,
        "published_date": parse_date(cve.get("published")),
        "modified_date": parse_date(cve.get("lastModified")),
        "severity": severity,
        "cvss_score": cvss_score,
        "reference_links": refs if refs else None,
    }


def chunk_date_ranges(start_date, end_date, chunk_size_days=120):
    """
    Split date range into chunks of given size (default: 120 days).
    Returns list of (chunk_start, chunk_end).
    """
    chunks = []
    current = start_date
    while current < end_date:
        chunk_end = min(current + timedelta(days=chunk_size_days - 1), end_date)
        chunks.append((current, chunk_end))
        current = chunk_end + timedelta(days=1)
    return chunks

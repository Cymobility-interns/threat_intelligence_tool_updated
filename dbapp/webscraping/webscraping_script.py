import os
import re
import cloudscraper
import urllib.robotparser
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from transformers import pipeline
import psycopg2
from datetime import datetime
from dotenv import load_dotenv
import nltk

# ---------------- NLTK Setup ---------------- #
nltk.download("punkt", quiet=True)
nltk.download("punkt_tab", quiet=True)
from nltk.tokenize import sent_tokenize # pyright: ignore[reportMissingImports]

# ---------------- Load Environment Variables ---------------- #
load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432"),
    "dbname": os.getenv("DB_NAME", "vuldbtest"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "123456"),
}

from transformers import pipeline, AutoTokenizer, AutoModelForSeq2SeqLM

# ---------------- AI Helpers ---------------- #
try:
    summarizer_tokenizer = AutoTokenizer.from_pretrained("facebook/bart-base")
    summarizer_model = AutoModelForSeq2SeqLM.from_pretrained("facebook/bart-base")

    def summarizer(text_input, max_length=60, min_length=10, do_sample=False):
        inputs = summarizer_tokenizer([text_input], max_length=1024, truncation=True, return_tensors="pt")
        summary_ids = summarizer_model.generate(inputs["input_ids"], max_length=max_length, min_length=min_length, do_sample=do_sample)
        summary_text = summarizer_tokenizer.batch_decode(summary_ids, skip_special_tokens=True, clean_up_tokenization_spaces=False)[0]
        return [{"summary_text": summary_text}]
except Exception as e:
    print(f"[AI ERROR] Failed to load local summarizer model: {e}")
    # Fallback if summarizer completely fails to load
    def summarizer(text_input, **kwargs):
        return [{"summary_text": text_input[:500]}]
attack_detector = pipeline(
    "zero-shot-classification", model="valhalla/distilbart-mnli-12-1"
)


def classify_attack(text: str):
    """Classify severity using zero-shot model and map to CVSS score."""
    labels = [
        "low severity vulnerability",
        "medium severity vulnerability",
        "high severity vulnerability",
        "critical severity vulnerability",
        "not a vulnerability",
    ]
    if not text.strip():
        return "none", 0.0

    try:
        result = attack_detector(text[:1000], labels)
        label = result["labels"][0].lower()
        confidence = result["scores"][0]
    except Exception as e:
        print(f"[AI ERROR] Classification failed: {e}")
        return "none", 0.0

    if "critical" in label:
        cvss = 9.0 + confidence * (10.0 - 9.0)
    elif "high" in label:
        cvss = 7.0 + confidence * (8.9 - 7.0)
    elif "medium" in label:
        cvss = 4.0 + confidence * (6.9 - 4.0)
    elif "low" in label:
        cvss = 0.1 + confidence * (3.9 - 0.1)
    else:
        cvss = 0.0

    return label, round(cvss, 1)


def clean_description(text: str, max_chars=1000) -> str:
    """Trim text neatly at sentence boundaries."""
    sentences = sent_tokenize(text)
    clean_text, total = [], 0
    for sent in sentences:
        if total + len(sent) + 1 <= max_chars:
            clean_text.append(sent.strip())
            total += len(sent) + 1
        else:
            break
    return " ".join(clean_text).strip()


def extract_article_date(html: str):
    """Try multiple strategies to extract a publish date."""
    soup = BeautifulSoup(html, "html.parser")
    selectors = [
        {"attr": "property", "value": "article:published_time"},
        {"attr": "name", "value": "date"},
        {"attr": "name", "value": "pubdate"},
        {"attr": "itemprop", "value": "datePublished"},
    ]
    for sel in selectors:
        tag = soup.find("meta", {sel["attr"]: sel["value"]})
        if tag and tag.get("content"):
            return tag["content"].split("T")[0]

    time_tag = soup.find("time")
    if time_tag and time_tag.get("datetime"):
        return time_tag["datetime"].split("T")[0]
    return None


def process_vulnerability(text, url="", html=""):
    """Extract CVE, generate description, classify severity & CVSS."""
    cve_match = re.findall(r"CVE-\d{4}-\d+", text)
    cve_id = cve_match[0] if cve_match else "Not Available"
    pub_date = extract_article_date(html) if html else None

    if cve_id != "Not Available":
        description = clean_description(text[:2000])
    else:
        try:
            description = (
                summarizer(
                    text[:2000], max_length=60, min_length=10, do_sample=False
                )[0]["summary_text"]
                if text.strip()
                else "No valid article content extracted"
            )
            description = clean_description(description)
        except Exception as e:
            print(f"[AI ERROR] Summarizer failed for {url}: {e}")
            description = (
                clean_description(text[:1000])
                if text.strip()
                else "No description available"
            )
            
    _, cvss = classify_attack(description)
    if cvss >= 9.0:
        severity = "critical"
    elif cvss >= 7.0:
        severity = "high"
    elif cvss >= 4.0:
        severity = "medium"
    elif cvss >= 0.1:
        severity = "low"
    else:
        severity = "none"

    return (
        cve_id,
        url,
        description,
        pub_date,
        None,  # modified_date
        severity,
        cvss,
        None,  # reference_links
        datetime.now().isoformat(),
        datetime.now().isoformat(),
    )


# ---------------- Scraper ---------------- #
class SafeScraper:
    def __init__(self, user_agent="MyScraperBot"):
        self.user_agent = user_agent
        self.scraper = cloudscraper.create_scraper()

    def _get_robots_url(self, url):
        parsed_url = urlparse(url)
        return f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"

    def can_scrape(self, url):
        # Bypassing robots.txt check to allow scraping security news sites
        # rp = urllib.robotparser.RobotFileParser()
        # rp.set_url(self._get_robots_url(url))
        # try:
        #     rp.read()
        # except Exception as e:
        #     print(f"[WARN] Could not fetch robots.txt: {e}")
        return True
        # return rp.can_fetch(self.user_agent, url)

    def get_page(self, url):
        if not self.can_scrape(url):
            print(f"[BLOCKED] Scraping not allowed: {url}")
            return None
        try:
            response = self.scraper.get(url, timeout=15)
            response.raise_for_status()
            print(f"[OK] Fetched: {url}")
            print(f"[DEBUG] Response Type: {type(response)}")
            print(f"[DEBUG] Response Attributes: {dir(response)}")
            return response.text
        except Exception as e:
            print(f"[ERROR] Fetching {url}: {e}")
            return None


# ---------------- Database Helpers ---------------- #
def db_connect():
    return psycopg2.connect(**DB_CONFIG)


def url_exists_in_db(url, table_name="classified_vulnerabilities"):
    try:
        with db_connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"SELECT 1 FROM {table_name} WHERE source = %s LIMIT 1;",
                (url,),
            )
            return cur.fetchone() is not None
    except Exception as e:
        print(f"[DB ERROR] Check failed for {url}: {e}")
        return False


def safe_insert(conn, table, values):
    cur = conn.cursor()
    try:
        placeholders = ", ".join(["%s"] * len(values))
        query = f"INSERT INTO {table} VALUES (DEFAULT, {placeholders})"
        cur.execute(query, values)
        conn.commit()
        print(f"[DB] Inserted: {values[1]}")
    except Exception as e:
        print(f"[DB ERROR] Insert failed: {e}")
        conn.rollback()
    finally:
        cur.close()


def save_to_postgres(data_list, table_name="classified_vulnerabilities"):
    try:
        with db_connect() as conn:
            for data in data_list:
                safe_insert(conn, table_name, data)
        print(f"[DB] {len(data_list)} records saved successfully to {table_name}!")
    except Exception as e:
        print(f"[DB ERROR] Save failed: {e}")


# ---------------- Main Runner ---------------- #
if __name__ == "__main__":
    scraper = SafeScraper()
    automotive_websites = [
        "https://www.thesun.co.uk/motors/25104889/thieves-keyless-steal-mercedes-car-harrow-london/",
        "https://www.thesun.co.uk/news/24837650/thieves-rolls-royce-aerial-clone-key/",
        "https://www.securityweek.com/tesla-car-hacked-remotely-drone-zero-click-exploit/",
        "https://arstechnica.com/information-technology/2022/06/hackers-out-to-steal-a-tesla-can-create-their-very-own-personal-key/",
        "https://electrek.co/2023/03/24/tesla-hacked-winning-hackers-model-3/",
        "https://thehackernews.com/2022/10/european-police-arrest-gang-that-hacked.html",
        "https://cybersecurityventures.com/hacking-into-cars-new-techniques-emerge/",
        "https://edgelabs.ai/blog/edge-computing-top-cyber-attacks-in-2021-2022-for-the-automotive-industry/",
        "https://www.mylondon.news/news/north-london-news/three-gang-members-jailed-sophisticated-22475212",
        "https://www.wired.com/story/electric-vehicle-charging-station-hacks/",
        "https://www.forbes.com/forbes/2002/0708/148.html?sh=56683d566b49",
        "https://thehackernews.com/2014/08/hacking-traffic-lights-is-amazingly_20.html",
        "https://www.networkworld.com/article/756954/cisco-subnet-defcon-hacking-tire-pressure-monitors-remotely.html",
        "https://www.kaspersky.com/about/press-releases/2014_connected-cars-are-now-a-reality-but-are-they-secure",
        "https://money.cnn.com/2015/08/14/technology/volkswagen-car-hacking/",
        "https://www.bbc.com/news/technology-36444586",
        "https://www.vice.com/en/article/av478z/how-las-traffic-system-got-hacked",
        "https://gizmodo.com/security-researchers-hack-reviver-digital-license-plate-1849967297",
        "https://www.vice.com/en/article/akv7z5/how-a-hacker-controlled-dozens-of-teslas-using-a-flaw-in-third-party-app",
        "https://www.the-parallax.com/tesla-radar-model-3-phone-key-ibeacon/",
        "https://www.nassiben.com/phantoms",
        "https://www.abc.net.au/news/2019-11-06/ract-employee-pleads-guilty-to-using-app-to-stalk-ex-girlfriend/11678980",
        "https://www.vice.com/en/article/zmpx4x/hacker-monitor-cars-kill-engine-gps-tracking-apps",
        "https://www.the-parallax.com/hacker-ford-key-fob-vulnerability/",
        "https://www.caranddriver.com/news/a30260730/chevy-volt-hacked-data-collection/",
        "https://www.caranddriver.com/news/a34762383/tesla-model-x-hack-steal/",
        "https://www.wired.com/story/mycar-remote-start-vulnerabilities/",
        "https://www.theguardian.com/money/2014/oct/27/thieves-range-rover-keyless-locking",
        "https://hackaday.com/2022/07/18/hacker-liberates-hyundai-head-unit-writes-custom-apps/",
        "https://www.wired.com/story/cryptojacking-tesla-amazon-cloud/",
        "https://www.liverpoolecho.co.uk/news/liverpool-news/gang-used-clone-key-signals-21005457",
        "https://www.thisismoney.co.uk/money/cars/article-7800957/Expensive-cars-stolen-owners-driveways-sold-1-000-black-market.html",
        "https://www.theguardian.com/technology/2016/sep/20/tesla-model-s-chinese-hack-remote-control-brakes",
        "https://www.techradar.com/news/kia-motors-usa-reportedly-hit-by-huge-ransomware-campaign",
        "https://www.computerworld.com/article/2971826/hack-to-steal-cars-with-keyless-ignition-volkswagen-spent-2-years-hiding-flaw.html",
        "https://www.dailymaverick.co.za/article/2022-01-25-teen-tesla-hacker-accessed-owners-email-addresses-to-warn-them/",
        "https://www.bleepingcomputer.com/news/security/kia-motors-america-suffers-ransomware-attack-20-million-ransom/",
        "https://www.telegraph.co.uk/technology/2022/06/13/west-broke-grip-lamborghini-driving-russian-hackers/",
        "https://www.theverge.com/2021/10/21/22738747/tesla-driving-data-hack-dutch-investigators-autopilot",
        "https://www.cnbc.com/2019/04/03/chinese-hackers-tricked-teslas-autopilot-into-switching-lanes.html",
        "https://carbuzz.com/news/how-hackers-can-take-control-of-your-steering-wheel",
        "https://www.wired.com/2017/04/just-pair-11-radio-gadgets-can-steal-car/",
        "https://www.wired.com/story/hackers-steal-tesla-model-s-seconds-key-fob/",
        "https://www.bleepingcomputer.com/news/security/toyota-security-breach-exposes-personal-info-of-31-million-clients/",
        "https://www.bbc.com/news/technology-35642749",
        "https://www.express.co.uk/life-style/cars/806889/Keyless-entry-car-keys-hack-theft-warning",
        "https://www.motorbiscuit.com/how-thieves-are-stealing-the-chevrolet-silverado-so-quickly/",
        "https://www.theregister.com/2022/08/17/software_developer_cracks_hyundai_encryption/",
        "https://www.theguardian.com/technology/2023/dec/26/hackers-steal-customer-data-europe-parking-app-easypark-ringgo-parkmobile",
        "https://www.bbc.com/news/technology-52982427",
        "https://www.thenationalnews.com/business/carmaker-nissan-says-uk-plant-hit-by-ransomware-attack-1.69769",
        "https://www.bbc.com/news/technology-58011014",
        "https://thehackernews.com/2016/08/hack-unlock-car-door.html",
        "https://thehackernews.com/2016/09/hack-tesla-autopilot.html",
        "https://hackaday.com/2022/11/28/ev-chargers-could-be-a-serious-target-for-hackers/",
        "https://spectrum.ieee.org/ev-hacks",
        "https://www.theguardian.com/business/2022/sep/06/go-ahead-cyberattack-bus-services-thameslink-rail",
        "https://www.technadu.com/nottingham-city-transport-victim-service-disrupting-cyberattack/290218/",
        "https://www.cbc.ca/news/canada/toronto/ttc-ransomware-attack-1.6231349",
        "https://www.hawaiinewsnow.com/2021/12/09/city-bus-handi-van-servers-down-due-possible-cyber-attack/",
        "https://www.icelandreview.com/news/straeto-was-hit-by-cyber-attack/",
        "https://passenger.tech/news/the-2023-cyber-attack-on-transport-that-went-largely-unnoticed/",
        "https://therecord.media/pierce-transit-washington-ransomware-attack-lockbit",
        "https://www.rnz.co.nz/news/national/498003/suspected-cyberattack-crashes-auckland-transport-card-network",
        "https://www.bleepingcomputer.com/news/security/montreals-stm-public-transport-system-hit-by-ransomware-attack/",
        "https://www.clickondetroit.com/all-about-ann-arbor/2021/11/01/ann-arbors-theride-bus-system-impacted-by-recent-cyberattack/",
        "https://www.nytimes.com/2021/06/02/nyregion/mta-cyber-attack.html",
        "https://www.itsecurityguru.org/2020/12/04/vancouver-public-transport-agency-hit-by-ransomware-attack/",
        "https://www.businesstoday.in/latest/trends/story/pakistani-bike-hailing-app-bykea-hacked-users-get-abusive-messages-while-logging-in-385476-2023-06-13",
        "https://www.ccjdigital.com/technology/video/15542339/truck-hacking-a-new-age-road-hazard",
        "https://lloydslist.com/LL1134044/CMA-CGM-confirms-ransomware-attack",
        "https://www.freightwaves.com/news/news-alert-forward-air-reveals-ransomware-attack-warns-of-revenue-hit",
        "https://www.freightwaves.com/news/daseke-targeted-in-cyberattack",
        "https://www.usatoday.com/story/money/cars/2024/01/03/key-fob-hack-metal-can/72076687007/",
        "https://www.indiatvnews.com/technology/news-cybercriminals-hack-electric-bikes-spy-users-know-how-583496",
        "https://carbuzz.com/news/hackers-are-starting-to-target-ev-charging-stations",
        "https://www.motorbiscuit.com/a-ukrainian-company-hacked-russian-ev-charging-stations-to-protest-the-invasion/",
        "https://cluballiance.aaa.com/the-extra-mile/articles/prepare/car/can-electric-cars-be-hacked",
        "https://www.komando.com/security-privacy/hackers-targeting-evs/891154/",
        "https://portswigger.net/daily-swig/car-companies-massively-exposed-to-web-vulnerabilities",
        "https://hackaday.com/2023/06/08/hacking-a-hyundai-ioniqs-infotainment-system-again-after-security-fixes/",
        "https://www.cpomagazine.com/cyber-security/nearly-10-million-drivers-license-holders-exposed-in-the-oregon-dmv-and-louisiana-omv-cyber-attack/",
        "https://www.bleepingcomputer.com/news/security/toyota-warns-customers-of-data-breach-exposing-personal-financial-info/",
        "https://www.securityweek.com/researchers-find-exploitable-bugs-mercedes-benz-cars/",
        "https://www.bleepingcomputer.com/news/security/hyundai-motor-europe-hit-by-black-basta-ransomware-attack/",
        "https://www.securityweek.com/vulnerability-in-toyota-management-platform-provided-access-to-customer-data/",
        "https://www.securityweek.com/german-auto-and-defense-firm-rheinmetall-says-malware-hit-several-plants/",
        "https://www.computerweekly.com/news/252477247/Travelex-hackers-shut-down-German-car-parts-company-Gedia-in-massive-cyber-attack",
        "https://www.theregister.com/2022/02/01/oiltrading/",
        "https://www.bleepingcomputer.com/news/security/orbcomm-ransomware-attack-causes-trucking-fleet-management-outage/",
        "https://therecord.media/knp-logistics-ransomware-insolvency-uk",
        "https://cybernews.com/security/after-refusing-to-pay-ransom-us-based-auto-parts-distributor-has-sensitive-data-leaked-by-cybercriminals/",
        "https://www.bleepingcomputer.com/news/security/qilin-ransomware-claims-attack-on-automotive-giant-yanfeng/",
        "https://cyberscoop.com/fleet-management-vulnerability-digitial-communications-technologies/",
        "https://cybernews.com/news/bmw-france-data-breach-ransomware-victim/",
        "https://thecyberexpress.com/cyberattack-on-bmw-munique-motors/",
        "https://cybernews.com/news/car-hackers-arrested-grand-theft-auto/",
        "https://cybernews.com/news/ferrari-hit-by-ransomware-data-leaked/",
        "https://www.autocar.co.uk/car-news/business/volkswagen-locking-software-hacked-researchers-millions-cars-implicated",
        "https://sensorstechforum.com/ivi-systems-volkswagen-audi-vulnerable/",
        "https://blog.vensis.pl/2019/11/vw-hacking/",
        "https://www.hackster.io/news/hacking-a-car-s-key-fob-with-a-rolljam-attack-7f863c10c8da",
        "https://www.vice.com/en/article/xgxaq4/hackers-are-selling-data-stolen-from-audi-and-volkswagen",
        "https://www.theregister.com/2023/09/28/volkswagen_crippled_it_disruption/",
        "https://www.theregister.com/2018/07/23/car_factory_rsync_server_leak/",
        "https://www.skynews.com.au/australia-news/how-australians-datahoovering-chinese-madecars-could-be-secretly-sending-their-private-data-to-the-communist-nation/news-story/d4e3afdb160eab42fa173ac26f19dfd9",
        "https://www.theregister.com/2022/05/17/ble_vulnerability_lets_attackers_steal/",
        "https://github.com/advisories/GHSA-27c3-9rq9-x65x",
        "https://www.securityweek.com/vulnerability-exposed-tesla-central-touchscreen-dos-attacks/",
        "https://www.zdnet.com/article/tesla-car-hacked-at-pwn2own-contest/",
        "https://www.theregister.com/2018/05/23/bmw_security_bugs/",
        "https://in.mashable.com/tech/7773/the-mercedes-benz-app-accidentally-gave-people-access-to-strangers-personal-info",
        "https://medium.com/@windsormoreira/xentry-retail-data-storage-v7-8-1-denial-of-service-cve-2023-23590-60b65f5fa358",
        "https://keenlab.tencent.com/en/2021/05/12/Tencent-Security-Keen-Lab-Experimental-Security-Assessment-on-Mercedes-Benz-Cars/",
        "https://github.com/advisories/GHSA-pgx7-89g7-j29c",
        "https://www.scip.ch/en/?labs.20180405",
        "https://github.com/advisories/GHSA-4cc7-pcqm-mp56",
        "https://www.cnet.com/roadshow/news/hyundai-patches-blue-link-app-to-remove-vulnerabilities/",
        "https://www.cvedetails.com/cve/CVE-2019-9493/",
        "https://www.rapid7.com/blog/post/2024/01/03/genie-aladdin-connect-retrofit-garage-door-opener-multiple-vulnerabilities/",
        "https://github.com/advisories/GHSA-fxfh-x86p-h99g",
        "https://github.com/advisories/GHSA-w6gv-63rm-rv7h",
        "https://github.com/advisories/GHSA-5c48-qxrh-hrpg",
        "https://github.com/advisories/GHSA-hhwc-fxxw-wfmx",
        "https://github.com/advisories/GHSA-595w-7wc6-v6g8",
        "https://techxplore.com/news/2023-11-stellantis-production-affected-cyberattack-auto.html",
        "https://github.com/advisories/GHSA-cw66-q853-7m23",
        "https://github.com/advisories/GHSA-28p7-rxh6-3h6x",
        "https://github.com/advisories/GHSA-8g5q-mp2w-j766",
        "https://github.com/advisories/GHSA-v96f-28cg-5h5p",
        "https://github.com/advisories/GHSA-6fpg-44rr-wcfj",
        "https://github.com/advisories/GHSA-c457-8wp3-h45c",
        "https://github.com/advisories/GHSA-mf42-cj9f-vmhp",
        "https://www.bleepingcomputer.com/news/security/mitm-phishing-attack-can-let-attackers-unlock-and-steal-a-tesla/",
        "https://www.bleepingcomputer.com/news/security/chinese-researchers-hack-tesla-model-x-in-impressive-video/",
        "https://www.bleepingcomputer.com/news/security/hyundai-patches-mobile-app-flaws-that-allow-hackers-to-steal-cars/",
        "https://www.bleepingcomputer.com/news/security/millions-of-smart-cars-vulnerable-due-to-insecure-android-apps/",
        "https://www.bleepingcomputer.com/news/security/suspect-arrested-for-hacking-goget-car-sharing-service/",
        "https://www.bleepingcomputer.com/news/security/honda-bug-lets-a-hacker-unlock-and-start-your-car-via-replay-attack/",
        "https://www.bleepingcomputer.com/news/security/hacker-sells-129-million-sensitive-records-of-russian-car-owners/",
        "https://www.bleepingcomputer.com/news/security/nissan-is-investigating-cyberattack-and-potential-data-breach/",
        "https://www.bleepingcomputer.com/news/security/bmw-infiltrated-by-hackers-hunting-for-automotive-trade-secrets/",
        "https://www.bleepingcomputer.com/news/security/wireless-hack-threatens-locking-system-on-nearly-all-vw-cars-sold-since-1995/",
        "https://www.bleepingcomputer.com/news/security/steel-giant-thyssenkrupp-confirms-cyberattack-on-automotive-division/",
        "https://www.bleepingcomputer.com/news/security/honda-bug-allows-hackers-to-unlock-and-start-cars-from-afar/",
        "https://www.bleepingcomputer.com/news/security/siriusxm-flaw-could-let-hackers-remotely-unlock-start-smart-cars/",
        "https://www.darkreading.com/vulnerabilities-threats/siriusxm-vulnerability-allows-remote-hijacking-of-honda-nissan-fca-vehicles",
        "https://www.wired.com/story/sirius-xm-car-hack/",
        "https://thehackernews.com/2022/07/researchers-uncover-vulnerabilities-in.html",
        "https://www.securityweek.com/hackers-can-remotely-hijack-hyundai-genesis-vehicles-via-app-flaw/",
        "https://www.wired.com/story/hyundai-genesis-car-hack/",
        "https://thehackernews.com/2022/11/researchers-detail-new-attack-that.html",
        "https://www.bleepingcomputer.com/news/security/new-relay-attack-lets-hackers-steal-most-modern-cars/",
        "https://www.darkreading.com/iot/new-relay-attack-targets-tesla-model-3-keyless-entry-system",
        "https://www.securityweek.com/tesla-releases-update-to-prevent-relay-attacks/",
        "https://www.wired.com/story/tesla-key-fob-hack-relay-attack/",
        "https://thehackernews.com/2021/08/researchers-find-new-flaws-in-blackberry.html",
        "https://www.bleepingcomputer.com/news/security/cisa-warns-of-critical-flaws-in-blackberry-qnx-rtos-used-in-cars/",
        "https://www.darkreading.com/vulnerabilities-threats/blackberry-qnx-vulnerabilities-expose-medical-automotive-devices",
        "https://www.wired.com/story/blackberry-qnx-vulnerability-badalloc/",
        "https://www.securityweek.com/vulnerability-in-mercedes-benz-infotainment-system-exposes-sensitive-data/",
        "https://thehackernews.com/2021/05/critical-vulnerability-found-in.html",
        "https://www.bleepingcomputer.com/news/security/flaw-in-mercedes-benz-cars-allowed-hackers-to-remotely-start-engine/",
        "https://www.darkreading.com/vulnerabilities-threats/mercedes-benz-fixes-flaws-that-could-let-hackers-start-car-engines",
        "https://thehackernews.com/2020/08/mercedes-benz-car-hacking.html",
        "https://www.securityweek.com/hackers-find-vulnerabilities-in-volkswagen-audi-infotainment-systems/",
        "https://www.wired.com/story/volkswagen-audi-car-hack-vulnerabilities/",
        "https://www.darkreading.com/vulnerabilities-threats/siriusxm-flaw-leaves-honda-nissan-fca-cars-open-to-remote-hijacking",
        "https://thehackernews.com/2022/11/hackers-could-have-unlocked-and-started.html",
        "https://www.bleepingcomputer.com/news/security/hackers-uncover-flaws-in-siriusxm-connected-vehicle-services/",
        "https://www.securityweek.com/vulnerabilities-in-siriusxm-connected-vehicle-services-exposed-cars-to-remote-attacks/",
        "https://www.wired.com/story/siriusxm-vulnerability-connected-cars/",
        "https://threatpost.com/siriusxm-flaw-remote-hijacking-cars/176921/",
        "https://www.cyberscoop.com/siriusxm-vulnerability-honda-nissan-fca/",
        "https://www.bleepingcomputer.com/news/security/relay-attack-vulnerability-discovered-in-dozens-of-car-models/",
        "https://www.darkreading.com/iot/ble-relay-attacks-target-keyless-entry-systems-in-modern-vehicles",
        "https://thehackernews.com/2023/04/new-ble-relay-attack-can-unlock-teslas.html",
        "https://www.wired.com/story/tesla-bluetooth-relay-attack/",
        "https://www.securityweek.com/new-relay-attack-method-can-bypass-tesla-pin-to-drive-feature/",
        "https://www.bleepingcomputer.com/news/security/hackers-can-steal-keyless-cars-in-seconds-using-ble-relay-attacks/",
        "https://threatpost.com/keyless-entry-cars-vulnerable-to-ble-relay-attacks/175834/",
        "https://www.darkreading.com/vulnerabilities-threats/researchers-demonstrate-ble-relay-attack-against-ford-mustang-mach-e",
        "https://www.wired.com/story/hackers-can-steal-your-car-with-a-cheap-radio/",
        "https://www.bleepingcomputer.com/news/security/cisa-issues-advisory-for-blackberry-qnx-vulnerability-affecting-medical-and-automotive-devices/",
        "https://www.darkreading.com/vulnerabilities-threats/blackberry-qnx-rtos-vulnerability-exposes-critical-systems-to-attack",
        "https://thehackernews.com/2021/08/critical-badalloc-flaw-in-blackberry.html",
        "https://www.securityweek.com/blackberry-qnx-vulnerability-impacts-millions-of-devices-including-cars/",
        "https://www.wired.com/story/blackberry-qnx-badalloc-vulnerability/",
        "https://threatpost.com/blackberry-qnx-rtos-vulnerability-medical-automotive/168759/",
        "https://www.cyberscoop.com/blackberry-qnx-vulnerability-cisa-warning/",
        "https://www.bleepingcomputer.com/news/security/ford-toyota-and-volkswagen-investigate-blackberry-qnx-vulnerability/",
        "https://www.darkreading.com/iot/automakers-scramble-to-patch-blackberry-qnx-flaw-in-connected-cars"
    ]

    iot_websites = [
        "https://thehackernews.com/2023/11/new-bluetooth-flaw-lets-hackers-take.html",
        "https://thehackernews.com/2023/10/critical-flaw-in-widely-used-iot.html",
        "https://www.bleepingcomputer.com/news/security/new-iot-botnet-infects-smart-devices-to-launch-ddos-attacks/",
        "https://www.wired.com/story/iot-hacks-smart-home-vulnerabilities/",
        "https://thehackernews.com/2024/01/critical-auth-bypass-flaw-in-bosch-iot.html",
        "https://www.bleepingcomputer.com/news/security/tp-link-smart-bulbs-can-let-hackers-steal-your-wifi-password/",
        "https://www.bleepingcomputer.com/news/security/critical-vulnerabilities-found-in-popular-gps-trackers/",
        "https://www.darkreading.com/iot/new-critical-vulnerability-discovered-in-millions-of-iot-devices",
        "https://threatpost.com/iot-botnet-targets-routers/165432/",
        "https://www.securityweek.com/hackers-exploit-zero-day-in-embedded-systems/"
    ]

    tasks = [
        (automotive_websites, "classified_vulnerabilities"),
        (iot_websites, "classified_iot_embedded_vulnerabilities")
    ]

    for websites_list, table_name in tasks:
        results = []
        for site in set(websites_list):  # remove duplicates
            if url_exists_in_db(site, table_name):
                print(f"[SKIP] Already processed in {table_name}: {site}")
                continue

            html = scraper.get_page(site)
            if not html:
                continue

            soup = BeautifulSoup(html, "html.parser")
            article_text = " ".join(p.get_text() for p in soup.find_all("p"))
            data = process_vulnerability(article_text, site, html)
            results.append(data)

        print(f"\n[FINISHED] Processed {len(results)} new sites for {table_name}.")
        if results:
            save_to_postgres(results, table_name)
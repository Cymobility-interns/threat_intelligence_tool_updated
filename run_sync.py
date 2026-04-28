import subprocess
import sys
import os

def main():
    print("="*60)
    print("  🚀 Starting Automated Threat Intelligence Pipeline 🚀")
    print("="*60)

    # Make sure we are executing from the root directory so imports work
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)
    
    # --- 1. Run NVD Incremental Update ---
    # This automatically picks up from the last synced date saved in the database
    print("\n[1/2] Fetching incremental updates from NVD...")
    nvd_cmd = [sys.executable, "-m", "dbapp.api_json.modified_ingest_api"]
    
    try:
        subprocess.run(nvd_cmd, check=True)
    except subprocess.CalledProcessError:
        print("\n❌ NVD Sync encountered an error. Stopping pipeline.")
        sys.exit(1)

    # --- 2. Run Web Scraping ---
    # This automatically skips URLs that are already present in the database
    print("\n[2/2] Running web scraper for new automotive & IoT articles...")
    scraper_cmd = [sys.executable, "-m", "dbapp.webscraping.webscraping_script"]
    
    try:
        subprocess.run(scraper_cmd, check=True)
    except subprocess.CalledProcessError:
        print("\n❌ Web scraping encountered an error.")
        sys.exit(1)
        
    print("\n" + "="*60)
    print("  ✅ All pipelines completed successfully! ✅")
    print("="*60)

if __name__ == "__main__":
    main()

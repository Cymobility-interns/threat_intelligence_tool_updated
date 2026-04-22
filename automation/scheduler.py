import logging
import sys
from apscheduler.schedulers.background import BackgroundScheduler
from pathlib import Path

# Add project root to path so we can import run_pipeline
import sys
import os
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    import run_pipeline
except ImportError:
    run_pipeline = None
    logging.error("Could not import run_pipeline. Make sure it exists in the project root.")

# Configure logging for the scheduler
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()

def pipeline_job():
    logger.info("Starting scheduled AI Ingestion Pipeline...")
    if run_pipeline:
        try:
            run_pipeline.main()
            logger.info("Scheduled AI Ingestion Pipeline completed successfully.")
        except Exception as e:
            logger.error(f"Error running pipeline: {e}")
    else:
        logger.error("Pipeline script not found. Skipping execution.")

def start_scheduler():
    """
    Initializes and starts the APScheduler.
    Configured to run daily at 2:00 AM.
    """
    if scheduler.running:
        logger.warning("Scheduler is already running.")
        return

    # Schedule the job to run every day at 2:00 AM
    scheduler.add_job(
        pipeline_job,
        trigger='cron',
        hour=2,
        minute=0,
        id='ai_pipeline_job',
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("Scheduler started. Pipeline will run daily at 02:00 AM.")

def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler shut down.")

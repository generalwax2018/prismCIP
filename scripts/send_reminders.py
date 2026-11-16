"""Send due reminders for every organization. For cron or Task Scheduler if the in-app daily job is turned off
(PRISMCIP_REMINDERS=off). Run: python -m scripts.send_reminders"""
import os

from app.catalog import seed_requirements
from app.db import Base, SessionLocal, auto_migrate, engine
from app.reminders import run_all

if __name__ == "__main__":
    Base.metadata.create_all(engine)
    auto_migrate()
    with SessionLocal() as db:
        seed_requirements(db)
        print(run_all(db, base_url=os.environ.get("PRISMCIP_BASE_URL", "")))

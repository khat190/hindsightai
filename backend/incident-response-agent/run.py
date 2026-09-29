"""Start the API:  python run.py   (or: uvicorn app.main:app --reload)"""
import os

import uvicorn

from app.config import load_dotenv

if __name__ == "__main__":
    load_dotenv()
    uvicorn.run("app.main:app", host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")),
                reload=os.environ.get("RELOAD", "false").lower() == "true")

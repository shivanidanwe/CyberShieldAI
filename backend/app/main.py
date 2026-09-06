from fastapi import FastAPI

from app.database import engine
from app.models import Base

Base.metadata.create_all(bind=engine)

app = FastAPI()


@app.get("/")
def home():
    return {
        "message": "CyberShield AI SOC Running"
    }
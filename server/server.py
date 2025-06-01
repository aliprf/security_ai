from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
from starlette.requests import Request

from agents.orch import SecurityAnalysisPipeline
from commons.incident_context import (
    IncidentContext,
)
from commons.logger import get_logger
from config import Config

logger = get_logger(__name__)

app = FastAPI()


@app.get("/")
def read_root() -> dict:
    return {"message": "SecurityAnalyzer API is running."}


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_incident(request: Request) -> dict:
    try:
        json_data = await request.json()
        context = IncidentContext(**json_data)
        logger.info("Valid incident received, invoking agent...")

        pipeline = SecurityAnalysisPipeline(model_name=Config.get_model_name())
        report = pipeline.run(
            context.model_dump_json(),
        )  # yes, I know thats not good, will fix it :D
        logger.info(report)

    except ValidationError as ve:
        msg = f"Validation error: {ve}"
        logger.exception(msg)
        raise HTTPException(status_code=400, detail=str(ve)) from ve
    except Exception as e:
        logger.exception("Unexpected error during analysis")
        raise HTTPException(status_code=500, detail=str(e)) from e
    else:
        return {"report": report}

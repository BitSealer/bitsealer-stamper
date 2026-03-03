from fastapi import FastAPI

from app.api.routes import router
from app.core.logging import get_logger
from app.services.ots_service import require_ots
from app.core.config import settings

log = get_logger("stamper")


def create_app() -> FastAPI:
    app = FastAPI(title="BitSealer Stamper", version="0.9.0")  # nuevo verify

    @app.on_event("startup")
    def on_startup():
        require_ots()
        log.info("Stamper listo. calendars=%s", settings.OTS_CALENDARS)

    app.include_router(router)

    return app


app = create_app()
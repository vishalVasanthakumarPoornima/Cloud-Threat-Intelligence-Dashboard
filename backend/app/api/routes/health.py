from fastapi import APIRouter

from app.core.config import SettingsDep

router = APIRouter()


@router.get("/health")
async def health(settings: SettingsDep):
    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": settings.app_env,
    }

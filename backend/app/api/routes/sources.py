from fastapi import APIRouter

from app.core.config import SettingsDep
from app.connectors import CONNECTOR_DEFINITIONS

router = APIRouter()


@router.get("/sources/status")
async def sources_status(settings: SettingsDep):
    return {
        "sources": [
            {
                "name": definition.name,
                "supported_ioc_types": sorted(definition.supported_ioc_types),
                "configured": definition.is_configured(settings),
            }
            for definition in CONNECTOR_DEFINITIONS
        ]
    }

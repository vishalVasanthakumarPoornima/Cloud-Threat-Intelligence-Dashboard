from pydantic import BaseModel, ConfigDict, Field


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ioc: str = Field(
        min_length=1,
        max_length=2048,
        description="IP address, domain, URL, or file hash to analyze.",
    )

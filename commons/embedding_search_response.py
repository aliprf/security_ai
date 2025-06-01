from __future__ import annotations

from pydantic import BaseModel, Field


class EmbeddingSearchResponse(BaseModel):
    entity: BaseModel = Field(
        ...,
    )
    score: float = Field(0.0)

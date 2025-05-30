from __future__ import annotations

from pydantic import BaseModel, Field


class SoftwareInfo(BaseModel):
    name: str = Field(...)
    version: str | None = Field(default=None)


class AssetInfo(BaseModel):
    name: str = Field(...)
    ip: str | None = Field(default=None)
    os: str | None = Field(default=None)
    software: list[SoftwareInfo] = Field(...)
    role: str | None = Field(default=None)


class IncidentContext(BaseModel):
    incident_id: str = Field(...)
    timestamp: str | None = Field(default=None)
    summary: str = Field(...)
    description: str | None = Field(default=None)
    affected_assets: list[AssetInfo] = Field(...)
    observed_ttps: list[str] = Field(...)
    ioc_ips: list[str] = Field(...)
    ioc_usernames: list[str] = Field(...)
    inferred_software: list[str] = Field(...)
    inferred_cves: list[str] = Field(...)
    initial_findings: str | None = Field(default=None)

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
    summary: str | None = Field(default=None)
    description: str | None = Field(default=None)
    affected_assets: list[AssetInfo] | None = Field(default=None)
    observed_ttps: list[str] | None = Field(default=None)
    ioc_ips: list[str] | None = Field(default=None)
    ioc_usernames: list[str] | None = Field(default=None)
    inferred_software: list[str] | None = Field(default=None)
    inferred_cves: list[str] | None = Field(default=None)
    initial_findings: str | None = Field(default=None)

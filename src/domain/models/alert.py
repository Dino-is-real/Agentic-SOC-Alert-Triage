"""Normalized Alert Domain Models and Schemas."""
from datetime import datetime, timezone
from typing import Optional, Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from src.domain.enums import AlertSourceFormat, AlertSeverity


class NormalizedNetworkContext(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    bytes_in: Optional[int] = Field(None, ge=0)
    bytes_out: Optional[int] = Field(None, ge=0)
    dns_query: Optional[str] = None
    http_uri: Optional[str] = None
    flags: list[str] = Field(default_factory=list)


class NormalizedEndpointContext(BaseModel):
    hostname: Optional[str] = None
    agent_id: Optional[str] = None
    os_type: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    file_path: Optional[str] = None
    registry_key: Optional[str] = None


class NormalizedIdentityContext(BaseModel):
    username: Optional[str] = None
    user_id: Optional[str] = None
    user_domain: Optional[str] = None
    auth_status: Optional[str] = None
    mfa_used: Optional[bool] = None
    src_geo_country: Optional[str] = None
    src_geo_city: Optional[str] = None
    is_privileged: Optional[bool] = None


class NormalizedCloudContext(BaseModel):
    cloud_provider: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    resource_arn: Optional[str] = None
    event_source: Optional[str] = None
    event_name: Optional[str] = None


class NormalizedAlert(BaseModel):
    alert_id: UUID = Field(default_factory=uuid4)
    source_format: AlertSourceFormat
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str = Field(..., min_length=1, description="Rule title or signature")
    raw_severity: AlertSeverity
    category: str = Field(default="uncategorized")
    description: str = Field(default="")
    network: NormalizedNetworkContext = Field(default_factory=NormalizedNetworkContext)
    endpoint: NormalizedEndpointContext = Field(default_factory=NormalizedEndpointContext)
    identity: NormalizedIdentityContext = Field(default_factory=NormalizedIdentityContext)
    cloud: NormalizedCloudContext = Field(default_factory=NormalizedCloudContext)
    raw_payload: dict[str, Any] = Field(default_factory=dict)

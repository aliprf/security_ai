from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional

from commons.attack_patterns import ExternalReference


class Relationship(BaseModel):
    id: str = Field(..., description="Unique STIX ID for the relationship object")
    type: str = Field(..., description="STIX object type (should be 'relationship')")
    
    relationship_type: str = Field(..., description="Type of relationship (e.g., uses, indicates, etc.)")
    source_ref: str = Field(..., description="STIX ID of the source object")
    target_ref: str = Field(..., description="STIX ID of the target object")
    
    description: Optional[str] = Field(None, description="Optional description of the relationship")
    created_by_ref: Optional[str] = Field(None, description="Reference to the identity that created the object")
    object_marking_refs: Optional[list[str]] = Field(None, description="List of marking definitions")
    external_references: Optional[list[ExternalReference]] = Field(None, description="List of external references")

    created: Optional[datetime] = Field(None, description="Timestamp of object creation")
    modified: Optional[datetime] = Field(None, description="Timestamp of last modification")
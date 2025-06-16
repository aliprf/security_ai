from enum import Enum

from pydantic import BaseModel, Field


class Role(str, Enum):
    system = "system"
    human = "human"


class AIChatModel(BaseModel):
    role: Role = Field(..., description="Role of the user in the conversation ")
    message: str = Field(..., description="Message to be sent to the model.")

class AIChatMessages(BaseModel):
    messages: list[AIChatModel]


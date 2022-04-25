from typing import Optional, Union
from pydantic import BaseModel


class Permission(BaseModel):
    id: Optional[Union[str,int]]
    name: str
    
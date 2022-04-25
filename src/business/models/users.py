from typing import Optional, Union, List
from pydantic import BaseModel

from .permissions import Permission

class User(BaseModel):
    id: Optional[Union[str, int]]
    email: str
    username: Optional[str]
    password: str
    permissions: List[Permission]


from numbers import Number
from typing import Optional

from pydantic import BaseModel


class CommonDependencies():
    def __init__(self, page: Optional[int] = 1, size: Optional[int] = 20):
        self.page = page
        self.size = size

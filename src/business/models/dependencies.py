from typing import Optional

class CommonDependencies():
    def __init__(self, page: Optional[str] = 1, size: Optional[int] = 20):
        self.page = page
        self.size = size

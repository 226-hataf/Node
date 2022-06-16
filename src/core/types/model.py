from typing import List, Optional

from pydantic import BaseModel


class ZKModelPermission(BaseModel):
    create: List[str]
    read: List[str]
    delete: List[str]
    update: List[str]
    list: List[str]

class ZKModel(BaseModel):
    name: str
    plural: str
    permissions: Optional[ZKModelPermission]

    def get_model_pk(self):
        pk = [f for f in self.fields if f.pk]
        if len(pk)>0:
            return pk
        else:
            return None
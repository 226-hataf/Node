from typing import Dict, Optional

from pydantic import BaseModel


class ZKModelPermission(BaseModel):
    create: list[str]
    read: list[str]
    delete: list[str]
    update: list[str]

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
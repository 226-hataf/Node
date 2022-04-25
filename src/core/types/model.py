from typing import List

from pydantic import BaseModel


class ZKModelField(BaseModel):
    name: str
    pk: bool

class ZKModel(BaseModel):
    name: str
    plural: str
    fields: List[ZKModelField]

    def get_model_pk(self):
        pk = [f for f in self.fields if f.pk]
        if len(pk)>0:
            return pk
        else:
            return None
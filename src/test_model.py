import pytest
import pydantic
from business.models.users import User


def test_user_model_proper():
    pm = User(id="test_id", email="test@example.com", first_name="ezgisu", last_name="tuncel")
    assert pm.id == "test_id"
    assert pm.email == "test@example.com"
    assert pm.first_name == "ezgisu"
    assert pm.last_name == "tuncel"
    assert pm.full_name =="ezgisu tuncel"

def test_user_model_improper():
    with pytest.raises(pydantic.ValidationError):
        user = User(email="useless")
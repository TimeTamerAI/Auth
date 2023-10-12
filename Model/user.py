from pydantic import BaseModel
from tortoise import fields
from tortoise.models import Model


class User(Model):
    """
    User model for storing user related details
    This defines the database table
    """

    id = fields.IntField(pk=True)
    firebase_uid = fields.CharField(max_length=255, unique=True)
    name = fields.TextField()
    email = fields.CharField(max_length=255, unique=True, null=True)


class UserProfile(BaseModel):
    """
    This defines the pydantic model validation
    """

    firebase_uid: str
    name: str
    email: str

from tortoise import Tortoise

DATABASE_URL = "postgres://auth_user:auth_pass@db:5432/auth_db"


async def init_db():
    await Tortoise.init(
        db_url=DATABASE_URL,
        modules={"models": ["Model.user"]},  # Point to your models here
    )
    await Tortoise.generate_schemas()


async def close_db():
    await Tortoise.close_connections()

from fastapi import FastAPI

from app.database import Base, engine
from app.routers import admin, auth, users

# Dev convenience: create tables at startup. Replace with Alembic for real migrations.
Base.metadata.create_all(bind=engine)

app = FastAPI(title="User Management 2.0")

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)

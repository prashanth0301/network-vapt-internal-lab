"""Bootstrap script: create the first administrator account.

Usage:
    # Seed with default credentials:
    python scripts/create_admin.py

    # Custom credentials:
    python scripts/create_admin.py --username admin --password Admin@123

Default credentials (.env overridable):
    Username: admin
    Email:    admin@networkvapt.local
    Password: Admin@123
    Role:     administrator

Run this once after the backend starts to create the initial admin user.
Skip if the user already exists (idempotent).
"""
import asyncio
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.database import async_session_factory
from app.services.auth.auth_service import AuthService
from sqlalchemy import select
from app.models.user import User


async def main():
    parser = argparse.ArgumentParser(description="Create the first admin user")
    parser.add_argument("--username", default="admin", help="Admin username")
    parser.add_argument("--email", default="admin@networkvapt.local", help="Admin email")
    parser.add_argument("--password", default="Admin@123", help="Admin password")
    args = parser.parse_args()

    auth_service = AuthService()

    async with async_session_factory() as session:
        result = await session.execute(
            select(User).where(User.username == args.username)
        )
        if result.scalar_one_or_none():
            print(f"User '{args.username}' already exists — skipping creation.")
            return

        user = await auth_service.create_user(
            session,
            username=args.username,
            email=args.email,
            password=args.password,
            full_name="System Administrator",
            role="administrator",
        )
        await session.commit()
        print(f"Admin user created:")
        print(f"  Username: {user.username}")
        print(f"  Email:    {user.email}")
        print(f"  Role:     {user.role}")


if __name__ == "__main__":
    asyncio.run(main())

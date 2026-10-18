#!/usr/bin/env python3
"""Encrypt legacy plaintext webhook signing secrets in place.

Dry-run is the default. Set the production encryption key in the environment and
pass --apply only after taking a verified database backup.
"""

from __future__ import annotations

import argparse
import os
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from data_protection import encrypt_value
from models import WebhookConfig


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write encrypted values (default: report only)",
    )
    args = parser.parse_args()

    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        parser.error("DATABASE_URL must be set")
    if not (
        os.getenv("PESAGUARD_PAYLOAD_ENCRYPTION_KEY")
        or os.getenv("PROVIDER_ENCRYPTION_KEY")
    ):
        parser.error(
            "Set PESAGUARD_PAYLOAD_ENCRYPTION_KEY before migrating webhook secrets"
        )

    engine = create_engine(database_url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    try:
        records = session.query(WebhookConfig).filter(
            WebhookConfig.signing_secret.isnot(None)
        ).all()
        plaintext_records = [
            record
            for record in records
            if isinstance(record.signing_secret, str)
            and not record.signing_secret.startswith("enc:v1:")
        ]
        print(f"Webhook records inspected: {len(records)}")
        print(f"Legacy plaintext secrets found: {len(plaintext_records)}")
        if not args.apply:
            print("Dry-run only; no database values changed. Re-run with --apply to migrate.")
            return 0

        for record in plaintext_records:
            record.signing_secret = encrypt_value(record.signing_secret)
        session.commit()
        print(f"Encrypted secrets migrated: {len(plaintext_records)}")
        return 0
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        engine.dispose()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Do not print connection strings or exception details that could expose
        # credentials from the database URL.
        print(f"Webhook-secret migration failed ({type(exc).__name__}).", file=sys.stderr)
        raise SystemExit(1)

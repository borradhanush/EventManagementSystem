"""Manually clear local application data while preserving the SQLite schema."""

import sqlite3
import sys
from pathlib import Path

from database import DATABASE_PATH


def _quote_identifier(name):
    """Quote a SQLite identifier obtained from sqlite_master."""
    return '"' + name.replace('"', '""') + '"'


def _is_application_table(name):
    """Exclude SQLite internals and conventional schema migration history."""
    lowered = name.casefold()
    if lowered.startswith("sqlite_"):
        return False
    if lowered in {"alembic_version", "schema_migrations"} or "migration" in lowered:
        return False
    return True


def reset_application_data(database_path=None):
    """Delete rows from application tables transactionally; return row totals.

    The path is optional for isolated tests. Normal manual use always takes
    the project's existing DATABASE_PATH and never initializes a database.
    """
    path = Path(database_path) if database_path is not None else Path(DATABASE_PATH)
    if not path.is_file():
        raise FileNotFoundError(f"Configured SQLite database does not exist: {path}")

    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        # Defer FK checks until all application rows have been removed. This
        # handles dependent and circular relationships without dropping FKs.
        connection.execute("PRAGMA defer_foreign_keys = ON")

        table_names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            if _is_application_table(row[0])
        ]
        before_counts = {}
        for name in table_names:
            before_counts[name] = connection.execute(
                f"SELECT COUNT(*) FROM {_quote_identifier(name)}"
            ).fetchone()[0]

        for name in table_names:
            connection.execute(f"DELETE FROM {_quote_identifier(name)}")

        # sqlite_sequence stores counters rather than application records.
        # Clear only counters belonging to application tables, preserving the
        # table itself and all schema objects.
        has_sequence = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'"
        ).fetchone()
        if has_sequence and table_names:
            placeholders = ",".join("?" for _ in table_names)
            connection.execute(
                f"DELETE FROM sqlite_sequence WHERE name IN ({placeholders})",
                table_names,
            )

        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise sqlite3.IntegrityError(
                f"Reset would leave {len(violations)} foreign-key violation(s)."
            )
        connection.commit()
        return before_counts
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def main():
    print("WARNING: This will permanently delete ALL application data from the local test database.")
    try:
        confirmation = input("Type RESET to continue: ")
    except (EOFError, KeyboardInterrupt):
        print("Reset cancelled. No data was changed.")
        return 1
    if confirmation != "RESET":
        print("Reset cancelled. No data was changed.")
        return 0

    try:
        cleared = reset_application_data()
    except Exception as error:
        print(f"Reset failed; the transaction was rolled back. {error}", file=sys.stderr)
        return 1

    total = sum(cleared.values())
    print(f"Reset complete. Removed {total} application row(s) from {len(cleared)} table(s):")
    for name, row_count in cleared.items():
        print(f"  {name}: {row_count} row(s)")
    print("The database file, schema, indexes, constraints, and migration history were preserved.")
    print("No Root account was created. Use `python app.py create-root` separately if needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Vulnerable sample application used by the secpatch test suite."""
import os

API_KEY = "sk-1234567890abcdef"


def get_user(db, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = db.execute(query)
    return cursor.fetchall()


def config_value(raw):
    return eval(raw)

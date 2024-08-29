#!/usr/bin/env python3
"""A password encryption module
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Applies a random salt to hash a password.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Verifies if a given password matches the hashed password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

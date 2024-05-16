#!/usr/bin/env python3
"""
Task - Encrypting passwords
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    hashes the password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hash_password: bytes, password: str) -> bool:
    """
    checks for password validity
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

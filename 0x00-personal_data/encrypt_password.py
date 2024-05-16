#!/usr/bin/env python3
"""
Task - Encrypting passwords
"""
import bcrypt


def hash_password(password: str) => bytes:
    """
    Salted password generation!!
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hash_password: bytes, password: str) -> bool:
    """
    Is password valid??
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

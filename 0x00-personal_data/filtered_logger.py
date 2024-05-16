#!/usr/bin/env python3
"""
script for all tasks
"""
import re
import os
import logging
import mysql.connector
from typing import List


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    returns the log message
    """
    pat = '|'.join('{}=[^{}]*'.format(field, separator) for field in fields)
    return re.sub(pat, lambda m: m.group().split('=')[0] + '=' + redaction,
                  message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """formatting fields"""
        result = super(RedactingFormatter, self).format(record)
        message = filter_datum(self.fields, self.REDACTION,
                               result, self.SEPARATOR)
        return message


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def get_logger() -> logging.Logger:
    """
    gets logs from csv
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    connects to a secure db
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    name_db = os.getenv("PERSONAL_DATA_DB_NAME", "")
    connection = mysql.connector.connecttion.MySQLConnection(user=username,
                                                             password=password,
                                                             host=host,
                                                             port=3306,
                                                             database=name_db)
    return connection


def main():
    """
    main func
    """
    db = get_db()
    curs = db.cursor()
    curs.execute("SELECT * FROM users;")
    f_name = [a[0] for a in curs.description]
    log = get_logger()
    for rows in curs:
        s_rows = ''.join(f'{b}={str(c)}; ' for b, c in zip(rows, f_name))
        log.info(s_rows.strip())
    curs.close()
    db.close()


if __name__ == "__main__":
    main()

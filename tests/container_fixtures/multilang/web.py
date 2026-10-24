import os
import sqlite3


def run_command(command):
    return os.system(command)


def find_user(connection: sqlite3.Connection, user_id):
    return connection.execute(f"SELECT * FROM users WHERE id = {user_id}")

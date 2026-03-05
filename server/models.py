import sqlite3
import os

DB_PATH = "/app/db/server.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            blob_path TEXT NOT NULL,
            nonce TEXT NOT NULL,
            tag TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_control (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            wrapped_dek TEXT NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(file_id, user_id)
        )
    """)

    conn.commit()
    conn.close()
import sqlite3
from pathlib import Path

from flask import current_app, g
from werkzeug.security import generate_password_hash


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db(app):
    @app.teardown_appcontext
    def close_db(error=None):
        db = g.pop('db', None)
        if db is not None:
            db.close()

    with app.app_context():
        db = get_db()
        db.executescript(Path(__file__).with_name('schema.sql').read_text())
        if db.execute('SELECT 1 FROM "User" WHERE UserName = ?', ('phat',)).fetchone() is None:
            # Public, synthetic lab fixture for localhost only; not a personal account.
            db.execute('INSERT INTO "User" (UserName, Password) VALUES (?, ?)',
                       ('phat', generate_password_hash('Phat@123')))
        db.commit()

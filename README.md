# Novel Writer

A private, multi-account manuscript editor. Each account has its own chapters,
notes, story bible, and writing settings stored in a local SQLite database.

## Run locally

Requires Python 3. The server uses only the Python standard library.

```sh
python3 server.py
```

Open <http://127.0.0.1:8000/> and create an account. The database is created as
`novel_writer.sqlite3` beside `server.py`. Set `PORT`, `HOST`, or
`NOVEL_WRITER_DB` to change the listening address or database location.

Passwords are stored as salted PBKDF2 hashes, and browser sessions use an
HTTP-only cookie. For use by multiple people over a network, run behind an
HTTPS reverse proxy and keep the database file private and backed up.
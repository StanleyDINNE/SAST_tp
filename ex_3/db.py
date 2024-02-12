
import sqlite3
from passlib.hash import pbkdf2_sha256

def db_init():

    users = [
        ('admin', pbkdf2_sha256.encrypt('123456')),
        ('john', pbkdf2_sha256.encrypt('Password')),
        ('tim', pbkdf2_sha256.encrypt('Vaider2'))
    ]

    conn = sqlite3.connect('users.sqlite')
    c = conn.cursor()
    c.execute("DROP TABLE users")
    c.execute("CREATE TABLE users (user text, password text, failures int)")

    c.executemany("INSERT INTO users (user, password, failures) VALUES (?, ?, '0')", users)

    conn.commit()
    conn.close()


if __name__ == '__main__':
    db_init()

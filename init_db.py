import sqlite3

conn = sqlite3.connect("database.db")
c = conn.cursor()

c.execute("""
CREATE TABLE users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT,
password TEXT,
role TEXT,
name TEXT,
email TEXT,
phone TEXT,
staff_id TEXT,
department TEXT,
pfp TEXT
)
""")
c.execute("""
CREATE TABLE flights(
id INTEGER PRIMARY KEY AUTOINCREMENT,
flight_number TEXT,
departure TEXT,
destination TEXT,
gate TEXT,
time TEXT,
status TEXT
)
""")

c.execute("""
CREATE TABLE passengers(
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
passport TEXT,
flight_id INTEGER,
seat TEXT
)
""")

c.execute("""
CREATE TABLE baggage(
id INTEGER PRIMARY KEY AUTOINCREMENT,
tag TEXT,
passenger_id INTEGER,
flight_id INTEGER,
weight INTEGER,
extra_weight INTEGER,
price INTEGER,
status TEXT,
location TEXT
)
""")

import sqlite3


c.execute("""
CREATE TABLE IF NOT EXISTS security_alerts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
alert TEXT,
time TEXT
)
""")

c.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'scrypt:32768:8:1$57AcwWh08SkgYzrY$7736c1d40f586bfd2d6abbc6d836b7d498bd16ab85833a8e2d24f174d0d3ff4bfbfd04b55129a0fba5df6764292dd85c713ff11c31e8cc15fc3ba1f23712e06c
', 'admin')")
c.execute("INSERT INTO flights VALUES(NULL,'TU123','Tunis','Paris','A2','10.26','ON TIME')")

conn.commit()
conn.close()

print("Database created")

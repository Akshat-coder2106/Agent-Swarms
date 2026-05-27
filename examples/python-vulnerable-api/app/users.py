from __future__ import annotations

import sqlite3
import pickle
import os
import random
import yaml
from flask import Flask, request, send_file, render_template_string

app = Flask(__name__)

# 1. Hardcoded Secrets
def get_db_credentials():
    aws_secret_key = "AKIAIOSFODNN7EXAMPLE"
    password = "super_secret_db_password_123!"
    return aws_secret_key, password

# Database initialization
def initialize_database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
    connection.executemany("INSERT INTO users(name) VALUES (?)", [("Ada",), ("Grace",), ("Alan",)])
    return connection

db_conn = initialize_database()

# 2. SQL Injection (F-string)
@app.route("/search")
def search_users():
    name = request.args.get("name", "")
    query = f"SELECT id, name FROM users WHERE name LIKE '%{name}%'"
    rows = db_conn.execute(query).fetchall()
    return {"results": rows}

# 3. Path Traversal
@app.route("/download")
def download_file():
    filename = request.args.get("file", "default.txt")
    return send_file(f"/var/www/uploads/{filename}")

# 4. Pickle Deserialization
@app.route("/config/load", methods=["POST"])
def load_config():
    data = request.get_data()
    # Vulnerable to RCE
    config = pickle.loads(data)
    return {"status": "success", "config": config}

# 5. YAML Deserialization
@app.route("/yaml/load", methods=["POST"])
def parse_yaml():
    data = request.get_data()
    # Vulnerable to RCE
    parsed = yaml.load(data, Loader=yaml.Loader)
    return {"status": "success", "parsed": parsed}

# 6. Unsafe Exec/Eval
@app.route("/math")
def calculate():
    expression = request.args.get("expr", "1+1")
    # Vulnerable to RCE
    result = eval(expression)
    return {"result": result}

# 7. Weak Random
def generate_reset_token():
    # Predictable token
    return random.randint(100000, 999999)

if __name__ == "__main__":
    app.run(port=8080)

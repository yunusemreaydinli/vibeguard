"""Demo vulnerable Flask application for VibeGuard testing.
This app contains INTENTIONAL security issues for demonstration purposes.
DO NOT use this code in production!"""

import os
import pickle
import sqlite3
from flask import Flask, request, jsonify, render_template
import requests
from openai import OpenAI

# ==========================================
# VULNERABILITY 1: Hardcoded API Keys
# ==========================================
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
OPENAI_SECRET = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_PASSWORD = "super_secret_password_123!"

app = Flask(__name__)

# ==========================================
# VULNERABILITY 2: Hallucinated API Calls
# ==========================================
# These function calls DON'T EXIST in the real packages
client = OpenAI(api_key=OPENAI_SECRET)


def analyze_with_ai(text):
    """Uses non-existent OpenAI API methods."""
    # openai.ChatCompletion.auto_moderate() doesn't exist
    result = client.chat.completions.auto_moderate(text)

    # requests.secure_get() doesn't exist
    response = requests.secure_get("https://api.example.com/data")

    # requests.post_json() doesn't exist
    requests.post_json("https://api.example.com/submit", data={"text": text})

    return result


# ==========================================
# VULNERABILITY 3: SQL Injection
# ==========================================
@app.route('/user/<username>')
def get_user(username):
    """SQL injection vulnerable endpoint."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string formatting in SQL
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    user = cursor.fetchone()
    conn.close()
    return jsonify({"user": user})


@app.route('/search')
def search():
    """Another SQL injection point."""
    query = request.args.get('q', '')
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    results = cursor.fetchall()
    conn.close()
    return jsonify({"results": results})


# ==========================================
# VULNERABILITY 4: Dangerous eval/exec
# ==========================================
@app.route('/calculate', methods=['POST'])
def calculate():
    """Dangerous eval usage."""
    expression = request.json.get('expression', '')
    # VULNERABLE: eval on user input
    result = eval(expression)
    return jsonify({"result": result})


@app.route('/run', methods=['POST'])
def run_code():
    """Dangerous exec usage."""
    code = request.json.get('code', '')
    exec(code)
    return jsonify({"status": "executed"})


# ==========================================
# VULNERABILITY 5: Insecure Deserialization
# ==========================================
@app.route('/load', methods=['POST'])
def load_data():
    """Insecure pickle deserialization."""
    data = request.get_data()
    obj = pickle.loads(data)  # VULNERABLE
    return jsonify({"loaded": str(obj)})


# ==========================================
# VULNERABILITY 6: OS Command Injection
# ==========================================
@app.route('/ping')
def ping():
    """OS command injection."""
    host = request.args.get('host', 'localhost')
    result = os.system(f"ping -c 1 {host}")  # VULNERABLE
    return jsonify({"result": result})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

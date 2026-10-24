"""
测试示例 — 一个包含安全漏洞的 Flask 应用

这个文件故意包含一些常见的安全漏洞，用于测试 Vibe Sec Platform 的审查能力。
"""

from flask import Flask, request, jsonify
import sqlite3
import os
import subprocess

app = Flask(__name__)

# 硬编码密码（漏洞：hardcoded_password）
DB_PASSWORD = "secret123"
API_KEY = "sk-1234567890abcdef"

# 数据库连接
def get_db():
    conn = sqlite3.connect('users.db')
    return conn

# 漏洞 1: SQL 注入
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # SQL 注入漏洞：直接拼接用户输入
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query)  # 危险！
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "success", "user": user[0]})
    else:
        return jsonify({"status": "failed"}), 401

# 漏洞 2: XSS
@app.route('/profile')
def profile():
    username = request.args.get('username', 'Guest')

    # XSS 漏洞：直接渲染用户输入
    html = f"<h1>Welcome, {username}!</h1>"

    return html

# 漏洞 3: 命令注入
@app.route('/run-command', methods=['POST'])
def run_command():
    cmd = request.form.get('command')

    # 命令注入漏洞：直接执行用户输入
    result = subprocess.call(cmd, shell=True)  # 危险！

    return jsonify({"result": result})

# 漏洞 4: 路径遍历
@app.route('/download')
def download():
    filename = request.args.get('file')

    # 路径遍历漏洞：用户输入直接用于文件路径
    filepath = os.path.join('/uploads', filename)

    with open(filepath, 'r') as f:
        content = f.read()

    return content

# 漏洞 5: 不安全的 eval
@app.route('/calculate', methods=['POST'])
def calculate():
    expression = request.form.get('expression')

    # 代码注入漏洞：eval 直接执行用户输入
    result = eval(expression)  # 危险！

    return jsonify({"result": result})

# 安全的示例（修复后的代码）
@app.route('/safe-login', methods=['POST'])
def safe_login():
    username = request.form.get('username')
    password = request.form.get('password')

    # 安全：使用参数化查询
    query = "SELECT * FROM users WHERE username = ? AND password = ?"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query, (username, password))  # 安全！
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "success", "user": user[0]})
    else:
        return jsonify({"status": "failed"}), 401

if __name__ == '__main__':
    app.run(debug=True)

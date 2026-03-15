import os
from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from cs50 import SQL

app = Flask(__name__)
app.secret_key = "paynow-secret-key"

db_path = os.path.join(os.path.dirname(__file__), "users.db")
db = SQL(f"sqlite:///{db_path}")

db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        balance REAL NOT NULL DEFAULT 1000
    )
""")

db.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
""")

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone")
        password = request.form.get("password")

        if not phone or not password:
            return render_template("login.html", error="Both fields required")

        user = db.execute("SELECT * FROM users WHERE phone = ?", phone)

        if not user or not check_password_hash(user[0]["password_hash"], password):
            return render_template("login.html", error="Invalid phone or password")

        session["user_id"] = user[0]["id"]
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        phone = request.form.get("phone")
        password = request.form.get("password")

        if not name or not phone or not password:
            return render_template("register.html", error="All fields required")

        existing = db.execute("SELECT * FROM users WHERE phone = ?", phone)
        if existing:
            return render_template("register.html", error="Phone number already registered")

        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        db.execute("INSERT INTO users (name, phone, password_hash) VALUES (?, ?, ?)",
                   name, phone, password_hash)

        return "Registered successfully!"

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]

    rows = db.execute("""
        SELECT t.amount, t.timestamp,
               s.name as sender_name, r.name as recipient_name,
               t.sender_id, t.recipient_id
        FROM transactions t
        JOIN users s ON t.sender_id = s.id
        JOIN users r ON t.recipient_id = r.id
        WHERE t.sender_id = ? OR t.recipient_id = ?
        ORDER BY t.timestamp DESC LIMIT 5
    """, session["user_id"], session["user_id"])

    transactions = []
    for row in rows:
        if row["sender_id"] == session["user_id"]:
            transactions.append({
                "type": "Sent",
                "other_party": row["recipient_name"],
                "amount": row["amount"],
                "timestamp": row["timestamp"]
            })
        else:
            transactions.append({
                "type": "Received",
                "other_party": row["sender_name"],
                "amount": row["amount"],
                "timestamp": row["timestamp"]
            })

    return render_template("dashboard.html",
                           name=user["name"],
                           balance=user["balance"],
                           transactions=transactions)


@app.route("/send", methods=["GET", "POST"])
def send():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if request.method == "POST":
        phone = request.form.get("phone")
        amount = request.form.get("amount")

        if not phone or not amount:
            return render_template("send.html", error="All fields required")

        amount = float(amount)
        sender = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]
        recipient = db.execute("SELECT * FROM users WHERE phone = ?", phone)

        if not recipient:
            return render_template("send.html", error="Phone number not found")

        recipient = recipient[0]

        if recipient["id"] == session["user_id"]:
            return render_template("send.html", error="Cannot send money to yourself")

        if amount <= 0:
            return render_template("send.html", error="Amount must be greater than 0")

        if sender["balance"] < amount:
            return render_template("send.html", error="Insufficient balance")

        db.execute("UPDATE users SET balance = balance - ? WHERE id = ?",
                   amount, session["user_id"])
        db.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
                   amount, recipient["id"])
        db.execute("INSERT INTO transactions (sender_id, recipient_id, amount) VALUES (?, ?, ?)",
                   session["user_id"], recipient["id"], amount)

        return render_template("send.html", success=f"Sent ${amount} to {recipient['name']}")

    return render_template("send.html")


@app.route("/history")
def history():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    rows = db.execute("""
        SELECT t.amount, t.timestamp,
               s.name as sender_name, r.name as recipient_name,
               t.sender_id, t.recipient_id
        FROM transactions t
        JOIN users s ON t.sender_id = s.id
        JOIN users r ON t.recipient_id = r.id
        WHERE t.sender_id = ? OR t.recipient_id = ?
        ORDER BY t.timestamp DESC
    """, session["user_id"], session["user_id"])

    transactions = []
    for row in rows:
        if row["sender_id"] == session["user_id"]:
            transactions.append({
                "type": "Sent",
                "other_party": row["recipient_name"],
                "amount": row["amount"],
                "timestamp": row["timestamp"]
            })
        else:
            transactions.append({
                "type": "Received",
                "other_party": row["sender_name"],
                "amount": row["amount"],
                "timestamp": row["timestamp"]
            })

    return render_template("history.html", transactions=transactions)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
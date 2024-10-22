import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    stocks = db.execute(
        "SELECT symbol, SUM(shares) AS shares, price, name FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])
    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # To calculate total amount
    total = cash_db

    for stock in stocks:
        total += stock["shares"] * stock["price"]

    return render_template("portfolio.html", stocks=stocks, cash=cash_db, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol or not shares:
            return apology("MISSING SYMBOL/SHARES")

        try:
            shares = int(shares)
        except:
            return apology("Shares must be integer!")

        if int(shares) < 1:
            return apology("INVALID SHARES")

        stock = lookup(symbol.upper())
        if not stock:
            return apology("Please enter valid symbol!")

        transaction_value = int(shares) * stock["price"]


# To get the money of the user.
        user_id = session["user_id"]
        user_cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        user_cash = user_cash_db[0]["cash"]

        if user_cash < transaction_value:
            return apology("NOT ENOUGH MONEY")

        # To update the money of the user.
        updt_cash = user_cash - transaction_value
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updt_cash, user_id)

        # To access the current date
        date = datetime.datetime.now()

        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date, name, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   user_id, stock["symbol"], shares, stock["price"], date, stock["name"], "Bought")

        # To display message
        flash("Bought!")

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT symbol, shares, price, date, name, status FROM transactions")
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("MISSING SYMBOL")

        stock = lookup(request.form.get("symbol").upper())

        if not stock:
            return apology("INVALID SYMBOL")

        return render_template("quoted.html", stock=stock)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            return apology("Please fill all the entries", 400)

        # To verify the passwords
        elif password != confirmation:
            return apology("Password does not match")

        else:
            usernames = db.execute("SELECT username FROM users WHERE username = ?", username)

            """
            if username == usernames[0]["username"]:
                return apology("Username already exits", 400)
            """
            # Users’ passwords to have some number of letters, numbers, and/or symbols.
            if len(password) < 8:
                return apology("Passwords must contain atleast 8 character")

            digit = 0
            upper = 0
            symbol = 0
            for char in password:
                if char.isupper():
                    upper += 1
                elif char.isdigit():
                    digit += 1
                elif char in ["$", "%", "*", "`", "~", "!", "@", "(", ")", "-", "_", "+", "=", "{", "}", "[", "]", ":", ";", '"', "'", "<", ">", "?", "/"]:
                    symbol += 1
            if upper == 0 or digit == 0 or symbol == 0:
                return apology("Passwords must contain at least 1 upper case, numeric, and special character")

            # To enter into the database
            try:
                new_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))
            except:
                return apology("Username already exits", 400)

            # To set session code for new_user
            session["user_id"] = new_user

            # To display the message
            flash("Registered!")

            # Redirect user to home page
            return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        user_id = session["user_id"]
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol or not shares:
            return apology("Missing symbol and/or shares")

        # To store acutal number of the shares of the user
        shares_db = db.execute("SELECT shares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)

        # Checking if entered shares exceed the acutal number of the shares of the user
        if int(shares) > int(shares_db[0]["shares"]):
            return apology("Insufficient shares!")

        stock = lookup(symbol.upper())
        transaction_value = int(shares) * stock["price"]

        # To get the current amount of the user
        user_cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        user_cash = user_cash_db[0]["cash"]

        # To update the money of the user.
        updt_cash = user_cash + transaction_value
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updt_cash, user_id)

        # To access the current date
        date = datetime.datetime.now()

        # To update the database
        shares = -1 * int(shares)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date, name, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   user_id, stock["symbol"], shares, stock["price"], date, stock["name"], "Sold")

        flash("Sold!")

        return redirect("/")

    else:
        symbol_db = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])
        return render_template("sell.html", stocks=symbol_db)


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    """To delete user's account"""
    if request.method == "POST":
        user_id = session["user_id"]
        db.execute("DELETE FROM transactions WHERE user_id = ?", user_id)
        db.execute("DELETE FROM users WHERE id = ?", user_id)

        # Forget any user_id
        session.clear()
        flash("Account successfully deleted!")
        # Redirect user to login form
        return redirect("/login")

    else:
        return render_template("delete.html")

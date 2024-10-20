import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # User cach balance
    cash = float(db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"])

    # Get information
    stocks = db.execute("SELECT symbol, SUM(shares), price FROM purchases WHERE id= ? GROUP BY symbol", session["user_id"])

    closingtotal = cash
    for stock in stocks:
        stock["price"] = float(lookup(stock["symbol"])["price"])
        stock["SUM(shares)"] = int(stock["SUM(shares)"])
        closingtotal += float(stock["price"] * stock["SUM(shares)"])

    # render the index.html template
    return render_template("index.html", stocks=stocks, cash=cash, closingtotal=closingtotal)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("Must provide stock symbol")

        try:
            int(request.form.get("shares"))
        except ValueError:
            return apology("Must provide valid share number", 400)

        if not request.form.get("shares") or request.form.get("shares") < "1":
            return apology("Must provide valid share number")

        # Serach for quote via lookup function
        quote = lookup(request.form.get("symbol"))

        # Check if stock symbol provided was valid
        if quote == None:
            return apology("Stock symbol not valid")

        available = float(db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"])
        cost = float(float(quote["price"]) * float(request.form.get("shares")))

        # Check if there is enough money in account
        if cost > available:
            return apology("Not enough cash available")

        # Update users
        db.execute("UPDATE users SET cash = ? WHERE id = ?", (available-cost), session["user_id"])

        # Update purchases
        db.execute("INSERT INTO purchases(id, symbol, shares, price, date) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                   session["user_id"], request.form.get("symbol").upper(), int(request.form.get("shares")), float(quote["price"]))

        # Display purchase info
        flash("Bought!")
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    purchases = db.execute("SELECT * FROM purchases WHERE id= ? ",  session["user_id"])

    return render_template("history.html", purchases=purchases)


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

        # Ensure name of stock was submitted
        if not request.form.get("symbol"):
            return apology("Must provide stock symbol")

        # Serach for quote via lookup function
        quote = lookup(request.form.get("symbol"))

        # Check if stock symbol provided was valid
        if quote == None:
            return apology("Stock symbol not valid")
        # If stock symbol is valid show its value
        else:
            return render_template("quoted.html", symbol=quote["symbol"], price=float(quote["price"]))

    # User reached route via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        # Check that username does not exist
        if len(db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))) == 1:
            return apology("username exists", 400)

        # Check the password confirmation
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # If username does not exist and passwords match, insert username and password hash to table
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=request.form.get("username"),
                   hash=generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))

        # Redirect user to login page
        return redirect("/login")

    # User reached route via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("Must provide stock symbol")

        if not request.form.get("shares") or request.form.get("shares") < "1":
            return apology("Must provide valid share number")

        # Serach for quote via lookup function
        quote = lookup(request.form.get("symbol"))

        # Check if stock symbol provided was valid
        if quote == None:
            return apology("Stock symbol not valid")

        # Create a list with the users stocks
        stocks = db.execute("SELECT symbol, SUM(shares), price FROM purchases WHERE id= ? GROUP BY symbol", session["user_id"])

        for stock in stocks:
            stock["price"] == float(lookup(stock["symbol"])["price"])

        # Check if the user has this stock symbol and if he has enough shares
        flag1 = 0
        flag2 = 0
        for stock in stocks:
            if request.form.get("symbol") == stock["symbol"]:
                flag1 = 1
                if int(request.form.get("shares")) <= stock["SUM(shares)"]:
                    flag2 = 1

        if flag1 == 0:
            return apology("You do not have this stock symbol")

        # Check if the user has enough shares to sell
        if flag2 == 0:
            return apology("You do not have enough shares")

        # Update users
        db.execute("UPDATE users SET cash= cash + ? WHERE id = ?",
                   int(request.form.get("shares"))*quote["price"], session["user_id"])

        # Update purchases
        db.execute("INSERT INTO purchases(id, symbol, shares, price, date) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                   session["user_id"], request.form.get("symbol"), -int(request.form.get("shares")), float(quote["price"]))

        # Display sold info
        flash("Sold!")
        return redirect("/")

     # User reached route via GET
    else:

        # Create a list with the users stocks
        stocks = db.execute("SELECT symbol, SUM(shares), price FROM purchases WHERE id= ? GROUP BY symbol", session["user_id"])
        for stock in stocks:
            stock["price"] == float(lookup(stock["symbol"])["price"])

        return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

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

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///final_project.db")


@app.route("/")
def index():
    """Learning more about ShuangLugha"""
    return render_template("index.html")


@app.route("/lessons", methods=["GET", "POST"])
@login_required
def lessons():
    """Six introductory lessons for kids"""

    if request.method == "GET":
        return render_template("lessons.html")

    else:  # if method == 'POST'
        user_id = session["user_id"]
        language = db.execute("SELECT language FROM users WHERE id = :user_id", user_id=user_id)[0]["language"]
        category = request.form.get("category")
        db.execute("UPDATE users SET {category} = 'TRUE' WHERE id = :user_id".format(**{"category" : category}), user_id=user_id)

        if language == 'Swahili':
            if category == 'greetings':
                return redirect("https://www.youtube.com/watch?v=GCDNLUqFztA")
            elif category == 'family':
                return redirect('https://www.youtube.com/watch?v=hY6AM5Ppr1A')
            elif category == 'numbers':
                return redirect('https://www.youtube.com/watch?v=asnURbNNWtM')
            elif category == 'colors':
                return redirect('https://youtu.be/DjmLoxkeMPg?t=1774')
            elif category == 'food':
                return redirect('https://www.youtube.com/watch?v=dWfCKdn46iE')
            else:  # if category == 'animals'
                return redirect('https://www.youtube.com/watch?v=N6wcz6PuW0M')

        else:  # if language == 'Chinese'
            if category == 'greetings':
                return redirect('https://www.youtube.com/watch?v=2ZA6M9EsSlM')
            elif category == 'family':
                return redirect('https://www.youtube.com/watch?v=uc7qd9xPpDY')
            elif category == 'numbers':
                return redirect('https://www.youtube.com/watch?v=LpPs5RppA5A')
            elif category == 'colors':
                return redirect('https://www.youtube.com/watch?v=9E1QHwAFCgo')
            elif category == 'food':
                return redirect('https://www.youtube.com/watch?v=W53Cn19m3T0')
            else:  # if category == 'animals'
                return redirect('https://www.youtube.com/watch?v=SILtVcCErzk')


@app.route("/practice", methods=["GET", "POST"])
@login_required
def practice():
    """Links to flashcards for practicing vocab from six categorys"""

    # send user to Practice page
    if request.method == "GET":
        return render_template("practice.html")

    # get flashcard category from user; if method == "POST"
    language = db.execute("SELECT language FROM users WHERE id = :user_id", user_id=session["user_id"])[0]["language"]
    category = request.form.get("category")
    card = db.execute("SELECT * FROM :category ORDER BY RANDOM()", category=category)[0]["word"]  # randomly generated flashcard
    return render_template("flashcard.html", card=card, category=category, language=language)


@app.route("/new_card/<category>/<language>")
def new_card(category, language):
    """Button for new flashcard"""

    card = db.execute("SELECT * FROM :category ORDER BY RANDOM()", category=category)[0]["word"]  # randomly generated flashcard
    return render_template("flashcard.html", card=card, category=category, language=language)


@app.route("/flip_card/<card>/<category>/<language>")
def flip_card(card, category, language):
    """Button to flip flashcard to see translation"""

    translation = db.execute("SELECT * FROM :category WHERE word = :card",
        category=category, card=card)[0][language]
    return render_template("flashcard.html", card=translation, category=category, language=language)


@app.route("/quizzes", methods=["GET", "POST"])
@login_required
def quizzes():
    """Links to quizzes for six vocabulary categories"""

    # send user to Quizzes page
    if request.method == "GET":
        return render_template("quizzes.html")

    # get flashcard category from user; if method == "POST"
    language = db.execute("SELECT language FROM users WHERE id = :user_id", user_id=session["user_id"])[0]["language"]
    category = request.form.get("category")
    word = db.execute("SELECT * FROM :category ORDER BY RANDOM()", category=category)[0]["word"]  # randomly generated vocab word
    return render_template("quiz.html", word=word, category=category, language=language)


@app.route("/quiz/<word>/<category>/<language>", methods=["GET","POST"])
@login_required
def quiz(word, category, language):
    """Vocabulary quiz for user-inputted category"""

    # obtain user's answer and correct answer
    answer = request.form.get("answer")
    translation = db.execute("SELECT * FROM :category WHERE word = :word",
        category=category, word=word)[0][language]                          # correct answer

    num_correct = 0
    alert = False

    # if correct answer
    if answer.lower() == translation.lower():
        num_correct +=1
        alert = True

    # update scores appropriately
    db.execute("UPDATE scores SET {category}_correct = {category}_correct + {num_correct} WHERE user_id = :user_id".format(**{"category": category}, **{"num_correct": num_correct}),
                user_id=session["user_id"])
    db.execute("UPDATE scores SET {category}_total = {category}_total + 1 WHERE user_id = :user_id".format(**{"category": category}),
                user_id=session["user_id"])

    return render_template("answer.html", alert=alert, translation=translation, category=category, language=language)


@app.route("/next_question/<category>/<language>")
@login_required
def next_question(category, language):
    """Button for next quiz question"""

    word = db.execute("SELECT * FROM :category ORDER BY RANDOM()", category=category)[0]["word"]  # randomly generated vocab word
    return render_template("quiz.html", word=word, category=category, language=language)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # when user is sent to registration page
    if request.method == "GET":
        return render_template("register.html")

    # when user inputs username and password for registration
    username = request.form.get("username")
    if username == '':
        return apology("Must enter a username", 403)
    if len(db.execute("SELECT * FROM users WHERE username = :username", username=username)) > 0:
        return apology("Username already taken", 403)

    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    if (password == '') or (confirmation == ''):
        return apology("Must enter a password", 403)
    if password != confirmation:
        return apology("Passwords must match", 403)

    language = request.form.get("language")

    user_id = db.execute("INSERT INTO users (username, hash, language) VALUES (:username, :password, :language)",
                         username=username, password=generate_password_hash(password), language=language)
    db.execute("INSERT INTO scores (user_id) VALUES :user_id", user_id=user_id)

    # Remember which user has logged in
    session["user_id"] = user_id

    # Redirect user to home page
    return redirect("/")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "GET":
        return render_template("settings.html")
    else:
        old = request.form.get("old")
        new = request.form.get("new")
        confirmation = request.form.get("confirmation")

        if old == '':
            return apology("Must enter current password", 403)
        if (new == '') or (confirmation == ''):
            return apology("Must enter a new password", 403)
        if new != confirmation:
            return apology("New password must match confirmation", 403)

        # Ensure current password is correct
        rows = db.execute("SELECT * FROM users WHERE id = :user_id",
                          user_id=session["user_id"])
        if not check_password_hash(rows[0]["hash"], old):
            return apology("Invalid current password", 403)

        db.execute("UPDATE users SET hash = :new WHERE id = :user_id",
                            new=generate_password_hash(new), user_id=session["user_id"])
        alert="Password updated!"
        return render_template("index.html", alert=alert)


@app.route("/clear")
@login_required
def clear():  # clear user's quiz history
    db.execute("DELETE FROM scores WHERE user_id = :user_id", user_id=session["user_id"])
    db.execute("INSERT INTO scores (user_id) VALUES (:user_id)", user_id=session["user_id"])
    alert="Quiz history cleared!"
    return render_template("index.html", alert=alert)


@app.route("/progress")
@login_required
def progress():
    """Display user's progress"""

    # display which lessons the user has watched
    lessons = db.execute("SELECT * from users WHERE id = :user_id", user_id=session["user_id"])[0]
    progress = {"Greetings and Phrases": lessons["greetings"],
                "Family": lessons["family"],
                "Numbers": lessons["numbers"],
                "Colors": lessons["colors"],
                "Food": lessons["food"],
                "Animals": lessons["animals"]
    }

    # obtain user's quiz scores
    user_scores = db.execute("SELECT * from scores WHERE user_id = :user_id", user_id=session["user_id"])[0]
    del(user_scores["user_id"])
    scores = user_scores.copy()  # this list of dictionaries will track the quizzes that the user has taken at least once

    # drop categories the user hasn't taken quizzes in
    for key in user_scores:
        underscore = key.find('_')
        category = key[0:underscore]
        attribute = key[underscore+1:]

        if attribute == 'total' and user_scores[key] == 0:
            del(scores[key])  # delete 'total' column
            del(scores[category + '_correct'])  # also delete 'correct column'
            print(f"scores is {scores}")
            print(f"user_scores is {user_scores}")

    return render_template("progress.html", progress=progress, scores=scores)
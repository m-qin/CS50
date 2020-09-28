from flask import redirect, render_template, request, session
from functools import wraps
import csv

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", bottom=escape(message)), code

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# def flashcard(category):
#     file = open(category + ".csv", "r")  # vocabulary in chosen category
#     database = csv.DictReader(file)

#     count = 0
#     for line in database:  # count number of words in category
#         count += 1

#     card = int(random() * count)  # randomly choose a word
#     for line in database:
#         if line["index"] == card:
#             word = line[category]
#             file.close()
#             return word

#     file.close()
#     return
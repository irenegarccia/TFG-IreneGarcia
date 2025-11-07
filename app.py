from flask import Flask, render_template, redirect, url_for, request, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder='static', static_url_path='/')
app.secret_key = "secretkey"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"

USERS = {}  # "id": username, "name": name, "email": email, "password": hash
USERS["admin"] = {
    "id": "admin",
    "name": "admin",
    "email": "admin@tfg.es",
    "password": generate_password_hash("admin")
}


class User(UserMixin):
    def __init__(self, id, name, email, password):
        self.id = id
        self.name = name
        self.email = email
        self.password = password


@app.context_processor
def inject_user():
    return dict(user=current_user)


@login_manager.user_loader
def load_user(user_id):
    u = USERS.get(user_id)
    return User(u["id"], u["name"], u["email"], u["password"]) if u else None


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        u = USERS.get(username)
        if u and check_password_hash(u["password"], password):
            login_user(User(u["id"], u["name"], u["email"], u["password"]))
            return redirect(url_for("panel"))
        return render_template("signin.html", error="Usuario o contraseña incorrectos.")
    return render_template("signin.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not username or not email or not password:
            return render_template("signup.html", error="Rellena todos los campos.")
        if username in USERS:
            return render_template("signup.html", error="Ese usuario ya existe.")
        USERS[username] = {
            "id": username,
            "name": name,
            "email": email,
            "password": generate_password_hash(password)
        }
        login_user(User(username, name, email, USERS[username]["password"]))
        return redirect(url_for("panel"))
    return render_template("signup.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("signin"))


@app.route("/index")
@app.route("/index.html")
def index_redirect():
    return redirect(url_for("panel"))


@app.route("/panel")
@login_required
def panel():
    return render_template("index.html", user=current_user)


ALLOWED_PAGES = {
    "index", "blank", "button", "chart", "element", "form",
    "signin", "signup", "table", "typography", "widget", "404"
}


@app.route("/<page>.html")
def page_with_ext(page):
    if page in ALLOWED_PAGES:
        return render_template(f"{page}.html")
    abort(404)


@app.route("/<page>")
def page_without_ext(page):
    if page in ALLOWED_PAGES:
        return redirect(url_for("page_with_ext", page=page))
    abort(404)


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(debug=True)

from flask import Flask, render_template, redirect, url_for, request, abort, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os

app = Flask(__name__, static_folder='static', static_url_path='/')
app.secret_key = "secretkey"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.path.join(INSTANCE_DIR, "tfg.db")
app.config["DATABASE"] = DB_PATH

def get_conn():
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            age INTEGER NOT NULL,
            gender TEXT NOT NULL,
            studies TEXT NOT NULL
        );
        """)
        conn.commit()
        
def get_user_by_username(username: str):
    with get_conn() as conn:
        cur = conn.execute("SELECT id, name, email, password, age, gender, studies FROM users WHERE id = ?", (username,))
        row = cur.fetchone()
        return dict(row) if row else None

def create_user(id_: str, name: str, email: str, raw_password: str, age: int, gender: str, studies: str):
    pwd_hash = generate_password_hash(raw_password)
    with get_conn() as conn:
        conn.execute("INSERT INTO users (id, name, email, password, age, gender, studies) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (id_, name, email, pwd_hash, age, gender, studies))
        conn.commit()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"

class User(UserMixin):
    def __init__(self, id, name, email, password, age, gender, studies):
        self.id = id
        self.name = name
        self.email = email
        self.password = password
        self.age = age
        self.gender = gender
        self.studies = studies


@app.context_processor
def inject_user():
    return dict(user=current_user)


@login_manager.user_loader
def load_user(user_id):
    u = get_user_by_username(user_id)
    return User(u["id"], u["name"], u["email"], u["password"], u["age"], u["gender"], u["studies"]) if u else None


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        u = get_user_by_username(username)
        if u and check_password_hash(u["password"], password):
            login_user(User(u["id"], u["name"], u["email"], u["password"],  u["age"],  u["gender"],  u["studies"]))
            session["username"] = u["id"]
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
        confirm_password = request.form.get("confirm_password", "")
        age = request.form.get("age")
        gender = request.form.get("gender")
        studies = request.form.get("studies")

        if not name or not username or not email or not password or not confirm_password or not age or not gender or not studies:
            return render_template("signup.html", error="Rellena todos los campos.")
        if password != confirm_password:
            return render_template("signup.html", error="Las contraseñas no coinciden.")
        if get_user_by_username(username):
            return render_template("signup.html", error="Ese usuario ya existe.")

        create_user(username, name, email, password, age, gender, studies)
        u = get_user_by_username(username)
        login_user(User(u["id"], u["name"], u["email"], u["password"], u["age"], u["gender"], u["studies"]))
        session["username"] = u["id"]
        return redirect(url_for("panel"))
    return render_template("signup.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("username", None)
    return redirect(url_for("signin"))


@app.route("/index")
@app.route("/index.html")
def index_redirect():
    return redirect(url_for("panel"))


@app.route("/panel")
@login_required
def panel():
    return render_template("index.html", user=current_user)

def default_admin():
    init_db()
    if not get_user_by_username("admin"):
        create_user("admin", "admin", "admin@tfg.es", "Admin_22", 22, "Mujer", "Grado Universitario")

ALLOWED_PAGES = {
    "index", "blank", "button", "chart", "element", "form",
    "signin", "signup", "table", "typography", "widget", "404"
}


@app.route("/<page>.html")
def page_with_ext(page):
    if page in ALLOWED_PAGES:
        return render_template(f"{page}.html", user=current_user)
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
    default_admin() 
    app.run(debug=True)

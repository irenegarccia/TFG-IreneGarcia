from flask import Flask, render_template, redirect, url_for, request, abort, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, string, json
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__, static_folder='static', static_url_path='/')
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
csrf = CSRFProtect(app)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.path.join(INSTANCE_DIR, "tfg.db")
app.config["DATABASE"] = DB_PATH
QUESTIONS_JSON_PATH = os.path.join(BASE_DIR, "data", "questions.json")

def get_conn():
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
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

        conn.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_code TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS subcategories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subcategory_code TEXT NOT NULL UNIQUE,
            category_code TEXT NOT NULL,
            title TEXT NOT NULL,
            order_index INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (category_code) REFERENCES categories(category_code)
        );
        """)


        conn.execute("""
        CREATE TABLE IF NOT EXISTS challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,

            subcategory_code TEXT NOT NULL,
            phase TEXT NOT NULL CHECK(phase IN ('pre','post')),
            order_index INTEGER NOT NULL DEFAULT 0,

            is_training INTEGER NOT NULL DEFAULT 1,
            points INTEGER NOT NULL DEFAULT 0,

            question TEXT,
            correct_answer TEXT,
            option1 TEXT,
            option2 TEXT,
            option3 TEXT,
            option4 TEXT,

            is_practical INTEGER NOT NULL DEFAULT 0,
            content TEXT,

            FOREIGN KEY (subcategory_code) REFERENCES subcategories(subcategory_code),
            UNIQUE(subcategory_code, phase, title)
        );
        """)



        conn.execute("""
        CREATE TABLE IF NOT EXISTS user_challenge_progress (
            user_id TEXT NOT NULL,
            challenge_id INTEGER NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0,
            completed_date TEXT,
            score INTEGER NOT NULL DEFAULT 0,
            user_answer TEXT,
            PRIMARY KEY (user_id, challenge_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (challenge_id) REFERENCES challenges(id)
        );
        """)

        conn.commit()

        
def add_data():
    if not os.path.exists(QUESTIONS_JSON_PATH):
        return

    with open(QUESTIONS_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    with get_conn() as conn:
        for cat in data.get("categories", []):
            conn.execute(
                "INSERT OR IGNORE INTO categories (category_code, title) VALUES (?, ?)",
                (cat["category_code"], cat["title"])
            )

            for sub in cat.get("subcategories", []):
                conn.execute("""
                    INSERT OR IGNORE INTO subcategories
                    (subcategory_code, category_code, title, order_index)
                    VALUES (?, ?, ?, ?)
                """, (
                    sub["subcategory_code"],
                    cat["category_code"],
                    sub["title"],
                    int(sub.get("order_index", 0))
                ))

                challenges_block = sub.get("challenges", {})

                for phase in ("pre", "post"):
                    for idx, ch in enumerate(challenges_block.get(phase, []), start=1):
                        options = ch.get("options", [])
                        o1 = options[0] if len(options) > 0 else None
                        o2 = options[1] if len(options) > 1 else None
                        o3 = options[2] if len(options) > 2 else None
                        o4 = options[3] if len(options) > 3 else None

                        conn.execute("""
                            INSERT OR IGNORE INTO challenges
                            (title, subcategory_code, phase, order_index,
                             is_training, points, question, correct_answer,
                             option1, option2, option3, option4,
                             is_practical, content)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            ch["title"],
                            sub["subcategory_code"],
                            phase,
                            int(ch.get("order_index", idx)),
                            int(ch.get("is_training", 1)),
                            int(ch.get("points", 10)),
                            ch.get("question"),
                            ch.get("correct_answer"),
                            o1, o2, o3, o4,
                            int(ch.get("is_practical", 0)),
                            ch.get("content")
                        ))

        conn.commit()


def get_categories():
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT category_code, title
            FROM categories
            ORDER BY id ASC
        """).fetchall()
        return [dict(r) for r in rows]


def get_category_by_code(category_code: str):
    with get_conn() as conn:
        row = conn.execute("""
            SELECT category_code, title
            FROM categories
            WHERE category_code = ?
        """, (category_code,)).fetchone()
        return dict(row) if row else None


def get_subcategories_by_category(category_code: str):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT subcategory_code, title, order_index
            FROM subcategories
            WHERE category_code = ?
            ORDER BY order_index ASC, id ASC
        """, (category_code,)).fetchall()
        return [dict(r) for r in rows]


def get_subcategory_challenges(subcategory_code: str, phase: str):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT id, title, points, question, correct_answer,
                   option1, option2, option3, option4,
                   is_training, is_practical, content, order_index
            FROM challenges
            WHERE subcategory_code = ?
              AND phase = ?
            ORDER BY order_index ASC, id ASC
        """, (subcategory_code, phase)).fetchall()
        return [dict(r) for r in rows]


def get_category_code_by_subcategory(subcategory_code: str):
    with get_conn() as conn:
        row = conn.execute("""
            SELECT category_code
            FROM subcategories
            WHERE subcategory_code = ?
        """, (subcategory_code,)).fetchone()
        return row["category_code"] if row else None


def is_challenge_completed(user_id: str, challenge_id: int) -> bool:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT completed
            FROM user_challenge_progress
            WHERE user_id = ? AND challenge_id = ?
        """, (user_id, challenge_id)).fetchone()
        return bool(row["completed"]) if row else False


def mark_challenge_completed(user_id: str, challenge_id: int, score: int = 0, user_answer: str = None):
    with get_conn() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO user_challenge_progress
            (user_id, challenge_id, completed, completed_date, score, user_answer)
            VALUES (?, ?, 1, datetime('now'), ?, ?)
        """, (user_id, challenge_id, score, user_answer))
        conn.commit()

def get_challenge_by_id(challenge_id: int):
    with get_conn() as conn:
        row = conn.execute("""
            SELECT *
            FROM challenges
            WHERE id = ?
        """, (challenge_id,)).fetchone()
        return dict(row) if row else None

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

def passwordValidation(password: str) -> bool:
    if password is None:
        return False
    
    if len(password) < 8:
        return False
    
    return (
        any(char.isupper() for char in password) and
        any(char.islower() for char in password) and
        any(char.isdigit() for char in password) and
        any(char in string.punctuation for char in password)
    )

def get_total_score(user_id: str) -> int:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT COALESCE(SUM(score), 0) AS total
            FROM user_challenge_progress
            WHERE user_id = ? AND completed = 1
        """, (user_id,)).fetchone()
        return int(row["total"]) if row else 0


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
def inject_globals():
    return dict(
        user=current_user,
        categories=get_categories()
    )



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
        if not passwordValidation(password):
            return render_template("signup.html", error="La contraseña debe tener al menos 8 caracteres e incluir mayúsculas, minúsculas, números y símbolos.")
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
    total_score = get_total_score(current_user.id)
    return render_template("index.html", user=current_user, total_score=total_score)


@app.route("/category/<category_code>")
@login_required
def category_page(category_code):
    category = get_category_by_code(category_code)
    if not category:
        abort(404)

    subcategories = get_subcategories_by_category(category_code)

    completed_map = {}
    all_pre_done = True
    pre_total = post_total = pre_done = post_done = 0

    for sub in subcategories:
        sub["pre_challenges"] = get_subcategory_challenges(sub["subcategory_code"], "pre")
        sub["post_challenges"] = get_subcategory_challenges(sub["subcategory_code"], "post")

        for ch in sub["pre_challenges"] + sub["post_challenges"]:
            completed_map[ch["id"]] = is_challenge_completed(current_user.id, ch["id"])

        pre_total += len(sub["pre_challenges"])
        post_total += len(sub["post_challenges"])

        pre_done += sum(1 for ch in sub["pre_challenges"] if completed_map.get(ch["id"]))
        post_done += sum(1 for ch in sub["post_challenges"] if completed_map.get(ch["id"]))

        if sub["pre_challenges"]:
            if not all(completed_map.get(ch["id"], False) for ch in sub["pre_challenges"]):
                all_pre_done = False

    pre_pct = round((pre_done / pre_total) * 100) if pre_total else 0
    post_pct = round((post_done / post_total) * 100) if post_total else 0

    return render_template(
        "category.html",
        category=category,
        subcategories=subcategories,
        completed_map=completed_map,
        all_pre_done=all_pre_done,
        pre_total=pre_total,
        post_total=post_total,
        pre_done=pre_done,
        post_done=post_done,
        pre_pct=pre_pct,
        post_pct=post_pct
    )



@app.route("/challenge/<int:challenge_id>")
@login_required
def challenge_page(challenge_id):
    challenge = get_challenge_by_id(challenge_id)
    if not challenge:
        abort(404)

    completed = is_challenge_completed(current_user.id, challenge_id)

    category_code = request.args.get("category_code")

    return render_template(
        "challenge.html",
        challenge=challenge,
        completed=completed,
        category_code=category_code,
        subcategory_code=challenge.get("subcategory_code")
    )



@app.route("/challenge/<int:challenge_id>/submit", methods=["POST"])
@login_required
def challenge_submit(challenge_id):
    challenge = get_challenge_by_id(challenge_id)
    if not challenge or challenge["is_practical"]:
        abort(404)

    subcategory_code = request.form.get("subcategory_code")
    if not subcategory_code:
        abort(400)

    category_code = get_category_code_by_subcategory(subcategory_code)
    if not category_code:
        abort(400)

    if is_challenge_completed(current_user.id, challenge_id):
        return redirect(url_for("category_page", category_code=category_code))

    selected = request.form.get("answer")
    if not selected:
        abort(400)

    score = 10 if selected == challenge["correct_answer"] else 0
    mark_challenge_completed(current_user.id, challenge_id, score=score, user_answer=selected)

    return redirect(url_for("category_page", category_code=category_code))


def default_admin():
    init_db()

    if not get_user_by_username("admin"):
        create_user("admin", "admin", "admin@tfg.es", "Admin_22", 22, "Mujer", "Grado Universitario")

    add_data()

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
    app.run(host='0.0.0.0', port=5000, debug=True)

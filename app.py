from flask import Flask, render_template, redirect, url_for, request, abort, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, string
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
        CREATE TABLE IF NOT EXISTS subcategory_challenges (
            subcategory_code TEXT NOT NULL,
            challenge_id INTEGER NOT NULL,
            phase TEXT NOT NULL CHECK(phase IN ('pre','post')),
            order_index INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (subcategory_code, challenge_id),
            FOREIGN KEY (subcategory_code) REFERENCES subcategories(subcategory_code),
            FOREIGN KEY (challenge_id) REFERENCES challenges(id)
        );
        """)


        conn.execute("""
        CREATE TABLE IF NOT EXISTS challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL UNIQUE,
            is_training INTEGER NOT NULL DEFAULT 1,
            points INTEGER NOT NULL DEFAULT 0,
            question TEXT,
            correct_answer TEXT,
            option1 TEXT,
            option2 TEXT,
            option3 TEXT,
            option4 TEXT,
            is_practical INTEGER NOT NULL DEFAULT 0,
            content TEXT
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS category_challenges (
            category_code TEXT NOT NULL,
            challenge_id INTEGER NOT NULL,
            phase TEXT NOT NULL CHECK(phase IN ('pre','post')),
            order_index INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (category_code, challenge_id),
            FOREIGN KEY (category_code) REFERENCES categories(category_code),
            FOREIGN KEY (challenge_id) REFERENCES challenges(id)
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS user_challenge_progress (
            user_id TEXT NOT NULL,
            challenge_id INTEGER NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0,
            completed_date TEXT,
            score INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, challenge_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (challenge_id) REFERENCES challenges(id)
        );
        """)

        conn.commit()

        
def add_data():
    with get_conn() as conn:

        categories = [
            ("physical_attacks", "Ataques Físicos"),
            ("credential_management", "Gestión de Credenciales"),
            ("social_engineering", "Ingeniería Social"),
            ("phishing", "Phishing"),
            ("devices", "Dispositivos"),
            ("data_protection", "Protección de Datos"),
        ]

        for code, title in categories:
            conn.execute(
                "INSERT OR IGNORE INTO categories (category_code, title) VALUES (?, ?)",
                (code, title)
            )

        physical_challenges = [
            (
                "Dispositivos maliciosos",
                "¿Qué es un USB malicioso?",
                "Un USB que puede ejecutar ataques o acciones no deseadas",
                "Un USB normal solo para almacenar archivos",
                "Un USB que puede ejecutar ataques o acciones no deseadas",
                "Un ratón",
                "Un cargador"
            ),
            (
                "Robo o pérdida de dispositivos",
                "¿Qué deberías hacer primero si pierdes el móvil?",
                "Bloquearlo/localizarlo y cambiar contraseñas importantes",
                "No hacer nada",
                "Bloquearlo/localizarlo y cambiar contraseñas importantes",
                "Comprar otro móvil y ya está",
                "Apagar el Wi-Fi y esperar"
            ),
            (
                "Pagos contactless y riesgos NFC",
                "¿Qué medida ayuda a reducir el riesgo de NFC/contactless?",
                "Desactivar NFC cuando no se use",
                "Dejar NFC siempre activado",
                "Desactivar NFC cuando no se use",
                "Usar un PIN débil",
                "Compartir la tarjeta con otras personas"
            ),
        ]

        credential_challenges = [
            (
                "Contraseñas seguras",
                "¿Cuál es una contraseña segura?",
                "Larga, única y con mezcla de caracteres",
                "123456",
                "Larga, única y con mezcla de caracteres",
                "Tu nombre",
                "Solo números"
            ),
            (
                "Gestores de contraseñas",
                "¿Qué es un gestor de contraseñas?",
                "Una herramienta para guardar contraseñas de forma segura",
                "Un antivirus",
                "Una VPN",
                "Una herramienta para guardar contraseñas de forma segura",
                "Un firewall"
            ),
            (
                "Filtración de credenciales",
                "¿Qué deberías hacer tras una filtración de datos?",
                "Cambiar contraseñas y revisar información sensible",
                "No hacer nada",
                "Cambiar contraseñas y revisar información sensible",
                "Publicarlo en redes sociales",
                "Reutilizar la misma contraseña"
            ),
        ]

        social_challenges = [
            (
                "Códigos QR",
                "¿Cuál es un riesgo típico de los códigos QR?",
                "Redirigir a webs falsas o maliciosas",
                "Mejorar la batería del móvil",
                "Redirigir a webs falsas o maliciosas",
                "Aumentar la velocidad de Internet",
                "Aumentar el almacenamiento"
            ),
            (
                "Llamadas fraudulentas",
                "Una táctica común en llamadas fraudulentas es…",
                "Crear urgencia y pedir datos personales",
                "Ofrecer regalos sin más",
                "Crear urgencia y pedir datos personales",
                "Decirte que te relajes",
                "No decir nada"
            ),
            (
                "Conexiones WI-FI",
                "El principal riesgo del Wi-Fi público suele ser…",
                "Intercepción del tráfico (robo de información)",
                "Que consuma más RAM",
                "Intercepción del tráfico (robo de información)",
                "Mejorar la cámara",
                "Mejorar el GPS"
            ),
            (
                "Gestión de información sensible",
                "¿Qué es información sensible?",
                "Datos que pueden identificarte o afectar tu privacidad",
                "El tiempo",
                "Un meme",
                "Datos que pueden identificarte o afectar tu privacidad",
                "Una canción"
            ),
        ]

        phishing_challenges = [
            (
                "Reconocimiento de Webs y correos fraudulentos",
                "Una señal típica de phishing es…",
                "Enlaces o dominios sospechosos",
                "Un dominio oficial y correcto",
                "Enlaces o dominios sospechosos",
                "Que no haya enlaces",
                "Que siempre tenga ortografía perfecta"
            ),
        ]

        devices_challenges = [
            (
                "Seguridad en dispositivos",
                "Una medida básica de protección del dispositivo es…",
                "Bloqueo de pantalla y actualizaciones",
                "No usar contraseña",
                "Bloqueo de pantalla y actualizaciones",
                "Compartir el PIN",
                "No actualizar nunca"
            ),
            (
                "Gestión de actualizaciones y parches de seguridad",
                "¿Por qué es importante actualizar el software?",
                "Porque corrige vulnerabilidades",
                "Porque lo hace más lento",
                "Porque corrige vulnerabilidades",
                "Porque cambia el fondo de pantalla",
                "Porque borra aplicaciones"
            ),
            (
                "BYOD - Políticas y riesgos",
                "BYOD significa…",
                "Bring Your Own Device (trae tu propio dispositivo)",
                "Buy Your Own Data (compra tus datos)",
                "Bring Your Own Device (trae tu propio dispositivo)",
                "Backup Your OS Daily (copia el SO a diario)",
                "Block Your Old Device (bloquea tu dispositivo antiguo)"
            ),
        ]

        data_protection_challenges = [
            (
                "Principios básicos",
                "Un principio básico de protección de datos es…",
                "Minimización de datos (recoger solo lo necesario)",
                "Compartirlo todo",
                "Minimización de datos (recoger solo lo necesario)",
                "No hace falta consentimiento",
                "No cifrar nunca"
            ),
        ]

        def create_challenge(title, question, correct, o1, o2, o3, o4, is_training=1, is_practical=0, content=None):
            conn.execute("""
                INSERT OR IGNORE INTO challenges
                (title, is_training, points, question, correct_answer, option1, option2, option3, option4, is_practical, content)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (title, is_training, 10, question, correct, o1, o2, o3, o4, is_practical, content))
            row = conn.execute("SELECT id FROM challenges WHERE title = ?", (title,)).fetchone()
            return row["id"]

        def insert_challenge(category_code, challenge_id, phase, order_index):
            conn.execute("""
                INSERT OR IGNORE INTO category_challenges (category_code, challenge_id, phase, order_index)
                VALUES (?, ?, ?, ?)
            """, (category_code, challenge_id, phase, order_index))


        # Ataques Físicos: PRE
        for i, (
            title,
            question,
            correct_answer,
            option1,
            option2,
            option3,
            option4
        ) in enumerate(physical_challenges, start=1):

            challenge_id = create_challenge(
                title=title,
                question=question,
                correct=correct_answer,
                o1=option1,
                o2=option2,
                o3=option3,
                o4=option4,
                is_training=1
            )

            insert_challenge("physical_attacks", challenge_id, "pre", i)


        # Ingeniería Social: PRE
        for i, (
            title,
            question,
            correct_answer,
            option1,
            option2,
            option3,
            option4
        ) in enumerate(social_challenges, start=1):

            challenge_id = create_challenge(
                title=title,
                question=question,
                correct=correct_answer,
                o1=option1,
                o2=option2,
                o3=option3,
                o4=option4,
                is_training=1
            )

            insert_challenge("social_engineering", challenge_id, "pre", i)


        # Phishing: PRE
        for i, (
            title,
            question,
            correct_answer,
            option1,
            option2,
            option3,
            option4
        ) in enumerate(phishing_challenges, start=1):

            challenge_id = create_challenge(
                title=title,
                question=question,
                correct=correct_answer,
                o1=option1,
                o2=option2,
                o3=option3,
                o4=option4,
                is_training=1
            )

            insert_challenge("phishing", challenge_id, "pre", i)


        # Dispositivos: PRE
        for i, (
            title,
            question,
            correct_answer,
            option1,
            option2,
            option3,
            option4
        ) in enumerate(devices_challenges, start=1):

            challenge_id = create_challenge(
                title=title,
                question=question,
                correct=correct_answer,
                o1=option1,
                o2=option2,
                o3=option3,
                o4=option4,
                is_training=1
            )

            insert_challenge("devices", challenge_id, "pre", i)


        # Protección de Datos: PRE
        for i, (
            title,
            question,
            correct_answer,
            option1,
            option2,
            option3,
            option4
        ) in enumerate(data_protection_challenges, start=1):

            challenge_id = create_challenge(
                title=title,
                question=question,
                correct=correct_answer,
                o1=option1,
                o2=option2,
                o3=option3,
                o4=option4,
                is_training=1
            )

            insert_challenge("data_protection", challenge_id, "pre", i)


        # Gestión de Credenciales: PRE
        for i, (
            title,
            question,
            correct_answer,
            option1,
            option2,
            option3,
            option4
        ) in enumerate(credential_challenges, start=1):

            challenge_id = create_challenge(
                title=title,
                question=question,
                correct=correct_answer,
                o1=option1,
                o2=option2,
                o3=option3,
                o4=option4,
                is_training=1
            )

            insert_challenge("credential_management", challenge_id, "pre", i)


        # Gestión de Credenciales: POST (reto de evaluación)
        post_challenge_id = create_challenge(
            title="Evaluación final (POST)",
            question="POST: Tras una filtración de contraseñas, ¿cuál es la mejor práctica?",
            correct="Cambiar la contraseña y no reutilizarla",
            o1="Ignorarlo",
            o2="Reutilizar la misma contraseña",
            o3="Cambiar la contraseña y no reutilizarla",
            o4="Compartir la contraseña con amistades",
            is_training=0
        )

        insert_challenge("credential_management", post_challenge_id, "post", 1)

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


def get_category_challenges(category_code: str, phase: str):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT challenge.id, challenge.title, challenge.points, challenge.question, 
                    challenge.correct_answer,challenge.option1, challenge.option2, 
                    challenge.option3, challenge.option4, challenge.is_training,
                    challenge.is_practical, challenge.content,category_map.order_index
            FROM category_challenges category_map
            JOIN challenges challenge
              ON challenge.id = category_map.challenge_id
            WHERE category_map.category_code = ?
              AND category_map.phase = ?
            ORDER BY category_map.order_index ASC
        """, (category_code, phase)).fetchall()
        return [dict(r) for r in rows]


def is_challenge_completed(user_id: str, challenge_id: int) -> bool:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT completed
            FROM user_challenge_progress
            WHERE user_id = ? AND challenge_id = ?
        """, (user_id, challenge_id)).fetchone()
        return bool(row["completed"]) if row else False


def mark_challenge_completed(user_id: str, challenge_id: int, score: int = 0):
    with get_conn() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO user_challenge_progress
            (user_id, challenge_id, completed, completed_date, score)
            VALUES (?, ?, 1, datetime('now'), ?)
        """, (user_id, challenge_id, score))
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

    pre_challenges = get_category_challenges(category_code, "pre")
    post_challenges = get_category_challenges(category_code, "post")

    completed_map = {}
    for ch in pre_challenges + post_challenges:
        completed_map[ch["id"]] = is_challenge_completed(current_user.id, ch["id"])

    pre_total = len(pre_challenges)
    post_total = len(post_challenges)

    pre_done = sum(1 for ch in pre_challenges if completed_map.get(ch["id"]))
    post_done = sum(1 for ch in post_challenges if completed_map.get(ch["id"]))

    pre_pct = round((pre_done / pre_total) * 100) if pre_total else 0
    post_pct = round((post_done / post_total) * 100) if post_total else 0

    all_pre_done = True
    if pre_challenges:
        all_pre_done = all(completed_map.get(ch["id"], False) for ch in pre_challenges)

    return render_template(
        "category.html",
        category=category,
        pre_challenges=pre_challenges,
        post_challenges=post_challenges,
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
        category_code=category_code
    )


@app.route("/challenge/<int:challenge_id>/submit", methods=["POST"])
@login_required
def challenge_submit(challenge_id):
    challenge = get_challenge_by_id(challenge_id)
    if not challenge or challenge["is_practical"]:
        abort(404)

    category_code = request.form.get("category_code")
    if not category_code:
        abort(400)

    if is_challenge_completed(current_user.id, challenge_id):
        return redirect(url_for("category_page", category_code=category_code))

    selected = request.form.get("answer")
    if not selected:
        abort(400)

    if selected == challenge["correct_answer"]:
        score = 10
    else:
        score = 0

    mark_challenge_completed(current_user.id, challenge_id, score=score)
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

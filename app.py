import re
import unicodedata
from flask import Flask, render_template, redirect, url_for, request, abort, session, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, string, json, hashlib, requests, logging, subprocess, tempfile, uuid, sys, shutil, random
from flask_wtf.csrf import CSRFProtect
from logging.config import dictConfig
from google import genai
import hmac
import base64
import io
from datetime import datetime
import qrcode
from openpyxl import Workbook


dictConfig({
    "version": 1,
    "formatters": {
        "default": {
            "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
        }
    },
    "handlers": {
        "wsgi": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
            "formatter": "default",
        }
    },
    "root": {
        "level": "INFO",
        "handlers": ["wsgi"]
    }
})

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
TRAINING_JSON_PATH = os.path.join(BASE_DIR, "data", "training.json")
_training_cache = {"mtime": None, "by_sub": {}}
# --- QR dinámico (sin tablas extra) ---
QR_SECRET = os.environ.get("QR_SECRET", "CAMBIA_ESTO_EN_PRODUCCION")

def get_public_base_url():
    # En prod define PUBLIC_BASE_URL=http://tfg-irene.grafo.etsii.urjc.es
    return os.environ.get("PUBLIC_BASE_URL", "http://localhost:5000").rstrip("/")

def make_qr_token(user_id: str) -> str:
    # Token firmando: user_id.firma
    uid = str(user_id)
    sig = hmac.new(QR_SECRET.encode(), uid.encode(), hashlib.sha256).digest()
    sig = base64.urlsafe_b64encode(sig)[:12].decode()
    return f"{uid}.{sig}"

def verify_qr_token(token: str):
    try:
        uid, sig = token.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(QR_SECRET.encode(), uid.encode(), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(expected)[:12].decode()
    if hmac.compare_digest(expected, sig):
        return uid
    return None

def make_qr_base64_png(url: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

def get_qr_dynamic_challenge_id():
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM challenges WHERE is_practical = 1 AND content LIKE '%qr_dynamic%' LIMIT 1"
        ).fetchone()
        return row["id"] if row else None

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
            studies TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            user_category TEXT NOT NULL DEFAULT 'urjc'
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
            img TEXT,
            ideal_answer TEXT,

            FOREIGN KEY (subcategory_code) REFERENCES subcategories(subcategory_code),
            UNIQUE(subcategory_code, phase, order_index)
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
            ai_score INTEGER,
            ai_comment TEXT,
            PRIMARY KEY (user_id, challenge_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (challenge_id) REFERENCES challenges(id)
        );
        """)


        conn.execute("""
        CREATE TABLE IF NOT EXISTS user_training_progress (
            user_id TEXT NOT NULL,
            subcategory_code TEXT NOT NULL,
            received INTEGER NOT NULL DEFAULT 0,
            received_date TEXT,
            PRIMARY KEY (user_id, subcategory_code),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (subcategory_code) REFERENCES subcategories(subcategory_code)
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
                            is_practical, content, img, ideal_answer)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                            ch.get("content"),
                            ch.get("img"),
                            ch.get("ideal_answer")
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


def get_subcategory_by_code(subcategory_code: str):
    with get_conn() as conn:
        row = conn.execute("""
            SELECT subcategory_code, category_code, title, order_index
            FROM subcategories
            WHERE subcategory_code = ?
        """, (subcategory_code,)).fetchone()
        return dict(row) if row else None


def _load_training_json():
    global _training_cache

    if not os.path.exists(TRAINING_JSON_PATH):
        _training_cache = {"mtime": None, "by_sub": {}}
        return {}

    mtime = os.path.getmtime(TRAINING_JSON_PATH)
    if _training_cache.get("mtime") == mtime and _training_cache.get("by_sub"):
        return _training_cache["by_sub"]

    with open(TRAINING_JSON_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)

    by_sub = {}
    for item in raw.get("subcategories", []):
        code = item.get("subcategory_code")
        if code:
            by_sub[code] = item

    _training_cache = {"mtime": mtime, "by_sub": by_sub}
    return by_sub


def get_training_for_subcategory(subcategory_code: str):
    return _load_training_json().get(subcategory_code)


def is_training_received(user_id: str, subcategory_code: str) -> bool:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT received
            FROM user_training_progress
            WHERE user_id = ? AND subcategory_code = ?
        """, (user_id, subcategory_code)).fetchone()
        return bool(row["received"]) if row else False


def mark_training_received(user_id: str, subcategory_code: str):
    with get_conn() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO user_training_progress (user_id, subcategory_code, received, received_date)
            VALUES (?, ?, 1, datetime('now'))
        """, (user_id, subcategory_code))
        conn.commit()


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
        cur = conn.execute("""
            SELECT id, name, email, password, age, gender, studies, is_admin, user_category
            FROM users
            WHERE id = ?
        """, (username,))
        row = cur.fetchone()
        return dict(row) if row else None

def get_user_by_id_or_email(value: str):
    with get_conn() as conn:
        cur = conn.execute("""
            SELECT id, name, email, password, age, gender, studies, is_admin, user_category
            FROM users
            WHERE lower(id) = lower(?) OR lower(email) = lower(?)
        """, (value, value))
        row = cur.fetchone()
        return dict(row) if row else None
    
def create_user(
    id_: str,
    name: str,
    email: str,
    raw_password: str,
    age: int,
    gender: str,
    studies: str,
    is_admin: int = 0,
    user_category: str = "urjc"
):
    pwd_hash = generate_password_hash(raw_password)
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO users (id, name, email, password, age, gender, studies, is_admin, user_category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (id_, name, email, pwd_hash, age, gender, studies, is_admin, user_category))
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

def admin_required():
    if not current_user.is_authenticated or int(current_user.is_admin) != 1:
        abort(403)

def get_all_user_categories():
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT DISTINCT LOWER(TRIM(user_category)) as user_category
            FROM users
            WHERE user_category IS NOT NULL AND TRIM(user_category) != ''
            ORDER BY user_category
        """).fetchall()

        result = []
        for row in rows:
            c = row["user_category"]
            if c == "urjc":
                result.append("URJC")
            elif c == "externo":
                result.append("Externo")
            else:
                result.append(c.capitalize())
        return result

def get_all_genders():
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT DISTINCT LOWER(TRIM(gender)) as gender
            FROM users
            WHERE gender IS NOT NULL AND TRIM(gender) != ''
            ORDER BY gender
        """).fetchall()

        result = []
        for row in rows:
            g = row["gender"]
            if g == "mujer":
                result.append("Mujer")
            elif g == "hombre":
                result.append("Hombre")
            elif g == "otro":
                result.append("Otro")
            else:
                result.append(g.capitalize())
        return result


def get_all_studies():
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT DISTINCT LOWER(TRIM(studies)) as studies
            FROM users
            WHERE studies IS NOT NULL AND TRIM(studies) != ''
            ORDER BY studies
        """).fetchall()

        result = []
        for row in rows:
            s = row["studies"]
            if s == "fp":
                result.append("FP")
            elif s == "eso":
                result.append("ESO")
            elif s == "postgrado":
                result.append("Postgrado")
            elif s == "gradouniversitario":
                result.append("Grado Universitario")
            elif s == "otros":
                result.append("Otros")
            else:
                result.append(s.capitalize())
        return result
    
def update_user_password_admin(user_id: str, raw_password: str):
    pwd_hash = generate_password_hash(raw_password)
    with get_conn() as conn:
        conn.execute("""
            UPDATE users
            SET password = ?
            WHERE id = ?
        """, (pwd_hash, user_id))
        conn.commit()


def update_user_category_admin(user_id: str, user_category: str):
    with get_conn() as conn:
        conn.execute("""
            UPDATE users
            SET user_category = ?
            WHERE id = ?
        """, (user_category, user_id))
        conn.commit()


def get_admin_results(
    search_value: str = "",
    result_category: str = "",
    user_category: str = "",
    gender: str = "",
    studies: str = "",
    min_age: str = "",
    max_age: str = "",
    limit=None, 
    offset=None
):
    query = """
        SELECT
            u.id AS user_id,
            u.name,
            u.email,
            u.age,
            u.gender,
            u.studies,
            u.user_category,
            c.title AS result_category,
            c.category_code,
            ch.title AS challenge_title,
            ch.phase,
            COALESCE(ucp.score, 0) AS score,
            ucp.completed,
            ucp.completed_date
        FROM users u
        LEFT JOIN user_challenge_progress ucp
            ON u.id = ucp.user_id
        LEFT JOIN challenges ch
            ON ucp.challenge_id = ch.id
        LEFT JOIN subcategories s
            ON ch.subcategory_code = s.subcategory_code
        LEFT JOIN categories c
            ON s.category_code = c.category_code
        WHERE 1=1
    """

    params = []

    if search_value:
        query += " AND (lower(u.id) = lower(?) OR lower(u.email) = lower(?))"
        params.extend([search_value, search_value])

    if result_category:
        query += " AND c.category_code = ?"
        params.append(result_category)

    if user_category:
        query += " AND LOWER(TRIM(u.user_category)) = LOWER(TRIM(?))"
        params.append(user_category)

    if gender:
        query += " AND LOWER(TRIM(u.gender)) = LOWER(TRIM(?))"
        params.append(gender)

    if studies:
        query += " AND LOWER(TRIM(u.studies)) = LOWER(TRIM(?))"
        params.append(studies)

    if min_age:
        query += " AND u.age >= ?"
        params.append(int(min_age))

    if max_age:
        query += " AND u.age <= ?"
        params.append(int(max_age))

    count_query = f"SELECT COUNT(*) as total FROM ({query}) AS subquery_count"

    query += " ORDER BY u.id, c.title, ch.phase, ch.order_index"

    with get_conn() as conn:
        total = conn.execute(count_query, params).fetchone()["total"]

        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows], total
    
def get_first_pending_challenge(user_id: str, subcategory_code: str, phase: str):
    with get_conn() as conn:
        row = conn.execute("""
            SELECT c.*
            FROM challenges c
            LEFT JOIN user_challenge_progress u
              ON u.challenge_id = c.id AND u.user_id = ?
            WHERE c.subcategory_code = ?
              AND c.phase = ?
              AND (u.completed IS NULL OR u.completed = 0)
            ORDER BY c.order_index ASC, c.id ASC
            LIMIT 1
        """, (user_id, subcategory_code, phase)).fetchone()
        return dict(row) if row else None

def get_next_pending_challenge_id(user_id: str, subcategory_code: str, phase: str, current_id: int):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT c.id
            FROM challenges c
            LEFT JOIN user_challenge_progress u
              ON u.challenge_id = c.id AND u.user_id = ?
            WHERE c.subcategory_code = ?
              AND c.phase = ?
              AND (u.completed IS NULL OR u.completed = 0)
            ORDER BY c.order_index ASC, c.id ASC
        """, (user_id, subcategory_code, phase)).fetchall()

    ids = [r["id"] for r in rows]

    if not ids:
        return None

    try:
        idx = ids.index(current_id)
    except ValueError:
        return ids[0]

    return ids[idx + 1] if idx + 1 < len(ids) else None

def normalize(text):
    if not text:
        return ""

    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]", "", text.lower().strip())


def split_values(text):
    if not text:
        return []

    values = []
    for part in re.split(r"[,\s]+", text):
        v = normalize(part)
        if v and v not in values:
            values.append(v)
    return values

def run_cupp_and_save_txt(profile: dict):
    cupp_script = os.path.join(BASE_DIR, "cupp", "cupp.py")
    if not os.path.isfile(cupp_script):
        raise RuntimeError("No existe cupp/cupp.py dentro del proyecto.")

    first_name = normalize(profile.get("first_name", "")) or "user"
    surname = normalize(profile.get("surname", ""))
    nickname = normalize(profile.get("nickname", ""))
    birthdate = normalize(profile.get("birthdate", "")) 
    partner_name = normalize(profile.get("partner_name", ""))
    partner_nick = normalize(profile.get("partner_nick", ""))
    partner_birth = normalize(profile.get("partner_birthdate", ""))
    child_name = normalize(profile.get("child_name", ""))
    child_nick = normalize(profile.get("child_nick", ""))
    child_birth = normalize(profile.get("child_birthdate", ""))
    pet_name = normalize(profile.get("pet_name", ""))
    company = normalize(profile.get("company", ""))
    raw_keywords = profile.get("keywords") or ""

    extra_fields = [
        profile.get("city", ""),
        profile.get("country", ""),
        profile.get("favorite_color", ""),
        profile.get("favorite_team", ""),
        profile.get("favorite_player", ""),
        profile.get("favorite_food", ""),
        profile.get("school", ""),
        profile.get("university", ""),
        profile.get("degree", ""),
        profile.get("hobby", ""),
        profile.get("instagram", ""),
        profile.get("tiktok", ""),
        profile.get("github", ""),
        profile.get("username_alt", ""),
        profile.get("phone", ""),
        profile.get("car_brand", ""),
        profile.get("car_model", ""),
    ]

    all_kw = []
    all_kw += split_values(raw_keywords)
    for x in extra_fields:
        all_kw += split_values(str(x))

    keywords = ",".join(all_kw)

    add_keywords = "y" if keywords else "n"

    use_special = "y" if profile.get("use_special", True) else "n"
    use_numbers = "y" if profile.get("use_numbers", True) else "n"
    use_leet = "y" if profile.get("use_leet", False) else "n"

    answers = [
        first_name,      
        surname,         
        nickname,         
        birthdate,      
        partner_name,   
        partner_nick,   
        partner_birth,   
        child_name,      
        child_nick,      
        child_birth,    
        pet_name,        
        company,        
        add_keywords,   
        keywords if keywords else "",
        use_special,    
        use_numbers,     
        use_leet,        
    ]
    padding = "\n" * 80  
    stdin_payload = "\n".join(answers) + "\n" + padding


    cupp_cwd = os.path.join(BASE_DIR, "cupp")

    proc = subprocess.run(
        [sys.executable, cupp_script, "-i", "-q"],
        input=stdin_payload,
        text=True,
        cwd=cupp_cwd,
        capture_output=True,
        timeout=60
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"CUPP falló (code={proc.returncode}).\nSTDERR:\n{proc.stderr[:2000]}\n\nSTDOUT:\n{proc.stdout[:2000]}"
        )

    txts = [os.path.join(cupp_cwd, f) for f in os.listdir(cupp_cwd) if f.lower().endswith(".txt")]
    if not txts:
        raise RuntimeError("CUPP no generó ningún .txt.")

    generated = max(txts, key=os.path.getmtime)


    out_dir = os.path.join(INSTANCE_DIR, "generated_wordlists")
    os.makedirs(out_dir, exist_ok=True)

    token = uuid.uuid4().hex
    out_path = os.path.join(out_dir, f"{token}.txt")
    shutil.copyfile(generated, out_path)
    try:
        os.remove(generated)
    except Exception:
        pass

    K = int((profile or {}).get("preview_size") or 30)  
    K = max(10, min(200, K))                            

    preview = []
    seen = 0
    rng = random.SystemRandom()

    with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.strip()
            if not pw:
                continue

            seen += 1
            if len(preview) < K:
                preview.append(pw)
            else:
                j = rng.randrange(seen)
                if j < K:
                    preview[j] = pw

    rng.shuffle(preview)
    return token, out_path, preview



def get_ai_feedback(user_id, challenge_id):
    with get_conn() as conn:
        row = conn.execute("""
            SELECT ai_score, ai_comment
            FROM user_challenge_progress
            WHERE user_id = ? AND challenge_id = ?
        """, (user_id, challenge_id)).fetchone()
        if not row:
            return None
        if row["ai_score"] is None and row["ai_comment"] is None:
            return None
        return {"score": row["ai_score"], "comment": row["ai_comment"]}


def save_ai_feedback(user_id, challenge_id, score, comment):
    with get_conn() as conn:
        conn.execute("""
            UPDATE user_challenge_progress
            SET ai_score = ?, ai_comment = ?
            WHERE user_id = ? AND challenge_id = ?
        """, (score, comment, user_id, challenge_id))
        conn.commit()

def normalize_option_value(value):
    if value is None:
        return ""
    value = str(value).strip()

    value = re.sub(r"^/static/static/", "/static/", value)

    return value


def is_image_option(value):
    value = normalize_option_value(value).lower()
    return value.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg"))
def ai_evaluate_answer(question: str, ideal_answer: str, user_answer: str) -> dict:

    prompt = f"""Eres un evaluador docente. Valora la respuesta del estudiante comparándola con una respuesta ideal.

PREGUNTA:
{question}

RESPUESTA IDEAL (criterios):
{ideal_answer}

RESPUESTA DEL ESTUDIANTE:
{user_answer}

Devuelve SOLO un JSON válido con este formato:
{{
  "score": <entero 1..10>,
  "comment": "<2-5 frases: qué está bien y qué falta/mejoraría>"
}}
""".strip()

    res = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt
    )

    text = (res.text or "").strip()
    text = text.replace("```json", "").replace("```", "").strip()

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start:end+1]

    try:
        data = json.loads(text)
    except Exception:
        return {"score": 1, "comment": "No se pudo generar la respuesta de la IA (formato inválido)."}


    score = max(1, min(10, int(data.get("score", 1))))
    comment = str(data.get("comment", "")).strip()

    return {"score": score, "comment": comment}

def get_admin_category_chart_data(
    search_value: str = "",
    result_category: str = "",
    user_category: str = "",
    gender: str = "",
    studies: str = "",
    min_age: str = "",
    max_age: str = ""
):
    query = """
        SELECT
            c.title AS category_title,
            COALESCE(SUM(ucp.score), 0) AS total_score
        FROM users u
        LEFT JOIN user_challenge_progress ucp
            ON u.id = ucp.user_id
        LEFT JOIN challenges ch
            ON ucp.challenge_id = ch.id
        LEFT JOIN subcategories s
            ON ch.subcategory_code = s.subcategory_code
        LEFT JOIN categories c
            ON s.category_code = c.category_code
        WHERE c.title IS NOT NULL
    """

    params = []

    if search_value:
        query += " AND (lower(u.id) = lower(?) OR lower(u.email) = lower(?))"
        params.extend([search_value, search_value])

    if result_category:
        query += " AND c.category_code = ?"
        params.append(result_category)

    if user_category:
        query += " AND LOWER(TRIM(u.user_category)) = LOWER(TRIM(?))"
        params.append(user_category)

    if gender:
        query += " AND LOWER(TRIM(u.gender)) = LOWER(TRIM(?))"
        params.append(gender)

    if studies:
        query += " AND LOWER(TRIM(u.studies)) = LOWER(TRIM(?))"
        params.append(studies)

    if min_age:
        query += " AND u.age >= ?"
        params.append(int(min_age))

    if max_age:
        query += " AND u.age <= ?"
        params.append(int(max_age))

    query += """
        GROUP BY c.category_code, c.title
        ORDER BY c.title
    """

    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()

    labels = [row["category_title"] for row in rows]
    values = [row["total_score"] for row in rows]

    return labels, values

@app.route("/challenge/<int:challenge_id>/complete-info", methods=["POST"])
@login_required
def challenge_complete_info(challenge_id):
    challenge = get_challenge_by_id(challenge_id)
    if not challenge:
        return {"ok": False, "error": "Reto no encontrado"}, 404

    if challenge.get("content") and "qr_dynamic" in (challenge.get("content") or ""):
        if not is_challenge_completed(current_user.id, challenge_id):
            mark_challenge_completed(
                current_user.id,
                challenge_id,
                score=10,
                user_answer="QR cerrado, el usuario no ha caído, reto superado"
            )
        return {"ok": True, "score": 10, "feedback": {"opened": False}}

    if is_challenge_completed(current_user.id, challenge_id):
        return {"ok": True}

    data = request.get_json(silent=True) or {}
    user_text = (data.get("answer") or "").strip()

    mark_challenge_completed(
        current_user.id,
        challenge_id,
        score=0,
        user_answer=user_text if user_text else None
    )

    return {"ok": True}


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"

class User(UserMixin):
    def __init__(self, id, name, email, password, age, gender, studies, is_admin=0, user_category="urjc"):
        self.id = id
        self.name = name
        self.email = email
        self.password = password
        self.age = age
        self.gender = gender
        self.studies = studies
        self.is_admin = is_admin
        self.user_category = user_category


@app.context_processor
def inject_globals():
    return dict(
        user=current_user,
        categories=get_categories()
    )


@login_manager.user_loader
def load_user(user_id):
    u = get_user_by_username(user_id)
    return User(
        u["id"],
        u["name"],
        u["email"],
        u["password"],
        u["age"],
        u["gender"],
        u["studies"],
        u["is_admin"],
        u["user_category"]
    ) if u else None


@app.route("/")
def landing():
    app.logger.info("Acceso a la plataforma")
    return render_template("landing.html")

@app.route("/signin", methods=["GET"])
def signin():
    return render_template("signin.html")

@app.route("/signin", methods=["POST"])
def signin_post():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    app.logger.info(f"Intento de inicio de sesión: usuario: {username}")
    u = get_user_by_username(username)
    if u and check_password_hash(u["password"], password):
        login_user(User(
            u["id"],
            u["name"],
            u["email"],
            u["password"],
            u["age"],
            u["gender"],
            u["studies"],
            u["is_admin"],
            u["user_category"]
        ))
        session["username"] = u["id"]
        app.logger.info(f"Inicio de sesión correcto: usuario: {username}")
        return redirect(url_for("panel"))
    app.logger.warning(f"Inicio de sesión fallido: usuario: {username}")
    return render_template("signin.html", error="Usuario o contraseña incorrectos.")

@app.route("/signup", methods=["GET"])
def signup():
    return render_template("signup.html")

@app.route("/signup", methods=["POST"])
def signup_post():
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip().lower()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    user_age = request.form.get("age", "").strip()
    gender = request.form.get("gender", "").strip().lower()
    studies = request.form.get("studies", "").strip().lower()
    user_category = request.form.get("user_category", "").strip().lower()

    if not name or not username or not email or not password or not confirm_password or not user_age or not gender or not studies or not user_category:
        return render_template("signup.html", error="Rellena todos los campos.")

    try:
        age_int = int(user_age)
    except ValueError:
        return render_template("signup.html", error="La edad debe ser un número entero válido.")

    if age_int < 1 or age_int > 120:
        return render_template("signup.html", error="La edad debe estar entre 1 y 120.")

    if password != confirm_password:
        return render_template("signup.html", error="Las contraseñas no coinciden.")
    if not passwordValidation(password):
        return render_template(
            "signup.html",
            error="La contraseña debe tener al menos 8 caracteres e incluir mayúsculas, minúsculas, números y símbolos."
        )
    if get_user_by_username(username):
        return render_template("signup.html", error="Ese usuario ya existe.")

    app.logger.info(f"Registro de nuevo usuario: usuario: {username}, email: {email}")

    create_user(username, name, email, password, age_int, gender, studies, user_category=user_category)
    u = get_user_by_username(username)
    login_user(User(
        u["id"],
        u["name"],
        u["email"],
        u["password"],
        u["age"],
        u["gender"],
        u["studies"],
        u["is_admin"],
        u["user_category"]
    ))
    session["username"] = u["id"]
    return redirect(url_for("panel"))


@app.route("/logout")
@login_required
def logout():
    app.logger.info(f"Cierre de sesión: usuario: {current_user.id}")
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
    radar_pre = get_category_scores(current_user.id, "pre")
    radar_post = get_category_scores(current_user.id, "post")

    total_score = sum(radar_pre.values()) + sum(radar_post.values())

    return render_template(
        "index.html",
        user=current_user,
        total_score=total_score,
        radar_pre=radar_pre,
        radar_post=radar_post
    )


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

        sub_pre_total = count_phase_total_for_subcategory(sub["subcategory_code"], "pre")
        sub_pre_done  = count_phase_done_for_subcategory(current_user.id, sub["subcategory_code"], "pre")

        sub_post_total = count_phase_total_for_subcategory(sub["subcategory_code"], "post")
        sub_post_done  = count_phase_done_for_subcategory(current_user.id, sub["subcategory_code"], "post")

        sub["pre_total"] = sub_pre_total
        sub["pre_done"]  = sub_pre_done
        sub["post_total"] = sub_post_total
        sub["post_done"]  = sub_post_done

        sub["pre_pct"] = round((sub["pre_done"] / sub["pre_total"]) * 100) if sub["pre_total"] else 0
        sub["post_pct"] = round((sub["post_done"] / sub["post_total"]) * 100) if sub["post_total"] else 0
        
        sub["pre_completed"] = (sub_pre_total > 0 and sub_pre_done == sub_pre_total)
        sub["training_received"] = is_training_received(current_user.id, sub["subcategory_code"])
        sub["post_unlocked"] = (sub["pre_completed"] and sub["training_received"])

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

    category_score = sum_scores_for_category(current_user.id, category_code)
    category_max_score = (pre_total + post_total) * 10

    for sub in subcategories:
        sub["pre_score"] = sum_scores_for_subcategory_phase(current_user.id, sub["subcategory_code"], "pre")
        sub["post_score"] = sum_scores_for_subcategory_phase(current_user.id, sub["subcategory_code"], "post")
        sub["pre_max_score"] = int(sub.get("pre_total", 0)) * 10
        sub["post_max_score"] = int(sub.get("post_total", 0)) * 10

    return render_template(
        "category.html",
        category=category,
        category_score=category_score,
        category_max_score=category_max_score,
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


@app.route("/training/<subcategory_code>")
@login_required
def training_page(subcategory_code):
    sub = get_subcategory_by_code(subcategory_code)
    if not sub:
        abort(404)

    category_code = sub["category_code"]

    pre_total = count_phase_total(subcategory_code, "pre")
    pre_done = count_phase_done(current_user.id, subcategory_code, "pre")
    if pre_total > 0 and pre_done < pre_total:
        return redirect(url_for(
            "category_page",
            category_code=category_code,
            msg="Completa todos los retos PRE para poder acceder a la formación"
        ))

    training = get_training_for_subcategory(subcategory_code)
    if not training:
        return render_template(
            "training.html",
            category_code=category_code,
            subcategory=sub,
            training=None,
            received=is_training_received(current_user.id, subcategory_code),
            post_unlocked=False
        )

    if not is_training_received(current_user.id, subcategory_code):
        mark_training_received(current_user.id, subcategory_code)

    received = is_training_received(current_user.id, subcategory_code)

    return render_template(
        "training.html",
        category_code=category_code,
        subcategory=sub,
        training=training,
        received=received,
        post_unlocked=received,
        msg=None
    )


@app.route("/challenge/<int:challenge_id>")
@login_required
def challenge_page(challenge_id):
    challenge = get_challenge_by_id(challenge_id)
    if not challenge:
        abort(404)

    if challenge.get("phase") == "post":
        sub_code = challenge.get("subcategory_code")
        pre_total = count_phase_total(sub_code, "pre")
        pre_done = count_phase_done(current_user.id, sub_code, "pre")

        if pre_total > 0 and pre_done < pre_total:
            category_code = get_category_code_by_subcategory(sub_code)
            return redirect(url_for(
                "category_page",
                category_code=category_code,
                msg="Completa todos los retos PRE para desbloquear los POST"
            ))

        if not is_training_received(current_user.id, sub_code):
            category_code = get_category_code_by_subcategory(sub_code)
            return redirect(url_for(
                "category_page",
                category_code=category_code,
                msg="Antes de los POST, entra en 'Formación' y recíbela al menos una vez"
            ))

    if is_challenge_completed(current_user.id, challenge_id):
        category_code = get_category_code_by_subcategory(challenge["subcategory_code"])
        return redirect(url_for("category_page", category_code=category_code, msg="Ese reto ya está completado"))

    category_code = request.args.get("category_code")

    if not category_code:
        category_code = get_category_code_by_subcategory(challenge["subcategory_code"])

    redirect_url = url_for("category_page", category_code=category_code)

    next_pending_id = get_next_pending_challenge_id(
        current_user.id,
        challenge["subcategory_code"],
        challenge["phase"],
        challenge_id
    )

    next_challenge_url = None
    if next_pending_id:
        next_challenge_url = url_for(
            "challenge_page",
            challenge_id=next_pending_id,
            category_code=category_code
        )

    options = []
    if not int(challenge.get("is_practical", 0)):
        raw_options = [
            challenge.get("option1"),
            challenge.get("option2"),
            challenge.get("option3"),
            challenge.get("option4"),
        ]
        options = [
            normalize_option_value(o)
            for o in raw_options
            if o and str(o).strip()
        ]

    challenge["correct_answer"] = normalize_option_value(challenge.get("correct_answer"))
    
    qr_image_b64 = None
    qr_public_url = None
    if int(challenge.get("is_practical", 0)) and challenge.get("content") and "qr_dynamic" in challenge["content"]:
        token = make_qr_token(current_user.id)
        qr_public_url = f"{get_public_base_url()}/qr/{token}"
        qr_image_b64 = make_qr_base64_png(qr_public_url)

    return render_template(
        "challenge.html",
        challenge=challenge,
        options=options,
        completed=False,
        review_mode=False, 
        category_code=category_code,
        subcategory_code=challenge["subcategory_code"],
        redirect_url=redirect_url,
        qr_image_b64=qr_image_b64,
        qr_public_url=qr_public_url,
        next_challenge_url=next_challenge_url
    )


@app.route("/challenge/<int:challenge_id>/submit", methods=["POST"])
@login_required
def challenge_submit(challenge_id):
    challenge = get_challenge_by_id(challenge_id)
    if not challenge or challenge["is_practical"]:
        abort(404)

    if is_challenge_completed(current_user.id, challenge_id):
        category_code = get_category_code_by_subcategory(challenge["subcategory_code"])
        return redirect(url_for("category_page", category_code=category_code, msg="Ese reto ya está completado"))

    selected = request.form.get("answer")
    if not selected:
        abort(400)

    score = 10 if selected == challenge["correct_answer"] else 0
    mark_challenge_completed(current_user.id, challenge_id, score=score, user_answer=selected)

    category_code = get_category_code_by_subcategory(challenge["subcategory_code"])
    submit_action = (request.form.get("submit_action") or "menu").strip().lower()

    if submit_action == "next":
        next_pending_id = get_next_pending_challenge_id(
            current_user.id,
            challenge["subcategory_code"],
            challenge["phase"],
            challenge_id
        )

        if next_pending_id:
            return redirect(url_for(
                "challenge_page",
                challenge_id=next_pending_id,
                category_code=category_code
            ))

    return redirect(url_for("category_page", category_code=category_code, msg="Reto guardado"))

@app.route("/api/pwned-check", methods=["POST"])
@login_required
def api_pwned_check():
    data = request.get_json(silent=True) or {}
    password = (data.get("password") or "").strip()

    if not password:
        return {"ok": False, "error": "Contraseña vacía"}, 400

    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    try:
        pwned_count = hibp_pwned_count(password)
    except Exception:
        return {"ok": False, "error": "No se pudo consultar HIBP"}, 502

    return {
        "ok": True,
        "pwned_count": pwned_count,
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol
    }


@app.route("/challenge/<int:challenge_id>/complete", methods=["POST"])
@login_required
def challenge_complete(challenge_id):
    challenge = get_challenge_by_id(challenge_id)
    if not challenge:
        return {"ok": False, "error": "Reto no encontrado"}, 404


    if not int(challenge.get("is_practical", 0)):
        return {"ok": False, "error": "Este reto no es práctico"}, 400


    if is_challenge_completed(current_user.id, challenge_id):
        return {"ok": False, "error": "Ese reto ya está completado"}, 400


    data = request.get_json(silent=True) or {}

    pwned_count = int(data.get("pwned_count", 0))
    password_length = int(data.get("password_length", 0))
    length_ok   = bool(data.get("length_ok", False))
    has_upper   = bool(data.get("has_upper", False))
    has_lower   = bool(data.get("has_lower", False))
    has_digit   = bool(data.get("has_digit", False))
    has_symbol  = bool(data.get("has_symbol", False))

    missing = []
    if not length_ok:  missing.append("length>=12")
    if not has_upper:  missing.append("has_upper")
    if not has_lower:  missing.append("has_lower")
    if not has_digit:  missing.append("has_digit")
    if not has_symbol: missing.append("has_symbol")

    no_breaches = (pwned_count == 0)
    all_reqs = (len(missing) == 0)

    if no_breaches and all_reqs:
        score = 10
    elif no_breaches and not all_reqs:
        score = 5
    else:
        score = 0

    feedback = {
        "pwned_count": pwned_count,
        "password_length": password_length,
        "missing_requirements": missing,
        "no_breaches": no_breaches,
        "all_requirements": all_reqs
    }


    if challenge.get("content") and "pp_form" in challenge["content"]:
        feedback_message = (
            "Si alguna de tus contraseñas coincidía con alguna de la lista generada "
            "o se parecía a ellas, deberías cambiarla por una contraseña larga, única "
            "y difícil de adivinar. Este ejercicio es educativo y no se almacena "
            "ninguna información sensible."
        )

        mark_challenge_completed(
            current_user.id,
            challenge_id,
            score=0,
            user_answer=json.dumps({"message": feedback_message}, ensure_ascii=False)
        )
    else:
        mark_challenge_completed(
            current_user.id,
            challenge_id,
            score=score,
            user_answer=json.dumps(feedback, ensure_ascii=False)
        )

    return {"ok": True, "score": score, "feedback": feedback}


@app.route("/qr/<token>", methods=["GET"])
def qr_dynamic_landing(token):
    user_id = verify_qr_token(token)
    if not user_id:
        abort(404)

    challenge_id = get_qr_dynamic_challenge_id()
    if not challenge_id:
        abort(404)

    if not is_challenge_completed(user_id, challenge_id):
        mark_challenge_completed(
            user_id,
            challenge_id,
            score=0,
            user_answer="QR abierto, el usuario falló el reto"
        )

    ch = get_challenge_by_id(challenge_id)
    if not ch:
        abort(404)

    category_code = get_category_code_by_subcategory(ch["subcategory_code"])
    if not category_code:
        abort(404)

    return render_template("qr_warning.html", category_code=category_code)

@app.route("/subcategory/<subcategory_code>/<phase>/next")
@login_required
def next_challenge(subcategory_code, phase):
    if phase not in ("pre", "post"):
        abort(400)

    category_code = get_category_code_by_subcategory(subcategory_code)
    if not category_code:
        abort(400)

    if phase == "post":
        pre_total = count_phase_total(subcategory_code, "pre")
        pre_done = count_phase_done(current_user.id, subcategory_code, "pre")
        if pre_total > 0 and pre_done < pre_total:
            return redirect(url_for(
                "category_page",
                category_code=category_code,
                msg="Completa todos los retos PRE para desbloquear los POST"
            ))
        
        if not is_training_received(current_user.id, subcategory_code):
            return redirect(url_for(
                "category_page",
                category_code=category_code,
                msg="Antes de los POST, entra en 'Formación' y recíbela al menos una vez"
            ))



    ch = get_first_pending_challenge(current_user.id, subcategory_code, phase)

    if not ch:
        return redirect(url_for(
            "category_page",
            category_code=category_code,
            msg="Ya has completado todos los retos de esta subcategoría"
        ))

    return redirect(url_for("challenge_page", challenge_id=ch["id"], category_code=category_code))


@app.route("/subcategory/<subcategory_code>/<phase>/review")
@login_required
def subcategory_review_start(subcategory_code, phase):
    if phase not in ("pre", "post"):
        abort(400)

    category_code = get_category_code_by_subcategory(subcategory_code)
    if not category_code:
        abort(400)

    total = count_phase_total_for_subcategory(subcategory_code, phase)
    done = count_phase_done_for_subcategory(current_user.id, subcategory_code, phase)

    if total == 0:
        return redirect(url_for("category_page", category_code=category_code, msg="No hay retos para revisar en esta fase"))

    if done < total:
        return redirect(url_for("category_page", category_code=category_code, msg="Completa todos los retos para poder revisarlos"))

    completed = get_completed_challenges_for_review(current_user.id, subcategory_code, phase)
    if not completed:
        return redirect(url_for("category_page", category_code=category_code, msg="No hay progreso para revisar"))

    first_id = completed[0]["id"]
    return redirect(url_for("subcategory_review_challenge", subcategory_code=subcategory_code, phase=phase, challenge_id=first_id))

@app.route("/api/cupp/generate", methods=["POST"])
@login_required
def api_cupp_generate():
    profile = request.get_json(silent=True) or {}

    try:
        token, path, preview = run_cupp_and_save_txt(profile)
        session["cupp_last_token"] = token

        return {
            "ok": True,
            "preview": preview,
            "download_url": url_for("api_cupp_download", token=token)
        }
    except Exception as e:
        app.logger.exception("Error generando wordlist con CUPP")
        return {"ok": False, "error": str(e)}, 500


@app.route("/api/cupp/download/<token>", methods=["GET"])
@login_required
def api_cupp_download(token):
    if token != session.get("cupp_last_token"):
        abort(403)

    wordlist_path = os.path.join(INSTANCE_DIR, "generated_wordlists", f"{token}.txt")
    if not os.path.isfile(wordlist_path):
        abort(404)

    return send_file(
        wordlist_path,
        as_attachment=True,
        download_name="cupp_wordlist.txt",
        mimetype="text/plain"
    )

@app.route("/admin")
@login_required
def admin_panel():
    admin_required()

    search_value = request.args.get("q", "").strip()
    result_category = request.args.get("result_category", "").strip()
    user_category = request.args.get("user_category", "").strip()
    gender = request.args.get("gender", "").strip()
    studies = request.args.get("studies", "").strip()
    min_age = request.args.get("min_age", "").strip()
    max_age = request.args.get("max_age", "").strip()

    selected_user = get_user_by_id_or_email(search_value) if search_value else None

    page = int(request.args.get("page", 1))
    per_page =30
    offset = (page - 1) * per_page

    results, total_results = get_admin_results(
        search_value=search_value,
        result_category=result_category,
        user_category=user_category,
        gender=gender,
        studies=studies,
        min_age=min_age,
        max_age=max_age,
        limit=per_page,
        offset=offset
    )

    total_pages = (total_results + per_page - 1) // per_page

    chart_labels, chart_values = get_admin_category_chart_data(
        search_value=search_value,
        result_category=result_category,
        user_category=user_category,
        gender=gender,
        studies=studies,
        min_age=min_age,
        max_age=max_age
    )
    total_score = sum(row.get("score", 0) for row in results)
    average_score = round(total_score / len(results), 2) if results else 0
    unique_users_count = len({row["user_id"] for row in results if row.get("user_id")})

    user_scores = {}
    for row in results:
        uid = row.get("user_id")
        score = row.get("score", 0)

        if uid:
            user_scores[uid] = user_scores.get(uid, 0) + score

    top_users = sorted(user_scores.items(), key=lambda x: x[1], reverse=True)[:5]

    total_completed = sum(1 for row in results if row.get("completed"))

    ages = [row.get("age") for row in results if row.get("age") is not None]
    avg_age = round(sum(ages) / len(ages), 1) if ages else 0

    gender_count = {}
    for row in results:
        g = row.get("gender")
        if g:
            gender_count[g] = gender_count.get(g, 0) + 1

    most_common_gender = max(gender_count, key=gender_count.get) if gender_count else "-"

    cat_count = {}
    for row in results:
        c = row.get("user_category")
        if c:
            cat_count[c] = cat_count.get(c, 0) + 1

    most_common_category = max(cat_count, key=cat_count.get) if cat_count else "-"

    return render_template(
        "admin.html",
        selected_user=selected_user,
        results=results,
        search_value=search_value,
        result_category=result_category,
        user_category=user_category,
        gender=gender,
        studies=studies,
        min_age=min_age,
        max_age=max_age,
        all_categories=get_categories(),
        all_user_categories=get_all_user_categories(),
        all_genders=get_all_genders(),
        all_studies=get_all_studies(),
        categories=get_categories(),
        unique_users_count=unique_users_count,
        average_score=average_score,
        top_users=top_users,
        avg_age=avg_age,
        most_common_gender=most_common_gender,
        most_common_category=most_common_category,
        total_score=total_score,
        chart_labels=chart_labels,
        chart_values=chart_values,
        page=page,
        total_pages=total_pages
    )

@app.route("/admin/change-password/<user_id>", methods=["POST"])
@login_required
def admin_change_password(user_id):
    admin_required()

    new_password = request.form.get("new_password", "").strip()
    if not new_password:
        return redirect(url_for("admin_panel", q=user_id))

    if not passwordValidation(new_password):
        return redirect(url_for("admin_panel", q=user_id))

    update_user_password_admin(user_id, new_password)
    return redirect(url_for("admin_panel", q=user_id))


@app.route("/admin/change-category/<user_id>", methods=["POST"])
@login_required
def admin_change_category(user_id):
    admin_required()

    new_category = request.form.get("new_category", "").strip().lower()
    if not new_category:
        return redirect(url_for("admin_panel", q=user_id))

    update_user_category_admin(user_id, new_category)
    return redirect(url_for("admin_panel", q=user_id))


@app.route("/admin/export")
@login_required
def admin_export():
    admin_required()

    search_value = request.args.get("q", "").strip()
    result_category = request.args.get("result_category", "").strip()
    user_category = request.args.get("user_category", "").strip()
    gender = request.args.get("gender", "").strip()
    studies = request.args.get("studies", "").strip()
    min_age = request.args.get("min_age", "").strip()
    max_age = request.args.get("max_age", "").strip()

    results,_ = get_admin_results(
        search_value=search_value,
        result_category=result_category,
        user_category=user_category,
        gender=gender,
        studies=studies,
        min_age=min_age,
        max_age=max_age
    )

    wb = Workbook()
    ws = wb.active
    ws.title = "Resultados"

    ws.append([
        "ID Usuario",
        "Nombre",
        "Email",
        "Edad",
        "Sexo",
        "Estudios",
        "Categoría usuario",
        "Categoría resultado",
        "Código categoría",
        "Reto",
        "Fase",
        "Puntuación",
        "Completado",
        "Fecha completado"
    ])

    for row in results:
        ws.append([
            row.get("user_id"),
            row.get("name"),
            row.get("email"),
            row.get("age"),
            row.get("gender"),
            row.get("studies"),
            row.get("user_category"),
            row.get("result_category"),
            row.get("category_code"),
            row.get("challenge_title"),
            row.get("phase"),
            row.get("score"),
            row.get("completed"),
            row.get("completed_date")
        ])

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="resultados_admin.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
@app.route("/subcategory/<subcategory_code>/<phase>/review/<int:challenge_id>")
@login_required
def subcategory_review_challenge(subcategory_code, phase, challenge_id):
    if phase not in ("pre", "post"):
        abort(400)

    challenge = get_challenge_by_id(challenge_id)
    if not challenge or challenge.get("subcategory_code") != subcategory_code or challenge.get("phase") != phase:
        abort(404)

    category_code = get_category_code_by_subcategory(subcategory_code)
    if not category_code:
        abort(400)

    progress = get_user_progress_for_challenge(current_user.id, challenge_id)
    if not progress or not progress.get("completed"):
        return redirect(url_for("category_page", category_code=category_code, msg="Ese reto no está completado, no se puede revisar"))

    next_id = get_next_review_challenge_id(current_user.id, subcategory_code, phase, challenge_id)
    if next_id:
        next_url = url_for("subcategory_review_challenge", subcategory_code=subcategory_code, phase=phase, challenge_id=next_id)
        end_url = None
    else:
        next_url = None
        end_url = url_for("category_page", category_code=category_code, msg="Revisión terminada")

    options = []
    if not int(challenge.get("is_practical", 0)):
        raw_options = [
            challenge.get("option1"),
            challenge.get("option2"),
            challenge.get("option3"),
            challenge.get("option4"),
        ]
        options = [
            normalize_option_value(o)
            for o in raw_options
            if o and str(o).strip()
        ]

    challenge["correct_answer"] = normalize_option_value(challenge.get("correct_answer"))

    user_answer = progress.get("user_answer")
    practical_feedback = None
    img_practical = bool(challenge.get("img"))

    if int(challenge.get("is_practical", 0)) and user_answer:
        try:
            practical_feedback = json.loads(user_answer)
        except Exception:
            practical_feedback = {"raw": user_answer}

    if int(challenge.get("is_practical", 0)) and (challenge.get("content") and "pp_form" in challenge["content"]):
        practical_feedback = {
            "message": "En este reto se han generado contraseñas a partir de datos personales (mascotas, hijos, fechas o lugares habituales). Si alguna coincidía o se parecía a una contraseña real que uses, deberías cambiarla por una contraseña larga, única y difícil de adivinar. Este ejercicio es educativo y no se almacena ninguna información sensible ni contraseñas reales."
        }


    redirect_url = url_for("category_page", category_code=category_code)

    ai_feedback = None

    if int(challenge.get("is_practical", 0)):
        ideal = (challenge.get("ideal_answer") or "").strip()

        if user_answer and ideal:
            ai_feedback = get_ai_feedback(current_user.id, challenge_id)

            if not ai_feedback:
                try:
                    result = ai_evaluate_answer(
                        question=(challenge.get("question") or challenge.get("title") or "").strip(),
                        ideal_answer=ideal,
                        user_answer=str(user_answer)
                    )
                    save_ai_feedback(current_user.id, challenge_id, result["score"], result["comment"])
                    ai_feedback = result
                except Exception as e:
                    msg = str(e)
                    print(msg)

                    if "429" in msg or "RESOURCE_EXHAUSTED" in msg:
                        ai_feedback = {
                            "score": None,
                            "comment": "La IA no está disponible ahora mismo por límite de cuota. Inténtalo en unos segundos o más tarde."
                        }
                    else:
                        ai_feedback = {"score": None, "comment": f"No se pudo generar el feedback automático: {e}"}


    return render_template(
        "challenge.html",
        challenge=challenge,
        options=options,
        completed=True,
        review_mode=True,
        user_answer=user_answer,
        ai_feedback=ai_feedback,
        practical_feedback=practical_feedback,
        img_practical=img_practical,
        user_score=int(progress.get("score") or 0),
        next_url=next_url,
        end_url=end_url,
        category_code=category_code,
        subcategory_code=subcategory_code,
        redirect_url=redirect_url
    )




def count_phase_total_for_subcategory(subcategory_code: str, phase: str) -> int:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT COUNT(*) AS c
            FROM challenges
            WHERE subcategory_code = ? AND phase = ?
        """, (subcategory_code, phase)).fetchone()
        return int(row["c"]) if row else 0


def count_phase_done_for_subcategory(user_id: str, subcategory_code: str, phase: str) -> int:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT COUNT(*) AS c
            FROM user_challenge_progress u
            JOIN challenges c ON c.id = u.challenge_id
            WHERE u.user_id = ?
              AND u.completed = 1
              AND c.subcategory_code = ?
              AND c.phase = ?
        """, (user_id, subcategory_code, phase)).fetchone()
        return int(row["c"]) if row else 0


def count_phase_total(subcategory_code: str, phase: str) -> int:
    return count_phase_total_for_subcategory(subcategory_code, phase)


def count_phase_done(user_id: str, subcategory_code: str, phase: str) -> int:
    return count_phase_done_for_subcategory(user_id, subcategory_code, phase)


def sum_scores_for_category(user_id: str, category_code: str) -> int:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT COALESCE(SUM(u.score), 0) AS s
            FROM user_challenge_progress u
            JOIN challenges ch ON ch.id = u.challenge_id
            JOIN subcategories sc ON sc.subcategory_code = ch.subcategory_code
            WHERE u.user_id = ?
              AND u.completed = 1
              AND sc.category_code = ?
        """, (user_id, category_code)).fetchone()
        return int(row["s"]) if row else 0


def sum_scores_for_subcategory_phase(user_id: str, subcategory_code: str, phase: str) -> int:
    with get_conn() as conn:
        row = conn.execute("""
            SELECT COALESCE(SUM(u.score), 0) AS s
            FROM user_challenge_progress u
            JOIN challenges ch ON ch.id = u.challenge_id
            WHERE u.user_id = ?
              AND u.completed = 1
              AND ch.subcategory_code = ?
              AND ch.phase = ?
        """, (user_id, subcategory_code, phase)).fetchone()
        return int(row["s"]) if row else 0


def get_completed_challenges_for_review(user_id: str, subcategory_code: str, phase: str):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT ch.*, u.score AS user_score, u.user_answer AS user_answer, u.completed_date AS completed_date
            FROM user_challenge_progress u
            JOIN challenges ch ON ch.id = u.challenge_id
            WHERE u.user_id = ?
              AND u.completed = 1
              AND ch.subcategory_code = ?
              AND ch.phase = ?
            ORDER BY datetime(u.completed_date) ASC, ch.order_index ASC, ch.id ASC
        """, (user_id, subcategory_code, phase)).fetchall()
        return [dict(r) for r in rows]


def get_user_progress_for_challenge(user_id: str, challenge_id: int):
    with get_conn() as conn:
        row = conn.execute("""
            SELECT completed, completed_date, score, user_answer
            FROM user_challenge_progress
            WHERE user_id = ? AND challenge_id = ?
        """, (user_id, challenge_id)).fetchone()
        return dict(row) if row else None


def get_next_review_challenge_id(user_id: str, subcategory_code: str, phase: str, current_id: int):
    items = get_completed_challenges_for_review(user_id, subcategory_code, phase)
    ids = [c["id"] for c in items]
    try:
        idx = ids.index(current_id)
    except ValueError:
        return None
    return ids[idx + 1] if idx + 1 < len(ids) else None


def hibp_pwned_count(password: str) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "TFG-IreneGarcia/1.0 (Flask)",
        "Add-Padding": "true"
    }

    r = requests.get(url, headers=headers, timeout=10)
    r.raise_for_status()

    for line in r.text.splitlines():
        h, count = line.split(":")
        if h.strip().upper() == suffix:
            return int(count.strip())
    return 0

def get_category_scores(user_id: str, phase: str):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT cat.title AS category,
                   COALESCE(SUM(u.score), 0) AS total_score
            FROM categories cat
            JOIN subcategories sub
              ON sub.category_code = cat.category_code
            JOIN challenges ch
              ON ch.subcategory_code = sub.subcategory_code
             AND ch.phase = ?
            LEFT JOIN user_challenge_progress u
              ON u.challenge_id = ch.id
             AND u.user_id = ?
             AND u.completed = 1
            GROUP BY cat.category_code, cat.title
            ORDER BY cat.id
        """, (phase, user_id)).fetchall()

        return {row["category"]: row["total_score"] for row in rows}


def default_admin():
    init_db()

    if not get_user_by_username("admin"):
        create_user(
            "admin",
            "admin",
            "admin@tfg.es",
            "Admin_22",
            22,
            "mujer",
            "gradouniversitario",
            is_admin=1,
            user_category="urjc"
        )
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
    app.logger.info("Arranque de la aplicación")
    default_admin() 
    app.run(host='0.0.0.0', port=5000, debug=True)

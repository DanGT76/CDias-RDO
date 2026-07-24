import os
import sqlite3
import threading
import uuid
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "rdo.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")

TOKEN_TTL_DAYS = 30
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "CDias123"

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
CORS(app)

# Guards folha numbering against races when two devices save at the same time.
write_lock = threading.Lock()


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception=None):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS servicos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            cliente TEXT,
            contratante TEXT,
            cidade TEXT,
            created_by TEXT,
            created_at TEXT
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS rdos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            servico_id INTEGER,
            folha INTEGER NOT NULL,
            tipo TEXT,
            data TEXT,
            contratante TEXT,
            cliente TEXT,
            cidade TEXT,
            descricao TEXT,
            atividades TEXT,
            pendencias TEXT,
            total_horas TEXT,
            gps_lat REAL,
            gps_lng REAL,
            material_json TEXT,
            pessoal_json TEXT,
            photos_json TEXT,
            signatures_json TEXT,
            pdf_base64 TEXT,
            created_by TEXT,
            created_at TEXT
        )"""
    )
    # migração leve para bancos criados antes da coluna existir
    try:
        conn.execute("ALTER TABLE rdos ADD COLUMN servico_id INTEGER")
    except sqlite3.OperationalError:
        pass
    cur = conn.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (DEFAULT_ADMIN_USER, generate_password_hash(DEFAULT_ADMIN_PASS)),
        )
    conn.commit()
    conn.close()


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.split("Bearer ")[-1].strip() if "Bearer " in auth else None
        if not token:
            return jsonify({"error": "Não autenticado"}), 401
        db = get_db()
        row = db.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
        if not row:
            return jsonify({"error": "Sessão inválida"}), 401
        created = datetime.fromisoformat(row["created_at"])
        if datetime.utcnow() - created > timedelta(days=TOKEN_TTL_DAYS):
            db.execute("DELETE FROM sessions WHERE token = ?", (token,))
            db.commit()
            return jsonify({"error": "Sessão expirada"}), 401
        g.username = row["username"]
        return f(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Usuário ou senha inválidos"}), 401
    token = uuid.uuid4().hex
    db.execute(
        "INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)",
        (token, username, datetime.utcnow().isoformat()),
    )
    db.commit()
    return jsonify({"token": token, "username": username})


@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    auth = request.headers.get("Authorization", "")
    token = auth.split("Bearer ")[-1].strip()
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token = ?", (token,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/me")
@require_auth
def me():
    return jsonify({"username": g.username})


@app.route("/api/servicos", methods=["POST"])
@require_auth
def create_servico():
    payload = request.get_json(silent=True) or {}
    nome = (payload.get("nome") or "").strip()
    if not nome:
        return jsonify({"error": "Nome do serviço é obrigatório"}), 400
    db = get_db()
    now = datetime.utcnow().isoformat()
    cur = db.execute(
        "INSERT INTO servicos (nome, cliente, contratante, cidade, created_by, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (
            nome,
            payload.get("cliente"),
            payload.get("contratante"),
            payload.get("cidade"),
            g.username,
            now,
        ),
    )
    db.commit()
    return jsonify({
        "id": cur.lastrowid,
        "nome": nome,
        "cliente": payload.get("cliente"),
        "contratante": payload.get("contratante"),
        "cidade": payload.get("cidade"),
    })


@app.route("/api/servicos", methods=["GET"])
@require_auth
def list_servicos():
    db = get_db()
    rows = db.execute(
        """SELECT s.id, s.nome, s.cliente, s.contratante, s.cidade,
                  s.created_by, s.created_at, COUNT(r.id) AS total_folhas
           FROM servicos s
           LEFT JOIN rdos r ON r.servico_id = s.id
           GROUP BY s.id
           ORDER BY s.created_at DESC"""
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/servicos/<int:servico_id>", methods=["GET"])
@require_auth
def get_servico(servico_id):
    db = get_db()
    row = db.execute("SELECT * FROM servicos WHERE id = ?", (servico_id,)).fetchone()
    if not row:
        return jsonify({"error": "Serviço não encontrado"}), 404
    return jsonify(dict(row))


@app.route("/api/next-folha")
@require_auth
def next_folha():
    servico_id = request.args.get("servico_id", type=int)
    if not servico_id:
        return jsonify({"error": "servico_id é obrigatório"}), 400
    db = get_db()
    row = db.execute(
        "SELECT MAX(folha) AS m FROM rdos WHERE servico_id = ?", (servico_id,)
    ).fetchone()
    nxt = (row["m"] or 0) + 1
    return jsonify({"folha": nxt})


@app.route("/api/rdos", methods=["GET"])
@require_auth
def list_rdos():
    servico_id = request.args.get("servico_id", type=int)
    db = get_db()
    base_query = (
        "SELECT r.id, r.folha, r.data, r.tipo, r.cliente, r.contratante, "
        "r.created_by, r.created_at, r.servico_id, s.nome AS servico_nome "
        "FROM rdos r LEFT JOIN servicos s ON s.id = r.servico_id "
    )
    if servico_id:
        rows = db.execute(
            base_query + "WHERE r.servico_id = ? ORDER BY r.folha DESC", (servico_id,)
        ).fetchall()
    else:
        rows = db.execute(base_query + "ORDER BY r.created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/rdos/<int:rdo_id>", methods=["GET"])
@require_auth
def get_rdo(rdo_id):
    db = get_db()
    row = db.execute("SELECT * FROM rdos WHERE id = ?", (rdo_id,)).fetchone()
    if not row:
        return jsonify({"error": "Não encontrado"}), 404
    d = dict(row)
    for field in ("material_json", "pessoal_json", "photos_json", "signatures_json"):
        try:
            d[field] = json.loads(d[field]) if d[field] else None
        except (TypeError, ValueError):
            pass
    return jsonify(d)


REQUIRED_FIELDS = [
    "data",
    "contratante",
    "cliente",
    "cidade",
    "descricao",
    "atividades",
    "pendencias",
    "totalHoras",
]


@app.route("/api/rdos", methods=["POST"])
@require_auth
def create_rdo():
    payload = request.get_json(silent=True) or {}

    missing = [f for f in REQUIRED_FIELDS if not str(payload.get(f, "")).strip()]

    servico_id = payload.get("servico_id")
    if not servico_id:
        missing.append("servico")

    material = payload.get("material") or []
    if not any((m.get("desc") or "").strip() for m in material):
        missing.append("material")

    pessoal = payload.get("pessoal") or []
    if not any((p.get("nome") or "").strip() for p in pessoal):
        missing.append("pessoal")

    gps = payload.get("gps") or {}

    sigs = payload.get("signatures") or {}
    for key in ("sig_empreita", "sig_cliente", "sig_tecnico"):
        if not sigs.get(key):
            missing.append(key)

    if not payload.get("pdf_base64"):
        missing.append("pdf")

    if missing:
        return jsonify({"error": "Campos obrigatórios ausentes", "missing": missing}), 400

    with write_lock:
        db = get_db()
        srow = db.execute("SELECT id FROM servicos WHERE id = ?", (servico_id,)).fetchone()
        if not srow:
            return jsonify({"error": "Serviço inválido", "missing": ["servico"]}), 400
        row = db.execute(
            "SELECT MAX(folha) AS m FROM rdos WHERE servico_id = ?", (servico_id,)
        ).fetchone()
        folha = (row["m"] or 0) + 1
        now = datetime.utcnow().isoformat()
        cur = db.execute(
            """INSERT INTO rdos (
                servico_id, folha, tipo, data, contratante, cliente, cidade, descricao,
                atividades, pendencias, total_horas, gps_lat, gps_lng,
                material_json, pessoal_json, photos_json, signatures_json,
                pdf_base64, created_by, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                servico_id,
                folha,
                payload.get("tipo"),
                payload.get("data"),
                payload.get("contratante"),
                payload.get("cliente"),
                payload.get("cidade"),
                payload.get("descricao"),
                payload.get("atividades"),
                payload.get("pendencias"),
                payload.get("totalHoras"),
                gps.get("lat"),
                gps.get("lng"),
                json.dumps(material),
                json.dumps(pessoal),
                json.dumps(payload.get("photos") or {}),
                json.dumps(sigs),
                payload.get("pdf_base64"),
                g.username,
                now,
            ),
        )
        db.commit()
        new_id = cur.lastrowid

    return jsonify({"id": new_id, "folha": folha, "servico_id": servico_id, "created_at": now})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)

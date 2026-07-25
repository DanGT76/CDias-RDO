import os
import threading
import uuid
import json
from datetime import datetime, timedelta
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Connection string do Postgres (ex.: Neon). Definida como variável de ambiente
# no Render — nunca deixar hardcoded aqui.
DATABASE_URL = os.environ.get("DATABASE_URL")

TOKEN_TTL_DAYS = 30
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "CDias123"

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
CORS(app)

# Protege a numeração da folha contra corrida quando dois dispositivos salvam ao
# mesmo tempo. Só é eficaz com 1 worker do gunicorn (ver Procfile/render.yaml) —
# com múltiplos workers cada processo teria seu próprio lock.
write_lock = threading.Lock()


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = psycopg2.connect(
            DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor
        )
    return db


@app.teardown_appcontext
def close_db(exception=None):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def init_db():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL não definida. Configure a connection string do Postgres "
            "(ex.: Neon) nas variáveis de ambiente."
        )
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )"""
    )
    cur.execute(
        """CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"""
    )
    cur.execute(
        """CREATE TABLE IF NOT EXISTS servicos (
            id SERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            cliente TEXT,
            contratante TEXT,
            cidade TEXT,
            created_by TEXT,
            created_at TEXT
        )"""
    )
    cur.execute(
        """CREATE TABLE IF NOT EXISTS rdos (
            id SERIAL PRIMARY KEY,
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
    cur.execute(
        """INSERT INTO users (username, password_hash)
           SELECT %s, %s
           WHERE NOT EXISTS (SELECT 1 FROM users)""",
        (DEFAULT_ADMIN_USER, generate_password_hash(DEFAULT_ADMIN_PASS)),
    )
    conn.commit()
    cur.close()
    conn.close()


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.split("Bearer ")[-1].strip() if "Bearer " in auth else None
        if not token:
            return jsonify({"error": "Não autenticado"}), 401
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM sessions WHERE token = %s", (token,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Sessão inválida"}), 401
        created = datetime.fromisoformat(row["created_at"])
        if datetime.utcnow() - created > timedelta(days=TOKEN_TTL_DAYS):
            cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
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
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    row = cur.fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Usuário ou senha inválidos"}), 401
    token = uuid.uuid4().hex
    cur.execute(
        "INSERT INTO sessions (token, username, created_at) VALUES (%s, %s, %s)",
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
    cur = db.cursor()
    cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
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
    cur = db.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO servicos (nome, cliente, contratante, cidade, created_by, created_at) "
        "VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
        (
            nome,
            payload.get("cliente"),
            payload.get("contratante"),
            payload.get("cidade"),
            g.username,
            now,
        ),
    )
    new_id = cur.fetchone()["id"]
    db.commit()
    return jsonify({
        "id": new_id,
        "nome": nome,
        "cliente": payload.get("cliente"),
        "contratante": payload.get("contratante"),
        "cidade": payload.get("cidade"),
    })


@app.route("/api/servicos", methods=["GET"])
@require_auth
def list_servicos():
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """SELECT s.id, s.nome, s.cliente, s.contratante, s.cidade,
                  s.created_by, s.created_at, COUNT(r.id) AS total_folhas
           FROM servicos s
           LEFT JOIN rdos r ON r.servico_id = s.id
           GROUP BY s.id
           ORDER BY s.created_at DESC"""
    )
    rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/servicos/<int:servico_id>", methods=["GET"])
@require_auth
def get_servico(servico_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM servicos WHERE id = %s", (servico_id,))
    row = cur.fetchone()
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
    cur = db.cursor()
    cur.execute("SELECT MAX(folha) AS m FROM rdos WHERE servico_id = %s", (servico_id,))
    row = cur.fetchone()
    nxt = (row["m"] or 0) + 1
    return jsonify({"folha": nxt})


@app.route("/api/rdos", methods=["GET"])
@require_auth
def list_rdos():
    servico_id = request.args.get("servico_id", type=int)
    db = get_db()
    cur = db.cursor()
    base_query = (
        "SELECT r.id, r.folha, r.data, r.tipo, r.cliente, r.contratante, "
        "r.created_by, r.created_at, r.servico_id, s.nome AS servico_nome "
        "FROM rdos r LEFT JOIN servicos s ON s.id = r.servico_id "
    )
    if servico_id:
        cur.execute(base_query + "WHERE r.servico_id = %s ORDER BY r.folha DESC", (servico_id,))
    else:
        cur.execute(base_query + "ORDER BY r.created_at DESC")
    rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/rdos/<int:rdo_id>", methods=["GET"])
@require_auth
def get_rdo(rdo_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM rdos WHERE id = %s", (rdo_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "Não encontrado"}), 404
    d = dict(row)
    for field in ("material_json", "pessoal_json", "photos_json", "signatures_json"):
        try:
            d[field] = json.loads(d[field]) if d[field] else None
        except (TypeError, ValueError):
            pass
    return jsonify(d)


# "descricao" é opcional (ver static/index.html) — não entra na validação obrigatória.
REQUIRED_FIELDS = [
    "data",
    "contratante",
    "cliente",
    "cidade",
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
        cur = db.cursor()
        cur.execute("SELECT id FROM servicos WHERE id = %s", (servico_id,))
        srow = cur.fetchone()
        if not srow:
            return jsonify({"error": "Serviço inválido", "missing": ["servico"]}), 400
        cur.execute("SELECT MAX(folha) AS m FROM rdos WHERE servico_id = %s", (servico_id,))
        folha = (cur.fetchone()["m"] or 0) + 1
        now = datetime.utcnow().isoformat()
        cur.execute(
            """INSERT INTO rdos (
                servico_id, folha, tipo, data, contratante, cliente, cidade, descricao,
                atividades, pendencias, total_horas, gps_lat, gps_lng,
                material_json, pessoal_json, photos_json, signatures_json,
                pdf_base64, created_by, created_at
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id""",
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
        new_id = cur.fetchone()["id"]
        db.commit()

    return jsonify({"id": new_id, "folha": folha, "servico_id": servico_id, "created_at": now})


# Cria as tabelas (se não existirem) assim que o módulo é importado — necessário
# porque em produção quem sobe o app é o gunicorn (ver Procfile), que nunca
# executa o bloco "if __name__ == '__main__'" abaixo.
if DATABASE_URL:
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

import os
import base64
import hashlib
import secrets
from datetime import date, datetime, timedelta

import pymysql
import requests
import boto3
import bcrypt
from dotenv import load_dotenv

from flask import (
    Flask, jsonify, render_template, request,
    redirect, url_for, session, flash
)
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from mahjong.hand_calculating.hand import HandCalculator
from mahjong.tile import TilesConverter
from mahjong.hand_calculating.hand_config import HandConfig


# ============================================
# Flask 初期化
# ============================================

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "macnijong-default-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# CSRF
csrf = CSRFProtect(app)

# レートリミット
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300 per hour"]
)
limiter.init_app(app)


# セキュリティヘッダー
@app.after_request
def add_security_headers(resp):
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self' https:; "
        "font-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    return resp

# ============================================
# DB & ユーティリティ
# ============================================

def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME"),
        cursorclass=pymysql.cursors.DictCursor,
    )

def log_audit(action: str, result: str = "success",
              user_id=None, email=None):
    """監査ログ用ユーティリティ"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (user_id, email, action, result, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            user_id,
            email,
            action,
            result,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            request.headers.get("User-Agent", ""),
        ))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[audit_log ERROR] {e}", flush=True)

def hash_password(password):
    """旧 SHA-256 ハッシュ（既存互換用）"""
    return hashlib.sha256(password.encode()).hexdigest()


# ============================================
# パスワード（bcrypt）
# ============================================

def hash_password_bcrypt(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password_bcrypt(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ============================================
# メール認証 & SES
# ============================================

ALLOWED_DOMAINS = ("macnica.co.jp", "pn.macnica.co.jp")


def is_allowed_email(email: str) -> bool:
    if not email or "@" not in email:
        return False
    domain = email.strip().lower().split("@")[-1]
    return domain in ALLOWED_DOMAINS


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def send_verification_email(to_email: str, token: str):
    base_url = os.getenv("APP_BASE_URL", "http://localhost:5000")
    link = f"{base_url}/register/verify?token={token}"
    subject = "【Macni雀】アカウント登録の確認"
    body = f"""Macni雀 アカウント登録リクエストを受け付けました。

下記のリンクから登録を完了してください（15分以内に有効）：

{link}

このメールに心当たりがない場合は破棄してください。
"""
    client = boto3.client(
        "ses",
        region_name=os.getenv("AWS_REGION", "ap-northeast-1"),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    client.send_email(
        Source=os.getenv("SES_SENDER_EMAIL"),
        Destination={"ToAddresses": [to_email]},
        Message={
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
        },
    )


# ============================================
# Teams通知（既存機能）
# ============================================

def notify_teams_matching_success(post_id, requester_user_id):
    print("[DEBUG] notify function called", flush=True)
    print("[DEBUG] post_id =", post_id, flush=True)
    print("[DEBUG] requester_user_id =", requester_user_id, flush=True)

    webhook_url = os.getenv("TEAMS_WEBHOOK_URL")
    print("[DEBUG] webhook_url =", webhook_url, flush=True)

    if not webhook_url:
        print("[Teams通知] TEAMS_WEBHOOK_URL が設定されていません", flush=True)
        return

    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                u_owner.employee_number AS owner_empnum,
                u_req.employee_number AS req_empnum,
                mp.target_date,
                mp.time_range,
                mp.location
            FROM matching_posts mp
            JOIN users u_owner ON mp.user_id = u_owner.id
            JOIN users u_req ON u_req.id = %s
            WHERE mp.id = %s
        """, (requester_user_id, post_id))
        info = cursor.fetchone()
        cursor.close()
        conn.close()

        print("[DEBUG] DB info =", info, flush=True)

        if not info:
            return

        owner_emp   = info.get("owner_empnum")
        req_emp     = info.get("req_empnum")
        target_date = info.get("target_date")
        time_range  = info.get("time_range") or "時間未定"
        location    = info.get("location") or "場所未定"

        message_text = (
            f"Macni雀 マッチング成立\n\n"
            f"- 募集者: {owner_emp}\n"
            f"- 申請者: {req_emp}\n"
            f"- 日付: {target_date}\n"
            f"- 時間帯: {time_range}\n"
            f"- 場所: {location}"
        )

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "Large",
                                "weight": "Bolder",
                                "text": "Macni雀 マッチング成立"
                            },
                            {
                                "type": "TextBlock",
                                "wrap": True,
                                "text": message_text
                            }
                        ]
                    }
                }
            ]
        }

        response = requests.post(webhook_url, json=payload, timeout=10)
        print("[DEBUG] status =", response.status_code, flush=True)
        print("[DEBUG] response =", response.text, flush=True)

    except Exception as e:
        print(f"[Teams通知エラー] {e}", flush=True)


# ============================================
# 共通ページ
# ============================================

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("menu"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour", methods=["POST"])
def login():
    error = None
    if request.method == "POST":
        emp_num = request.form.get("employee_number", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE employee_number=%s",
            (emp_num,)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and verify_password_bcrypt(password, user["password_hash"]):
            session["user_id"] = user["id"]
            session["nickname"] = user["nickname"]
            log_audit("login_success", user_id=user["id"], email=user.get("email"))
            return redirect(url_for("menu"))
        else:
            log_audit("login_fail", result="fail", email=emp_num)
            error = "社員番号またはパスワードが正しくありません"

    return render_template("login.html", error=error)

@app.errorhandler(429)
def ratelimit_handler(e):
    log_audit("login_rate_limited", result="fail")
    return render_template(
        "login.html",
        error="ログイン試行回数が多すぎます。しばらく（15分程度）経ってから再度お試しください。"
    ), 429


@app.route("/password/reset", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def password_reset():
    sent = False
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not is_allowed_email(email):
            error = "社員メールアドレス（@macnica.co.jp / @pn.macnica.co.jp）を入力してください"
        else:
            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
                user = cursor.fetchone()

                if user:
                    token = generate_token()
                    expires_at = datetime.utcnow() + timedelta(minutes=30)
                    cursor.execute(
                        "INSERT INTO password_resets (user_id, token, expires_at) VALUES (%s, %s, %s)",
                        (user["id"], token, expires_at)
                    )
                    conn.commit()

                    base_url = os.getenv("APP_BASE_URL", "http://localhost:5000")
                    link = f"{base_url}/password/reset/confirm?token={token}"
                    subject = "【Macni雀】パスワード再設定"
                    body = (
                        "Macni雀 パスワード再設定リクエストを受け付けました。\n\n"
                        "下記のリンクから30分以内に新しいパスワードを設定してください：\n\n"
                        f"{link}\n\n"
                        "このメールに心当たりがない場合は破棄してください。\n"
                    )

                    client = boto3.client(
                        "ses",
                        region_name=os.getenv("AWS_REGION", "ap-northeast-1"),
                        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                    )
                    client.send_email(
                        Source=os.getenv("SES_SENDER_EMAIL"),
                        Destination={"ToAddresses": [email]},
                        Message={
                            "Subject": {"Data": subject, "Charset": "UTF-8"},
                            "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
                        },
                    )
                    log_audit("password_reset_request", result="sent", email=email)
                else:
                    # メール流出を防ぐため、存在しなくても成功風の応答
                    log_audit("password_reset_request", result="unknown_email", email=email)

                cursor.close()
                conn.close()
                sent = True

            except Exception as e:
                error = f"送信エラー: {str(e)}"
                log_audit("password_reset_request", result="error", email=email)

    return render_template("password_reset.html", error=error, sent=sent)


@app.route("/password/reset/confirm", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def password_reset_confirm():
    token = request.args.get("token") or request.form.get("token")
    if not token:
        return "トークンがありません", 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM password_resets WHERE token=%s", (token,))
    row = cursor.fetchone()

    if not row:
        cursor.close(); conn.close()
        log_audit("password_reset_invalid", result="fail")
        return "無効なトークンです", 400
    if row["used"]:
        cursor.close(); conn.close()
        log_audit("password_reset_used", result="fail")
        return "このトークンは既に使用済みです", 400
    if row["expires_at"] < datetime.utcnow():
        cursor.close(); conn.close()
        log_audit("password_reset_expired", result="fail")
        return "トークンの有効期限が切れています", 400

    error = None
    if request.method == "POST":
        pw1 = request.form.get("password", "")
        pw2 = request.form.get("password2", "")

        if len(pw1) < 8:
            error = "パスワードは8文字以上にしてください"
        elif pw1 != pw2:
            error = "パスワードが一致しません"
        else:
            new_hash = hash_password_bcrypt(pw1)
            try:
                cursor.execute(
                    "UPDATE users SET password_hash=%s WHERE id=%s",
                    (new_hash, row["user_id"])
                )
                cursor.execute(
                    "UPDATE password_resets SET used=1 WHERE token=%s",
                    (token,)
                )
                conn.commit()
                log_audit("password_reset_complete", user_id=row["user_id"])
                cursor.close(); conn.close()
                flash("パスワードを更新しました。新しいパスワードでログインしてください。")
                return redirect(url_for("login"))
            except Exception as e:
                error = f"更新エラー: {str(e)}"

    cursor.close(); conn.close()
    return render_template("password_reset_confirm.html", token=token, error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    """メールアドレスを受け取り、認証メールを送信"""
    error = None
    sent = False
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not is_allowed_email(email):
            error = "社員メールアドレス（@macnica.co.jp / @pn.macnica.co.jp）を入力してください"
            log_audit("register_start", result="reject_domain", email=email)
        else:
            try:
                token = generate_token()
                expires_at = datetime.utcnow() + timedelta(minutes=15)

                conn = get_db()
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO email_verifications (email, token, expires_at) VALUES (%s, %s, %s)",
                    (email, token, expires_at),
                )
                conn.commit()
                cursor.close()
                conn.close()

                send_verification_email(email, token)
                log_audit("register_start", result="sent", email=email)
                sent = True
            except Exception as e:
                error = f"送信エラー: {str(e)}"
                log_audit("register_start", result="error", email=email)

    return render_template("register.html", error=error, sent=sent)

@app.route("/register/verify", methods=["GET", "POST"])

def register_verify():
    token = request.args.get("token") or request.form.get("token")
    if not token:
        return "トークンがありません", 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM email_verifications WHERE token=%s",
        (token,)
    )
    row = cursor.fetchone()

    if not row:
        cursor.close(); conn.close()
        log_audit("verify_invalid", result="fail")
        return "無効なトークンです", 400

    if row["used"]:
        cursor.close(); conn.close()
        log_audit("verify_used", result="fail", email=row["email"])
        return "このトークンは既に使用済みです", 400

    if row["expires_at"] < datetime.utcnow():
        cursor.close(); conn.close()
        log_audit("verify_expired", result="fail", email=row["email"])
        return "トークンの有効期限が切れています", 400

    if request.method == "POST":
        nickname = request.form.get("nickname", "").strip()
        emp_num = request.form.get("employee_number", "").strip()
        password = request.form.get("password", "")

        if not (nickname and emp_num and password):
            cursor.close(); conn.close()
            return render_template("register_complete.html",
                                   token=token, email=row["email"],
                                   error="全ての項目を入力してください")

        if len(password) < 8:
            cursor.close(); conn.close()
            return render_template("register_complete.html",
                                   token=token, email=row["email"],
                                   error="パスワードは8文字以上にしてください")

        pw_hash = hash_password_bcrypt(password)

        try:
            cursor.execute(
                "INSERT INTO users (employee_number, password_hash, nickname, email) VALUES (%s, %s, %s, %s)",
                (emp_num, pw_hash, nickname, row["email"])
            )
            cursor.execute(
                "UPDATE email_verifications SET used=1 WHERE token=%s",
                (token,)
            )
            conn.commit()
            log_audit("register_complete", email=row["email"])
            cursor.close(); conn.close()
            flash("登録が完了しました。ログインしてください。")
            return redirect(url_for("login"))
        except pymysql.err.IntegrityError:
            cursor.close(); conn.close()
            log_audit("register_complete", result="duplicate", email=row["email"])
            return render_template("register_complete.html",
                                   token=token, email=row["email"],
                                   error="社員番号またはメールアドレスは既に使用されています")

    cursor.close(); conn.close()
    return render_template("register_complete.html",
                           token=token, email=row["email"], error=None)


@app.route("/menu")
def menu():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("menu.html", nickname=session.get("nickname"))


@app.route("/logout")
def logout():
    log_audit("logout", user_id=session.get("user_id"))
    session.clear()
    return redirect(url_for("login"))


# ============================================
# 点数管理機能
# ============================================

@app.route("/score-manage")
def score_manage():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, employee_number, nickname FROM users ORDER BY nickname")
    users = cursor.fetchall()

    cursor.execute("""
        SELECT g.id, g.group_name
        FROM groups_tbl g
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.user_id = %s
        ORDER BY g.group_name
    """, (session["user_id"],))
    user_groups = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "score_manage.html",
        username=session.get("nickname"),
        users=users,
        user_groups=user_groups,
    )


# --- ELO レーティング（Phase 1）---

ELO_K_DEFAULT = 32
ELO_K_NEWBIE = 64
ELO_K_VETERAN = 16


def _get_k_value(games: int) -> int:
    if games < 20:
        return ELO_K_NEWBIE
    if games >= 200:
        return ELO_K_VETERAN
    return ELO_K_DEFAULT


def _expected_score(r_self: float, r_opp: float) -> float:
    return 1.0 / (1.0 + 10 ** ((r_opp - r_self) / 400.0))


def _actual_score(p_self: int, p_opp: int) -> float:
    diff = p_self - p_opp
    if diff == 0:
        return 0.5
    score = 0.5 + (diff / 100.0)
    return max(0.0, min(1.0, score))


def update_ratings_for_match(players: list, totals: list):
    if len(players) != 4 or len(totals) != 4:
        return

    user_ids = [int(p["user_id"]) for p in players]

    try:
        conn = get_db()
        cursor = conn.cursor()

        ratings = {}
        games_map = {}
        for uid in user_ids:
            cursor.execute(
                "SELECT rating, games FROM user_ratings WHERE user_id = %s",
                (uid,)
            )
            row = cursor.fetchone()
            if not row:
                cursor.execute(
                    "INSERT INTO user_ratings (user_id, rating) VALUES (%s, 1500)",
                    (uid,)
                )
                ratings[uid] = 1500
                games_map[uid] = 0
            else:
                ratings[uid] = int(row["rating"])
                games_map[uid] = int(row["games"])

        diffs = {uid: 0.0 for uid in user_ids}
        for i in range(4):
            for j in range(i + 1, 4):
                ui, uj = user_ids[i], user_ids[j]
                ri, rj = ratings[ui], ratings[uj]
                pi, pj = totals[i], totals[j]

                ei = _expected_score(ri, rj)
                ej = 1.0 - ei
                si = _actual_score(pi, pj)
                sj = 1.0 - si

                ki = _get_k_value(games_map[ui])
                kj = _get_k_value(games_map[uj])

                diffs[ui] += ki * (si - ei)
                diffs[uj] += kj * (sj - ej)

        for uid in user_ids:
            new_rating = int(round(ratings[uid] + diffs[uid]))
            won = 1 if diffs[uid] > 0 else 0
            lost = 1 if diffs[uid] < 0 else 0

            cursor.execute("""
                UPDATE user_ratings
                SET rating = %s,
                    games  = games + 1,
                    win    = win + %s,
                    lose   = lose + %s
                WHERE user_id = %s
            """, (new_rating, won, lost, uid))

        conn.commit()
        cursor.close()
        conn.close()

        print(f"[Rating] updated: {diffs}", flush=True)

    except Exception as e:
        print(f"[Rating ERROR] {e}", flush=True)


@app.route("/score-manage/save", methods=["POST"])
def score_manage_save():
    if "user_id" not in session:
        return jsonify({"status": "error", "message": "ログインしてください"}), 401

    data = request.get_json()
    played_date = data.get("played_date")
    group_id = data.get("group_id")
    players = data.get("players", [])
    rounds = data.get("rounds", [])

    if not played_date:
        return jsonify({"status": "error", "message": "日付が指定されていません"}), 400
    if len(players) != 4:
        return jsonify({"status": "error", "message": "プレイヤーは4人必要です"}), 400
    if not rounds:
        return jsonify({"status": "error", "message": "半荘データがありません"}), 400

    for r in rounds:
        if sum(r["scores"]) != 0:
            return jsonify({
                "status": "error",
                "message": f'半荘{r["round_number"]}の合計が0になっていません'
            }), 400

    group_id = None if (group_id == "" or group_id is None) else int(group_id)

    try:
        conn = get_db()
        cursor = conn.cursor()

        for r in rounds:
            for i, score in enumerate(r["scores"]):
                player = players[i]
                cursor.execute(
                    """INSERT INTO score_records
                       (group_id, user_id, score, point, round_number, played_date)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (group_id, player["user_id"], 0, score, r["round_number"], played_date)
                )

        conn.commit()
        cursor.close()
        conn.close()

        # レート自動更新
        totals = [0, 0, 0, 0]
        for r in rounds:
            for i, sc in enumerate(r["scores"]):
                totals[i] += int(sc)
        update_ratings_for_match(players, totals)

        return jsonify({"status": "success", "message": "保存しました"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ============================================
# 賭博モード（DB保存なし）
# ============================================

@app.route("/gamble-mode")
def gamble_mode():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template(
        "gamble_mode.html",
        username=session.get("nickname"),
    )


# ============================================
# グループ機能（省略なし・既存踏襲）
# ============================================

@app.route("/groups")
def groups():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    search = request.args.get("q", "").strip()

    conn = get_db()
    cursor = conn.cursor()

    if search:
        cursor.execute("""
            SELECT DISTINCT g.id, g.group_name, g.created_at,
                   (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) AS member_count,
                   (SELECT MAX(played_date) FROM score_records WHERE group_id = g.id) AS last_played
            FROM groups_tbl g
            JOIN group_members gm ON g.id = gm.group_id
            LEFT JOIN group_members gm2 ON g.id = gm2.group_id
            LEFT JOIN users u ON gm2.user_id = u.id
            WHERE gm.user_id = %s
            AND (g.group_name LIKE %s OR u.nickname LIKE %s OR u.employee_number LIKE %s)
            ORDER BY last_played DESC, g.created_at DESC
        """, (user_id, f"%{search}%", f"%{search}%", f"%{search}%"))
    else:
        cursor.execute("""
            SELECT g.id, g.group_name, g.created_at,
                   (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) AS member_count,
                   (SELECT MAX(played_date) FROM score_records WHERE group_id = g.id) AS last_played
            FROM groups_tbl g
            JOIN group_members gm ON g.id = gm.group_id
            WHERE gm.user_id = %s
            ORDER BY last_played DESC, g.created_at DESC
        """, (user_id,))

    group_list = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template(
        "groups.html",
        nickname=session.get("nickname"),
        groups=group_list,
        search=search,
    )


@app.route("/groups/new", methods=["GET", "POST"])
def groups_new():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        group_name = request.form.get("group_name", "").strip()
        member_ids = request.form.getlist("member_ids")

        if not group_name:
            flash("グループ名を入力してください")
            return redirect(url_for("groups_new"))

        if len(member_ids) < 2:
            flash("メンバーは2人以上選択してください")
            return redirect(url_for("groups_new"))

        if str(session["user_id"]) not in member_ids:
            member_ids.append(str(session["user_id"]))

        try:
            conn = get_db()
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO groups_tbl (group_name, created_by) VALUES (%s, %s)",
                (group_name, session["user_id"])
            )
            group_id = cursor.lastrowid

            for mid in member_ids:
                cursor.execute(
                    "INSERT INTO group_members (group_id, user_id) VALUES (%s, %s)",
                    (group_id, int(mid))
                )

            conn.commit()
            cursor.close()
            conn.close()

            flash(f'グループ「{group_name}」を作成しました')
            return redirect(url_for("groups"))

        except Exception as e:
            return f"エラー: {str(e)}", 500

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, employee_number, nickname FROM users WHERE id != %s ORDER BY nickname",
        (session["user_id"],)
    )
    users = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template(
        "groups_new.html",
        nickname=session.get("nickname"),
        users=users,
    )


@app.route("/groups/<int:group_id>")
def group_detail(group_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM groups_tbl WHERE id = %s", (group_id,))
    group = cursor.fetchone()

    if not group:
        cursor.close()
        conn.close()
        return "グループが見つかりません", 404

    cursor.execute("""
        SELECT u.id, u.nickname, u.employee_number
        FROM group_members gm
        JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = %s
        ORDER BY u.nickname
    """, (group_id,))
    members = cursor.fetchall()

    member_ids = [m["id"] for m in members]
    if session["user_id"] not in member_ids:
        cursor.close()
        conn.close()
        return "このグループにアクセスする権限がありません", 403

    cursor.execute("""
        SELECT played_date, user_id, SUM(point) AS total_point
        FROM score_records
        WHERE group_id = %s
        GROUP BY played_date, user_id
        ORDER BY played_date ASC
    """, (group_id,))
    records = cursor.fetchall()

    cursor.close()
    conn.close()

    date_data = {}
    for r in records:
        date_key = r["played_date"].strftime("%Y-%m-%d")
        if date_key not in date_data:
            date_data[date_key] = {}
        date_data[date_key][r["user_id"]] = float(r["total_point"])

    totals = {m["id"]: 0 for m in members}
    for date_key, scores in date_data.items():
        for uid, point in scores.items():
            if uid in totals:
                totals[uid] += point

    return render_template(
        "group_detail.html",
        nickname=session.get("nickname"),
        group=group,
        members=members,
        date_data=date_data,
        totals=totals,
    )


# ============================================
# マッチング機能（既存）
# ============================================

@app.route("/matching")
def matching():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE matching_posts
        SET status = 'expired'
        WHERE status = 'open' AND target_date < CURDATE()
    """)
    conn.commit()

    cursor.execute("""
        SELECT mp.*, u.nickname AS poster_nickname, u.employee_number AS poster_empnum
        FROM matching_posts mp
        JOIN users u ON mp.user_id = u.id
        WHERE mp.status IN ('open', 'matched')
        AND mp.target_date >= CURDATE()
        ORDER BY mp.created_at DESC
    """)
    posts = cursor.fetchall()

    cursor.execute("""
        SELECT COUNT(*) AS pending_count
        FROM matching_requests mr
        JOIN matching_posts mp ON mr.post_id = mp.id
        WHERE mp.user_id = %s AND mr.status = 'pending'
    """, (user_id,))
    pending_count = cursor.fetchone()["pending_count"]

    cursor.close()
    conn.close()

    return render_template(
        "matching.html",
        nickname=session.get("nickname"),
        user_id=user_id,
        posts=posts,
        pending_count=pending_count,
    )


@app.route("/matching/post", methods=["POST"])
def matching_post():
    if "user_id" not in session:
        return redirect(url_for("login"))

    post_type = request.form.get("post_type")
    target_date = request.form.get("target_date", "").strip()
    time_range = request.form.get("time_range", "").strip()
    location = request.form.get("location", "").strip()
    needed_count = request.form.get("needed_count", "0")
    comment = request.form.get("comment", "").strip()

    if post_type not in ["recruit", "apply"]:
        flash("投稿タイプが不正です")
        return redirect(url_for("matching"))
    if not target_date:
        flash("日付を入力してください")
        return redirect(url_for("matching"))
    if not location:
        flash("場所を入力してください")
        return redirect(url_for("matching"))

    try:
        needed_count = int(needed_count) if post_type == "recruit" else 0
    except ValueError:
        needed_count = 0

    if post_type == "recruit" and (needed_count < 1 or needed_count > 3):
        flash("募集人数は1〜3人で入力してください")
        return redirect(url_for("matching"))

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO matching_posts
            (user_id, post_type, target_date, time_range, location, needed_count, comment, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'open')
        """, (session["user_id"], post_type, target_date, time_range, location, needed_count, comment))
        conn.commit()
        cursor.close()
        conn.close()
        flash("投稿しました")
        return redirect(url_for("matching"))
    except Exception as e:
        return f"エラー: {str(e)}", 500


@app.route("/matching/<int:post_id>/delete", methods=["POST"])
def matching_delete(post_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT user_id FROM matching_posts WHERE id = %s", (post_id,))
        post = cursor.fetchone()
        if not post or post["user_id"] != session["user_id"]:
            cursor.close()
            conn.close()
            return "権限がありません", 403

        cursor.execute("UPDATE matching_posts SET status = 'closed' WHERE id = %s", (post_id,))
        cursor.execute("""
            UPDATE matching_requests SET status = 'rejected'
            WHERE post_id = %s AND status = 'pending'
        """, (post_id,))

        conn.commit()
        cursor.close()
        conn.close()
        flash("投稿を削除しました")
        return redirect(url_for("matching"))
    except Exception as e:
        return f"エラー: {str(e)}", 500


@app.route("/matching/<int:post_id>/request", methods=["POST"])
def matching_request(post_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM matching_posts WHERE id = %s", (post_id,))
        post = cursor.fetchone()
        if not post:
            cursor.close()
            conn.close()
            return "投稿が見つかりません", 404

        if post["user_id"] == user_id:
            cursor.close()
            conn.close()
            flash("自分の投稿には申請できません")
            return redirect(url_for("matching"))

        cursor.execute("""
            SELECT id FROM matching_requests
            WHERE post_id = %s AND requester_id = %s AND status IN ('pending', 'accepted')
        """, (post_id, user_id))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            flash("既に申請済みです")
            return redirect(url_for("matching"))

        cursor.execute("""
            INSERT INTO matching_requests (post_id, requester_id, status)
            VALUES (%s, %s, 'pending')
        """, (post_id, user_id))
        conn.commit()
        cursor.close()
        conn.close()
        flash("マッチング申請を送りました")
        return redirect(url_for("matching"))
    except Exception as e:
        return f"エラー: {str(e)}", 500


@app.route("/matching/requests")
def matching_requests():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT mr.*, mp.post_type, mp.target_date, mp.time_range, mp.location, mp.comment AS post_comment,
               u.nickname AS requester_nickname, u.employee_number AS requester_empnum
        FROM matching_requests mr
        JOIN matching_posts mp ON mr.post_id = mp.id
        JOIN users u ON mr.requester_id = u.id
        WHERE mp.user_id = %s AND mr.status = 'pending'
        ORDER BY mr.created_at DESC
    """, (user_id,))
    requests_list = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "matching_requests.html",
        nickname=session.get("nickname"),
        requests=requests_list,
    )


@app.route("/matching/requests/<int:request_id>/accept", methods=["POST"])
def matching_accept(request_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT mr.*, mp.user_id AS post_owner_id, mp.needed_count
            FROM matching_requests mr
            JOIN matching_posts mp ON mr.post_id = mp.id
            WHERE mr.id = %s
        """, (request_id,))
        req = cursor.fetchone()
        if not req or req["post_owner_id"] != user_id:
            cursor.close()
            conn.close()
            return "権限がありません", 403

        cursor.execute("UPDATE matching_requests SET status = 'accepted' WHERE id = %s", (request_id,))
        cursor.execute("""
            UPDATE matching_posts SET needed_count = GREATEST(needed_count - 1, 0)
            WHERE id = %s
        """, (req["post_id"],))
        cursor.execute("SELECT needed_count FROM matching_posts WHERE id = %s", (req["post_id"],))
        updated = cursor.fetchone()
        if updated["needed_count"] == 0:
            cursor.execute("UPDATE matching_posts SET status = 'matched' WHERE id = %s", (req["post_id"],))

        conn.commit()
        cursor.close()
        conn.close()

        notify_teams_matching_success(req["post_id"], req["requester_id"])

        flash("マッチング成立しました")
        return redirect(url_for("matching_requests"))
    except Exception as e:
        return f"エラー: {str(e)}", 500


@app.route("/matching/requests/<int:request_id>/reject", methods=["POST"])
def matching_reject(request_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT mr.id, mp.user_id AS post_owner_id
            FROM matching_requests mr
            JOIN matching_posts mp ON mr.post_id = mp.id
            WHERE mr.id = %s
        """, (request_id,))
        req = cursor.fetchone()
        if not req or req["post_owner_id"] != user_id:
            cursor.close()
            conn.close()
            return "権限がありません", 403

        cursor.execute("UPDATE matching_requests SET status = 'rejected' WHERE id = %s", (request_id,))
        conn.commit()
        cursor.close()
        conn.close()
        flash("申請を拒否しました")
        return redirect(url_for("matching_requests"))
    except Exception as e:
        return f"エラー: {str(e)}", 500


# ============================================
# 点数計算機能（既存）
# ============================================

@app.route("/score", methods=["GET", "POST"])
def score():
    result = None
    need_more = None
    detected_pretty = []
    image_url = None
    saved_path = None
    ai_result = None
    pick_win_tile = False
    detected_tiles = []
    detected_tiles_str = ""

    if request.method == "POST":
        new_image = request.files.get("image")
        prev_path = request.form.get("saved_path", "").strip()

        if new_image and new_image.filename:
            os.makedirs("static/uploads", exist_ok=True)
            saved_path = "static/uploads/" + secure_filename(new_image.filename)
            new_image.save(saved_path)
            detected_tiles_str = ""
        elif prev_path:
            saved_path = prev_path
            detected_tiles_str = request.form.get("detected_tiles_str", "")
        else:
            return render_template("score.html", error="ファイルを選択してください")

        image_url = "/" + saved_path

        detected_tiles = detected_tiles_str.split(",") if detected_tiles_str else []
        detected_pretty = [{"type":"keep","num":t[0],"short":t} for t in detected_tiles if t]

        if new_image and new_image.filename:
            try:
                with open(saved_path, "rb") as f:
                    image_data = base64.b64encode(f.read()).decode("utf-8")
                response = requests.post(
                    "https://detect.roboflow.com/mahjong-baq4s-m192l/1?api_key=dc4irmHEIZ2kRioxALz2",
                    data=image_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    verify=False
                )
                ai_result = response.json()
            except Exception as e:
                ai_result = {"error": str(e)}

            class_map = {
                "1C":("man","1"),"2C":("man","2"),"3C":("man","3"),
                "4C":("man","4"),"5C":("man","5"),"6C":("man","6"),
                "7C":("man","7"),"8C":("man","8"),"9C":("man","9"),
                "1D":("pin","1"),"2D":("pin","2"),"3D":("pin","3"),
                "4D":("pin","4"),"5D":("pin","5"),"6D":("pin","6"),
                "7D":("pin","7"),"8D":("pin","8"),"9D":("pin","9"),
                "1B":("sou","1"),"2B":("sou","2"),"3B":("sou","3"),
                "4B":("sou","4"),"5B":("sou","5"),"6B":("sou","6"),
                "7B":("sou","7"),"8B":("sou","8"),"9B":("sou","9"),
                "EW":("honors","1"),"SW":("honors","2"),
                "WW":("honors","3"),"NW":("honors","4"),
                "WD":("honors","5"),"GD":("honors","6"),"RD":("honors","7"),
            }

            if ai_result and "predictions" in ai_result:
                preds_sorted = sorted(ai_result["predictions"], key=lambda p: p["x"])
                for p in preds_sorted:
                    cls = p["class"]
                    if cls in class_map:
                        kind, num = class_map[cls]
                        short = f"{num}{ {'man':'m','pin':'p','sou':'s','honors':'z'}[kind] }"
                        detected_tiles.append(short)
                        detected_pretty.append({"type":kind,"num":num,"short":short})

        manual_tiles = request.form.getlist("manual_tile")
        for t in manual_tiles:
            if t:
                detected_tiles.append(t)
                detected_pretty.append({"type":"manual","num":t[0],"short":t})

        if len(detected_tiles) < 14:
            need_more = 14 - len(detected_tiles)
            return render_template(
                "score.html",
                need_more=need_more,
                detected=detected_pretty,
                ai_tiles=ai_result,
                image_url=image_url,
                saved_path=saved_path,
                detected_tiles_str=",".join(detected_tiles),
                nickname=session.get("nickname", ""),
            )

        win_tile_choice = request.form.get("win_tile", "").strip()
        if not win_tile_choice:
            return render_template(
                "score.html",
                pick_win_tile=True,
                detected=detected_pretty,
                ai_tiles=ai_result,
                image_url=image_url,
                saved_path=saved_path,
                tiles_14=detected_tiles[:14],
                detected_tiles_str=",".join(detected_tiles),
                nickname=session.get("nickname", ""),
            )

        def sort_mahjong_tiles(tiles):
            order = {"m":0, "p":1, "s":2, "z":3}
            return sorted(
                tiles,
                key=lambda t: (order.get(t[1], 9), int(t[0]))
            )

        detected_tiles = sort_mahjong_tiles(detected_tiles)

        tiles_man = tiles_pin = tiles_sou = tiles_honors = ""
        for tile in detected_tiles[:14]:
            num, kind = tile[0], tile[1]
            if kind == "m": tiles_man += num
            elif kind == "p": tiles_pin += num
            elif kind == "s": tiles_sou += num
            elif kind == "z": tiles_honors += num

        num, kind = win_tile_choice[0], win_tile_choice[1]
        win_tile = TilesConverter.string_to_136_array(**{
            "man": num if kind=="m" else "",
            "pin": num if kind=="p" else "",
            "sou": num if kind=="s" else "",
            "honors": num if kind=="z" else "",
        })[0]

        from mahjong.meld import Meld

        melds = []
        meld_count = int(request.form.get("meld_count", "0") or 0)

        for i in range(meld_count):
            m_type = request.form.get(f"meld_{i}_type")
            m_tiles_str = request.form.get(f"meld_{i}_tiles", "").strip()

            if not m_type or not m_tiles_str:
                continue

            m_tiles = m_tiles_str.split(",")
            tiles_136 = []

            for tile in m_tiles:
                num, kind = tile[0], tile[1]
                tiles_136.extend(
                    TilesConverter.string_to_136_array(**{
                        "man": num if kind == "m" else "",
                        "pin": num if kind == "p" else "",
                        "sou": num if kind == "s" else "",
                        "honors": num if kind == "z" else "",
                    })
                )

            if m_type == "pon":
                melds.append(Meld(meld_type=Meld.PON, tiles=tiles_136))
            elif m_type == "chi":
                melds.append(Meld(meld_type=Meld.CHI, tiles=tiles_136))
            elif m_type == "kan_open":
                melds.append(Meld(meld_type=Meld.KAN, tiles=tiles_136, opened=True))
            elif m_type == "kan_closed":
                melds.append(Meld(meld_type=Meld.KAN, tiles=tiles_136, opened=False))

        is_riichi = request.form.get("is_riichi") == "on"
        is_ippatsu = request.form.get("is_ippatsu") == "on"
        is_chankan = request.form.get("is_chankan") == "on"
        is_haitei = request.form.get("is_haitei") == "on"
        is_houtei = request.form.get("is_houtei") == "on"
        is_rinshan = request.form.get("is_rinshan") == "on"
        is_double_riichi = request.form.get("is_double_riichi") == "on"

        dora_count = int(request.form.get("dora_count", "0") or 0)
        player_wind_str = request.form.get("player_wind", "1z")
        round_wind_str = request.form.get("round_wind", "1z")

        WIND_MAP = {"1z": 27, "2z": 28, "3z": 29, "4z": 30}
        player_wind = WIND_MAP.get(player_wind_str, 27)
        round_wind = WIND_MAP.get(round_wind_str, 27)

        calculator = HandCalculator()
        tiles = TilesConverter.string_to_136_array(
            man=tiles_man, pin=tiles_pin, sou=tiles_sou, honors=tiles_honors
        )

        calc_tsumo = calculator.estimate_hand_value(
            tiles, win_tile, melds=melds,
            config=HandConfig(
                is_tsumo=True, is_riichi=is_riichi, is_ippatsu=is_ippatsu,
                is_chankan=is_chankan, is_haitei=is_haitei, is_houtei=is_houtei,
                is_rinshan=is_rinshan, is_daburu_riichi=is_double_riichi,
                player_wind=player_wind, round_wind=round_wind
            )
        )

        calc_ron = calculator.estimate_hand_value(
            tiles, win_tile, melds=melds,
            config=HandConfig(
                is_tsumo=False, is_riichi=is_riichi, is_ippatsu=is_ippatsu,
                is_chankan=is_chankan, is_haitei=is_haitei, is_houtei=is_houtei,
                is_rinshan=is_rinshan, is_daburu_riichi=is_double_riichi,
                player_wind=player_wind, round_wind=round_wind
            )
        )

        YAKU_JA = {
            "Riichi": "立直","Daburu Riichi": "ダブル立直","Ippatsu": "一発",
            "Tsumo": "ツモ","Menzen Tsumo": "門前清自摸和","Pinfu": "平和",
            "Iipeiko": "一盃口","Haitei Raoyue": "海底摸月","Houtei Raoyui": "河底撈魚",
            "Rinshan Kaihou": "嶺上開花","Chankan": "槍槓","Tanyao": "断幺九",
            "Yakuhai (Haku)": "役牌 白","Yakuhai (Hatsu)": "役牌 發","Yakuhai (Chun)": "役牌 中",
            "Yakuhai (Place Wind)": "場風","Yakuhai (Round Wind)": "自風",
            "Sanshoku Doujun": "三色同順","Ittsu": "一気通貫","Chanta": "全帯幺",
            "Honroutou": "混老頭","Toitoi": "対々和","Sanshoku Doukou": "三色同刻",
            "Sanankou": "三暗刻","Sankantsu": "三槓子","Shousangen": "小三元",
            "Honitsu": "混一色","Junchan": "純全帯幺","Ryanpeikou": "二盃口",
            "Chinitsu": "清一色","Kokushi Musou": "国士無双","Chiitoitsu": "七対子",
            "Suuankou": "四暗刻","Suuankou Tanki": "四暗刻単騎","Daisangen": "大三元",
            "Shousuushii": "小四喜","Daisuushii": "大四喜","Tsuuiisou": "字一色",
            "Ryuuiisou": "緑一色","Chinroutou": "清老頭","Suukantsu": "四槓子",
            "Chuuren Pouto": "九蓮宝燈","Junsei Chuuren Pouto": "純正九蓮宝燈",
            "Tenhou": "天和","Chiihou": "地和","Renhou": "人和",
        }

        def yaku_to_japanese(yaku_list):
            return [YAKU_JA.get(str(y), str(y)) for y in yaku_list]

        def build_yaku_with_dora(calc, dora_count):
            if not calc.yaku:
                return "なし"
            yaku_list = yaku_to_japanese(calc.yaku)
            if dora_count and dora_count > 0:
                yaku_list.append(f"ドラ{dora_count}")
            return yaku_list

        yaku_tsumo = build_yaku_with_dora(calc_tsumo, dora_count)
        yaku_ron = build_yaku_with_dora(calc_ron, dora_count)

        if calc_tsumo.han is not None:
            calc_tsumo.han += dora_count
        if calc_ron.han is not None:
            calc_ron.han += dora_count

        if calc_tsumo.cost:
            main = calc_tsumo.cost["main"]
            additional = calc_tsumo.cost["additional"]
            child_main = main
            child_add = additional
            child_total = main + additional * 2
            dealer_each = main
            dealer_total = main * 3
        else:
            child_main = child_add = child_total = "計算不可"
            dealer_each = dealer_total = "計算不可"

        RON_CHILD = {
            1: {30:1000, 40:1300, 50:1600, 60:2000, 70:2300},
            2: {20:1300, 25:1600, 30:2000, 40:2600, 50:3200, 60:3900, 70:4500},
            3: {20:2600, 25:3200, 30:3900, 40:5200, 50:6400, 60:7700, 70:"満貫"},
            4: {20:5200, 25:6400, 30:7700, 40:"満貫", 50:"満貫", 60:"満貫", 70:"満貫"},
        }
        RON_DEALER = {
            1: {30:1500, 40:2000, 50:2400, 60:2900, 70:3400},
            2: {20:2000, 25:2400, 30:2900, 40:3900, 50:4800, 60:5800, 70:6800},
            3: {20:3900, 25:4800, 30:5800, 40:7700, 50:9600, 60:11600, 70:"満貫"},
            4: {20:7700, 25:9600, 30:11600, 40:"満貫", 50:"満貫", 60:"満貫", 70:"満貫"},
        }

        if calc_ron.cost:
            han = calc_ron.han
            fu = calc_ron.fu
            if han and han >= 5:
                ron_child = calc_ron.cost["main"]
                ron_dealer = ron_child * 6 // 4
            else:
                ron_child = RON_CHILD.get(han, {}).get(fu, "計算不可")
                ron_dealer = RON_DEALER.get(han, {}).get(fu, "計算不可")
        else:
            ron_child = "計算不可"
            ron_dealer = "計算不可"

        result = {
            "yaku_tsumo": yaku_tsumo, "han_tsumo": calc_tsumo.han or "なし", "fu_tsumo": calc_tsumo.fu or "なし",
            "yaku_ron": yaku_ron, "han_ron": calc_ron.han or "なし", "fu_ron": calc_ron.fu or "なし",
            "child_main": child_main, "child_add": child_add, "child_total": child_total,
            "dealer_each": dealer_each, "dealer_total": dealer_total,
            "ron_child": ron_child, "ron_dealer": ron_dealer,
            "tiles_used": detected_tiles[:14], "ai_tiles": ai_result, "win_tile": win_tile_choice,
        }

    return render_template(
        "score.html",
        result=result,
        need_more=need_more,
        detected=detected_pretty,
        ai_tiles=ai_result,
        image_url=image_url,
        saved_path=saved_path,
        nickname=session.get("nickname", ""),
        pick_win_tile=pick_win_tile,
    )


# ============================================
# その他既存機能
# ============================================

@app.route("/test-ai")
def test_ai():
    try:
        with open("test.png", "rb") as image_file:
            image_data = base64.b64encode(image_file.read()).decode("utf-8")

        response = requests.post(
            "https://detect.roboflow.com/mahjong-baq4s/83?api_key=dc4irMHEIzzkRioxALzZ",
            data=image_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        return jsonify(response.json())
    except Exception as e:
        return str(e)


@app.route("/db-test")
def db_test():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT DATABASE() AS db, NOW() AS nowtime")
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return jsonify({"status": "success","database": row["db"],"time": str(row["nowtime"])})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":
        new_nickname = request.form.get("nickname", "").strip()
        new_bio = request.form.get("bio", "").strip()

        if not new_nickname:
            flash("ニックネームを入力してください")
            cursor.close()
            conn.close()
            return redirect(url_for("profile"))

        cursor.execute(
            "UPDATE users SET nickname=%s, bio=%s WHERE id=%s",
            (new_nickname, new_bio, user_id)
        )
        conn.commit()
        session["nickname"] = new_nickname
        flash("プロフィールを更新しました")
        cursor.close()
        conn.close()
        return redirect(url_for("profile"))

    cursor.execute(
        "SELECT id, employee_number, nickname, bio, created_at FROM users WHERE id=%s",
        (user_id,)
    )
    user = cursor.fetchone()

    cursor.execute(
        "SELECT rating, games, win, lose FROM user_ratings WHERE user_id=%s",
        (user_id,)
    )
    rating_row = cursor.fetchone()

    rating_info = {
        "rating": 1500, "games": 0, "win": 0, "lose": 0,
        "win_rate": 0, "rank": None, "total_users": 0,
    }
    if rating_row:
        rating_info["rating"] = int(rating_row["rating"])
        rating_info["games"] = int(rating_row["games"])
        rating_info["win"]   = int(rating_row["win"])
        rating_info["lose"]  = int(rating_row["lose"])
        if rating_info["games"] > 0:
            rating_info["win_rate"] = round(rating_info["win"] / rating_info["games"] * 100)

    cursor.execute("""
        SELECT user_id FROM user_ratings
        WHERE games > 0
        ORDER BY rating DESC
    """)
    rows = cursor.fetchall()
    rating_info["total_users"] = len(rows)
    for idx, r in enumerate(rows, start=1):
        if r["user_id"] == user_id:
            rating_info["rank"] = idx
            break

    cursor.close()
    conn.close()

    return render_template(
        "profile.html",
        user=user,
        nickname=session.get("nickname"),
        rating_info=rating_info,
    )


@app.route("/admin/audit")
def admin_audit():
    if session.get("user_id") != 1:  # 一旦IDで管理者判定
        return "権限がありません", 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.*, u.nickname
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
        LIMIT 200
    """)
    logs = cursor.fetchall()
    cursor.close(); conn.close()
    return render_template("admin_audit.html", logs=logs)

# ============================================
# 起動
# ============================================

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 5000))
    app.run(host="0.0.0.0", port=port)
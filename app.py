import os
import base64
import hashlib
from datetime import date

import pymysql
import requests
from dotenv import load_dotenv

from flask import (
    Flask, jsonify, render_template, request,
    redirect, url_for, session, flash
)
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

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


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# ============================================
# 共通ページ
# ============================================

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("menu"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        emp_num = request.form.get("employee_number", "")
        password = request.form.get("password", "")
        pw_hash = hash_password(password)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE employee_number=%s AND password_hash=%s",
            (emp_num, pw_hash)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["nickname"] = user["nickname"]
            return redirect(url_for("menu"))
        else:
            error = "社員番号またはパスワードが正しくありません"

    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        nickname = request.form.get("nickname", "")
        emp_num = request.form.get("employee_number", "")
        password = request.form.get("password", "")
        pw_hash = hash_password(password)

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (employee_number, password_hash, nickname) VALUES (%s, %s, %s)",
                (emp_num, pw_hash, nickname)
            )
            conn.commit()
            cursor.close()
            conn.close()
            flash("登録完了しました。ログインしてください。")
            return redirect(url_for("login"))
        except pymysql.err.IntegrityError:
            error = "その社員番号は既に登録されています"
            cursor.close()
            conn.close()

    return render_template("register.html", error=error)


@app.route("/menu")
def menu():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("menu.html", nickname=session.get("nickname"))


@app.route("/logout")
def logout():
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

        return jsonify({"status": "success", "message": "保存しました"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ============================================
# グループ機能
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
# マッチング機能
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
# 点数計算機能（mahjong）
# ============================================

@app.route("/score", methods=["GET", "POST"])
def score():
    result = None
    need_more = None
    detected_pretty = []
    image_url = None
    saved_path = None
    ai_result = None

    if request.method == "POST":
        # ===========================================
        # 画像の保持
        # ===========================================
        new_image = request.files.get("image")
        prev_path = request.form.get("saved_path", "").strip()

        if new_image and new_image.filename:
            os.makedirs("static/uploads", exist_ok=True)
            saved_path = "static/uploads/" + secure_filename(new_image.filename)
            new_image.save(saved_path)
        elif prev_path:
            saved_path = prev_path
        else:
            return render_template(
                "score.html",
                error="ファイルを選択してください"
            )

        image_url = "/" + saved_path

        # ===========================================
        # Roboflow に画像送信
        # ===========================================
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

        # ===========================================
        # Roboflow → mahjong に変換
        # ===========================================
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

        detected_tiles = []
        if ai_result and "predictions" in ai_result:
            preds_sorted = sorted(ai_result["predictions"], key=lambda p: p["x"])
            for p in preds_sorted:
                cls = p["class"]
                if cls in class_map:
                    kind, num = class_map[cls]
                    short = f"{num}{ {'man':'m','pin':'p','sou':'s','honors':'z'}[kind] }"
                    detected_tiles.append(short)
                    detected_pretty.append({
                        "type": kind,
                        "num": num,
                        "short": short,
                    })

        # ===========================================
        # 手動補完
        # ===========================================
        manual_tiles = request.form.getlist("manual_tile")
        for t in manual_tiles:
            if t:
                detected_tiles.append(t)
                detected_pretty.append({
                    "type": "manual",
                    "num": t[0],
                    "short": t,
                })

        # ===========================================
        # 14枚未満 → 補完UIへ
        # ===========================================
        if len(detected_tiles) < 14:
            need_more = 14 - len(detected_tiles)
            return render_template(
                "score.html",
                need_more=need_more,
                detected=detected_pretty,
                ai_tiles=ai_result,
                image_url=image_url,
                saved_path=saved_path,
            )

        # ===========================================
        # 14枚そろった → mahjong に渡す手牌を作る
        # ===========================================
        tiles_man = ""
        tiles_pin = ""
        tiles_sou = ""
        tiles_honors = ""

        for tile in detected_tiles[:14]:
            num = tile[0]
            kind = tile[1]
            if kind == "m":
                tiles_man += num
            elif kind == "p":
                tiles_pin += num
            elif kind == "s":
                tiles_sou += num
            elif kind == "z":
                tiles_honors += num

        # ===========================================
        # mahjong 1.4.0 による点数計算
        # ===========================================
        calculator = HandCalculator()
        tiles = TilesConverter.string_to_136_array(
            man=tiles_man,
            pin=tiles_pin,
            sou=tiles_sou,
            honors=tiles_honors,
        )

        if tiles_man:
            win_tile = TilesConverter.string_to_136_array(man=tiles_man[-1])[0]
        elif tiles_pin:
            win_tile = TilesConverter.string_to_136_array(pin=tiles_pin[-1])[0]
        elif tiles_sou:
            win_tile = TilesConverter.string_to_136_array(sou=tiles_sou[-1])[0]
        else:
            win_tile = TilesConverter.string_to_136_array(honors=tiles_honors[-1])[0]

        # ツモ
        calc_tsumo = calculator.estimate_hand_value(tiles, win_tile, config=HandConfig(is_tsumo=True))

        # ロン
        calc_ron = calculator.estimate_hand_value(tiles, win_tile, config=HandConfig(is_tsumo=False))

        # ===========================================
        # 点数の計算（独自）
        # ===========================================
        if calc_tsumo.cost:
            main = calc_tsumo.cost["main"]
            additional = calc_tsumo.cost["additional"]
            child_main = main
            child_add = additional
            child_total = main + additional * 2
            dealer_each = main * 2
            dealer_total = main * 6
        else:
            child_main = child_add = child_total = "計算不可"
            dealer_each = dealer_total = "計算不可"

        if calc_ron.cost:
            ron_main = calc_ron.cost["main"]
            ron_child = ron_main * 4
            ron_dealer = ron_main * 6
        else:
            ron_main = "計算不可"
            ron_child = "計算不可"
            ron_dealer = "計算不可"

        # ===========================================
        # 結果まとめ
        # ===========================================
        result = {
            "yaku_tsumo": [str(y) for y in calc_tsumo.yaku] if calc_tsumo.yaku else "なし",
            "han_tsumo": calc_tsumo.han or "なし",
            "fu_tsumo": calc_tsumo.fu or "なし",

            "yaku_ron": [str(y) for y in calc_ron.yaku] if calc_ron.yaku else "なし",
            "han_ron": calc_ron.han or "なし",
            "fu_ron": calc_ron.fu or "なし",

            "child_main": child_main,
            "child_add": child_add,
            "child_total": child_total,
            "dealer_each": dealer_each,
            "dealer_total": dealer_total,

            "ron_child": ron_child,
            "ron_dealer": ron_dealer,

            "tiles_used": detected_tiles[:14],
            "ai_tiles": ai_result,
        }

    return render_template(
        "score.html",
        result=result,
        need_more=need_more,
        detected=detected_pretty,
        ai_tiles=ai_result,
        image_url=image_url,
        saved_path=saved_path,
        nickname=session.get("nickname", "")
    )
# ============================================
# AIテスト
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


# ============================================
# DB接続テスト
# ============================================

@app.route("/db-test")
def db_test():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT DATABASE() AS db, NOW() AS nowtime")
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return jsonify({
            "status": "success",
            "database": row["db"],
            "time": str(row["nowtime"]),
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ============================================
# 起動
# ============================================

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 5000))
    app.run(host="0.0.0.0", port=port)
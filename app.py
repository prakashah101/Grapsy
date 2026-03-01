from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import random, sqlite3, time, os, uuid, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or "fallback-dev-secret-change-me-please"

MAIL_USERNAME       = os.getenv("MAIL_USERNAME")
MAIL_APP_PASSWORD   = os.getenv("MAIL_APP_PASSWORD")
MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER") or MAIL_USERNAME

UPLOAD_FOLDER  = os.path.join("static", "uploads")
ALLOWED_IMAGES = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_VIDEOS = {"mp4", "mov", "webm"}
app.config["UPLOAD_FOLDER"]       = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"]  = 50 * 1024 * 1024  # 50 MB
os.makedirs(os.path.join(UPLOAD_FOLDER, "profile_pics"), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, "posts"),        exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, "reels"),        exist_ok=True)

otp_store = {}

# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        # Migrate existing users.db — safely add new columns if missing
        for col, typedef in [('bio','TEXT DEFAULT ""'), ('profile_pic','TEXT DEFAULT NULL')]:
            try:
                conn.execute(f'ALTER TABLE users ADD COLUMN {col} {typedef}')
                conn.commit()
            except Exception:
                pass
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                password    TEXT NOT NULL,
                name        TEXT NOT NULL,
                email       TEXT UNIQUE NOT NULL,
                country     TEXT NOT NULL,
                phone       TEXT NOT NULL,
                bio         TEXT DEFAULT '',
                profile_pic TEXT DEFAULT NULL,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS posts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                caption    TEXT DEFAULT '',
                media_file TEXT NOT NULL,
                media_type TEXT NOT NULL DEFAULT 'image',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS reels (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                caption    TEXT DEFAULT '',
                video_file TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS likes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                post_id    INTEGER,
                reel_id    INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, post_id),
                UNIQUE(user_id, reel_id)
            );
            CREATE TABLE IF NOT EXISTS comments (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                post_id    INTEGER,
                reel_id    INTEGER,
                body       TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS follows (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                follower_id  INTEGER NOT NULL,
                following_id INTEGER NOT NULL,
                created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(follower_id, following_id)
            );
            CREATE TABLE IF NOT EXISTS stories (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                media_file TEXT NOT NULL,
                media_type TEXT NOT NULL DEFAULT 'image',
                caption    TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id   INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                body        TEXT NOT NULL,
                is_read     INTEGER DEFAULT 0,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id)   REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            );
        ''')
        conn.commit()

init_db()

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def allowed_file(filename, types):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in types

def save_file(file, subfolder):
    ext      = file.filename.rsplit(".", 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    file.save(os.path.join(UPLOAD_FOLDER, subfolder, filename))
    return filename

def get_user(username):
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

def get_user_by_id(uid):
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def pic_url(user):
    if user and user["profile_pic"]:
        return url_for("static", filename=f"uploads/profile_pics/{user['profile_pic']}")
    return url_for("static", filename="logo.png")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            flash("Please login first!", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def send_otp_email(recipient_email, otp):
    if not all([MAIL_USERNAME, MAIL_APP_PASSWORD]):
        return False
    try:
        msg = MIMEMultipart()
        msg["From"] = MAIL_DEFAULT_SENDER
        msg["To"]   = recipient_email
        msg["Subject"] = "Your Grapsy OTP"
        msg.attach(MIMEText(f"Your OTP: {otp}\n\nValid for 5 minutes.", "plain"))
        s = smtplib.SMTP("smtp.gmail.com", 587)
        s.starttls(); s.login(MAIL_USERNAME, MAIL_APP_PASSWORD)
        s.send_message(msg); s.quit()
        return True
    except Exception as e:
        flash(f"Email error: {e}", "error")
        return False

# ─────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────
@app.route("/signup", methods=["GET","POST"])
def signup():
    countries = ["Nepal","India","United States","United Kingdom","Canada",
                 "Australia","Germany","France","Japan","China","Brazil","Other"]
    if request.method == "POST":
        name     = request.form.get("name","").strip()
        username = request.form.get("username","").strip()
        email    = request.form.get("email","").strip().lower()
        country  = request.form.get("country","").strip()
        phone    = request.form.get("phone","").strip()
        password = request.form.get("password","").strip()
        if not all([name, username, email, country, phone, password]):
            flash("All fields are required.", "error")
            return render_template("signup.html", countries=countries)
        if "@" not in email:
            flash("Invalid email.", "error")
            return render_template("signup.html", countries=countries)
        if not phone.isdigit() or not (7 <= len(phone) <= 15):
            flash("Phone must be 7–15 digits.", "error")
            return render_template("signup.html", countries=countries)
        otp = random.randint(100000, 999999)
        otp_store[email] = {"otp": otp, "created": time.time()}
        session["signup_data"] = dict(name=name, username=username, email=email,
                                      country=country, phone=phone, password=password)
        if send_otp_email(email, otp):
            flash(f"OTP sent to {email}.", "success")
        else:
            flash("Failed to send OTP.", "error")
            otp_store.pop(email, None)
            return render_template("signup.html", countries=countries)
        return redirect(url_for("verify_otp"))
    return render_template("signup.html", countries=countries)


@app.route("/verify_otp", methods=["GET","POST"])
def verify_otp():
    if "signup_data" not in session:
        return redirect(url_for("signup"))
    d, email = session["signup_data"], session["signup_data"]["email"]
    if request.method == "POST":
        entered = request.form.get("otp","").strip()
        stored  = otp_store.get(email)
        if not stored:
            flash("No OTP found.", "error")
            return redirect(url_for("verify_otp"))
        if time.time() - stored["created"] > 300:
            flash("OTP expired.", "error")
            otp_store.pop(email, None); session.pop("signup_data", None)
            return redirect(url_for("signup"))
        if str(stored["otp"]) == entered:
            hpw = generate_password_hash(d["password"], method="pbkdf2:sha256:600000")
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO users (username,password,name,email,country,phone) VALUES (?,?,?,?,?,?)",
                        (d["username"], hpw, d["name"], d["email"], d["country"], d["phone"])
                    )
                    conn.commit()
                flash("Account created! Login now.", "success")
            except sqlite3.IntegrityError:
                flash("Username or email already taken.", "error")
                return render_template("verify_otp.html")
            otp_store.pop(email, None); session.pop("signup_data", None)
            return redirect(url_for("login"))
        flash("Incorrect OTP.", "error")
    return render_template("verify_otp.html")


@app.route("/resend_otp", methods=["POST"])
def resend_otp():
    if "signup_data" not in session:
        return redirect(url_for("signup"))
    email     = session["signup_data"]["email"]
    last_sent = otp_store.get(email, {}).get("created")
    if last_sent and time.time() - last_sent < 30:
        flash("Wait 30 seconds.", "warning"); return redirect(url_for("verify_otp"))
    new_otp = random.randint(100000, 999999)
    otp_store[email] = {"otp": new_otp, "created": time.time()}
    send_otp_email(email, new_otp)
    flash("New OTP sent.", "success")
    return redirect(url_for("verify_otp"))


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        user = get_user(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            return redirect(url_for("home"))
        flash("Invalid credentials.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# Home / Feed
# ─────────────────────────────────────────────
@app.route("/")
@login_required
def home():
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    with get_db() as conn:
        posts = conn.execute('''
            SELECT p.*, u.username, u.profile_pic,
                   (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS like_count,
                   (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comment_count,
                   (SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) AS i_liked
            FROM posts p JOIN users u ON u.id=p.user_id
            WHERE p.user_id=? OR p.user_id IN (SELECT following_id FROM follows WHERE follower_id=?)
            ORDER BY p.created_at DESC LIMIT 30
        ''', (me["id"], me["id"], me["id"])).fetchall()

        stories = conn.execute('''
            SELECT DISTINCT u.id, u.username, u.profile_pic
            FROM stories s JOIN users u ON u.id=s.user_id
            WHERE s.user_id IN (SELECT following_id FROM follows WHERE follower_id=?)
              AND s.created_at >= datetime('now','-1 day')
        ''', (me["id"],)).fetchall()

        suggested = conn.execute('''
            SELECT u.* FROM users u
            WHERE u.id!=? AND u.id NOT IN (SELECT following_id FROM follows WHERE follower_id=?)
            ORDER BY RANDOM() LIMIT 5
        ''', (me["id"], me["id"])).fetchall()

        unread_count = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE receiver_id=? AND is_read=0", (me["id"],)
        ).fetchone()[0]

    return render_template("home.html", me=me, posts=posts, stories=stories,
                           suggested=suggested, pic_url=pic_url, unread_count=unread_count)


# ─────────────────────────────────────────────
# Posts
# ─────────────────────────────────────────────
@app.route("/post/create", methods=["GET","POST"])
@login_required
def create_post():
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        caption = request.form.get("caption","").strip()
        f = request.files.get("media")
        if not f or f.filename == "":
            flash("Select a photo or video.", "error")
            return render_template("create_post.html", me=me, pic_url=pic_url)
        ext = f.filename.rsplit(".",1)[-1].lower()
        if ext in ALLOWED_VIDEOS:
            media_type = "video"
        elif ext in ALLOWED_IMAGES:
            media_type = "image"
        else:
            flash("Unsupported file type.", "error")
            return render_template("create_post.html", me=me, pic_url=pic_url)
        filename = save_file(f, "posts")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO posts (user_id,caption,media_file,media_type) VALUES (?,?,?,?)",
                (me["id"], caption, filename, media_type)
            )
            conn.commit()
        flash("Post shared!", "success")
        return redirect(url_for("home"))
    return render_template("create_post.html", me=me, pic_url=pic_url)


@app.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    with get_db() as conn:
        post = conn.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
        if post and post["user_id"] == me["id"]:
            fpath = os.path.join(UPLOAD_FOLDER, "posts", post["media_file"])
            if os.path.exists(fpath): os.remove(fpath)
            conn.execute("DELETE FROM posts WHERE id=?", (post_id,))
            conn.execute("DELETE FROM likes WHERE post_id=?", (post_id,))
            conn.execute("DELETE FROM comments WHERE post_id=?", (post_id,))
            conn.commit()
    return redirect(url_for("home"))


# ─────────────────────────────────────────────
# Reels
# ─────────────────────────────────────────────
@app.route("/reels")
@login_required
def reels():
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    with get_db() as conn:
        reels_list = conn.execute('''
            SELECT r.*, u.username, u.profile_pic,
                   (SELECT COUNT(*) FROM likes l WHERE l.reel_id=r.id) AS like_count,
                   (SELECT 1 FROM likes l WHERE l.reel_id=r.id AND l.user_id=?) AS i_liked,
                   (SELECT 1 FROM follows f WHERE f.follower_id=? AND f.following_id=r.user_id) AS i_follow
            FROM reels r JOIN users u ON u.id=r.user_id
            ORDER BY r.created_at DESC
        ''', (me["id"], me["id"])).fetchall()
        unread_count = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE receiver_id=? AND is_read=0", (me["id"],)
        ).fetchone()[0]
    return render_template("reels.html", me=me, reels=reels_list, pic_url=pic_url, unread_count=unread_count)


@app.route("/reel/create", methods=["GET","POST"])
@login_required
def create_reel():
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        caption = request.form.get("caption","").strip()
        f = request.files.get("video")
        if not f or not allowed_file(f.filename, ALLOWED_VIDEOS):
            flash("Upload a valid video (mp4/mov/webm).", "error")
            return render_template("create_reel.html", me=me, pic_url=pic_url)
        filename = save_file(f, "reels")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO reels (user_id,caption,video_file) VALUES (?,?,?)",
                (me["id"], caption, filename)
            )
            conn.commit()
        flash("Reel uploaded!", "success")
        return redirect(url_for("reels"))
    return render_template("create_reel.html", me=me, pic_url=pic_url)


# ─────────────────────────────────────────────
# Likes
# ─────────────────────────────────────────────
@app.route("/like/post/<int:post_id>", methods=["POST"])
@login_required
def like_post(post_id):
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    with get_db() as conn:
        ex = conn.execute("SELECT id FROM likes WHERE user_id=? AND post_id=?", (me["id"], post_id)).fetchone()
        if ex:
            conn.execute("DELETE FROM likes WHERE user_id=? AND post_id=?", (me["id"], post_id)); liked = False
        else:
            conn.execute("INSERT INTO likes (user_id,post_id) VALUES (?,?)", (me["id"], post_id)); liked = True
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM likes WHERE post_id=?", (post_id,)).fetchone()[0]
    return jsonify({"liked": liked, "count": count})


@app.route("/like/reel/<int:reel_id>", methods=["POST"])
@login_required
def like_reel(reel_id):
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    with get_db() as conn:
        ex = conn.execute("SELECT id FROM likes WHERE user_id=? AND reel_id=?", (me["id"], reel_id)).fetchone()
        if ex:
            conn.execute("DELETE FROM likes WHERE user_id=? AND reel_id=?", (me["id"], reel_id)); liked = False
        else:
            conn.execute("INSERT INTO likes (user_id,reel_id) VALUES (?,?)", (me["id"], reel_id)); liked = True
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM likes WHERE reel_id=?", (reel_id,)).fetchone()[0]
    return jsonify({"liked": liked, "count": count})


# ─────────────────────────────────────────────
# Comments
# ─────────────────────────────────────────────
@app.route("/comment/post/<int:post_id>", methods=["POST"])
@login_required
def comment_post(post_id):
    me   = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    body = request.json.get("body","").strip()
    if not body: return jsonify({"error": "Empty"}), 400
    with get_db() as conn:
        conn.execute("INSERT INTO comments (user_id,post_id,body) VALUES (?,?,?)", (me["id"], post_id, body))
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM comments WHERE post_id=?", (post_id,)).fetchone()[0]
    return jsonify({"username": me["username"], "body": body, "count": count, "pic": pic_url(me)})


@app.route("/comments/post/<int:post_id>")
@login_required
def get_comments(post_id):
    with get_db() as conn:
        rows = conn.execute('''
            SELECT c.body, c.created_at, u.username, u.profile_pic
            FROM comments c JOIN users u ON u.id=c.user_id
            WHERE c.post_id=? ORDER BY c.created_at ASC
        ''', (post_id,)).fetchall()
    return jsonify([{"username": r["username"], "body": r["body"],
                     "pic": pic_url(r), "created_at": r["created_at"]} for r in rows])


# ─────────────────────────────────────────────
# Follow
# ─────────────────────────────────────────────
@app.route("/follow/<int:target_id>", methods=["POST"])
@login_required
def follow(target_id):
    me = get_user(session["username"])
    if me["id"] == target_id: return jsonify({"error": "Cannot follow yourself"}), 400
    with get_db() as conn:
        ex = conn.execute("SELECT id FROM follows WHERE follower_id=? AND following_id=?", (me["id"], target_id)).fetchone()
        if ex:
            conn.execute("DELETE FROM follows WHERE follower_id=? AND following_id=?", (me["id"], target_id)); following = False
        else:
            conn.execute("INSERT INTO follows (follower_id,following_id) VALUES (?,?)", (me["id"], target_id)); following = True
        conn.commit()
        fc = conn.execute("SELECT COUNT(*) FROM follows WHERE following_id=?", (target_id,)).fetchone()[0]
    return jsonify({"following": following, "followers_count": fc})



# ─────────────────────────────────────────────
# Stories
# ─────────────────────────────────────────────
@app.route("/story/create", methods=["GET","POST"])
@login_required
def create_story():
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired.", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        f = request.files.get("media")
        caption = request.form.get("caption","").strip()
        if not f or f.filename == "":
            flash("Please select a photo or video.", "error")
            return render_template("create_story.html", me=me, pic_url=pic_url)
        ext = f.filename.rsplit(".",1)[-1].lower()
        if ext in ALLOWED_VIDEOS:
            media_type = "video"
        elif ext in ALLOWED_IMAGES:
            media_type = "image"
        else:
            flash("Unsupported file type.", "error")
            return render_template("create_story.html", me=me, pic_url=pic_url)
        filename = save_file(f, "posts")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO stories (user_id,media_file,media_type,caption) VALUES (?,?,?,?)",
                (me["id"], filename, media_type, caption)
            )
            conn.commit()
        flash("Story shared! Disappears in 24h.", "success")
        return redirect(url_for("home"))
    return render_template("create_story.html", me=me, pic_url=pic_url)


@app.route("/story/view/<int:user_id>")
@login_required
def view_story(user_id):
    me = get_user(session["username"])
    if me is None:
        session.clear(); return redirect(url_for("login"))
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("home"))
    with get_db() as conn:
        stories = conn.execute(
            "SELECT * FROM stories WHERE user_id=? AND created_at >= datetime('now','-1 day') ORDER BY created_at ASC",
            (user_id,)
        ).fetchall()
        unread_count = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE receiver_id=? AND is_read=0", (me["id"],)
        ).fetchone()[0]
    if not stories:
        flash("No active stories.", "warning")
        return redirect(url_for("home"))
    return render_template("view_story.html", me=me, user=user, stories=stories,
                           pic_url=pic_url, unread_count=unread_count)

# ─────────────────────────────────────────────
# Profile
# ─────────────────────────────────────────────
@app.route("/profile/<username>")
@login_required
def profile(username):
    me   = get_user(session["username"])
    user = get_user(username)
    if not user:
        flash("User not found.", "error"); return redirect(url_for("home"))
    with get_db() as conn:
        posts = conn.execute('''
            SELECT p.*,
                   (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS like_count,
                   (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comment_count
            FROM posts p WHERE p.user_id=? ORDER BY p.created_at DESC
        ''', (user["id"],)).fetchall()
        followers     = conn.execute("SELECT COUNT(*) FROM follows WHERE following_id=?", (user["id"],)).fetchone()[0]
        following_cnt = conn.execute("SELECT COUNT(*) FROM follows WHERE follower_id=?",  (user["id"],)).fetchone()[0]
        i_follow      = conn.execute("SELECT 1 FROM follows WHERE follower_id=? AND following_id=?", (me["id"], user["id"])).fetchone()
        unread_count  = conn.execute("SELECT COUNT(*) FROM messages WHERE receiver_id=? AND is_read=0", (me["id"],)).fetchone()[0]
    return render_template("profile.html", me=me, user=user, posts=posts,
                           followers=followers, following_count=following_cnt,
                           i_follow=bool(i_follow), pic_url=pic_url, unread_count=unread_count)


@app.route("/profile/edit", methods=["GET","POST"])
@login_required
def edit_profile():
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        name    = request.form.get("name","").strip()
        bio     = request.form.get("bio","").strip()
        f       = request.files.get("profile_pic")
        new_pic = me["profile_pic"]
        if f and f.filename and allowed_file(f.filename, ALLOWED_IMAGES):
            if me["profile_pic"]:
                old = os.path.join(UPLOAD_FOLDER, "profile_pics", me["profile_pic"])
                if os.path.exists(old): os.remove(old)
            new_pic = save_file(f, "profile_pics")
        with get_db() as conn:
            conn.execute("UPDATE users SET name=?,bio=?,profile_pic=? WHERE username=?",
                         (name, bio, new_pic, session["username"]))
            conn.commit()
        flash("Profile updated!", "success")
        return redirect(url_for("profile", username=session["username"]))
    return render_template("edit_profile.html", me=me, pic_url=pic_url)


# ─────────────────────────────────────────────
# Search
# ─────────────────────────────────────────────
@app.route("/search")
@login_required
def search():
    me    = get_user(session["username"])
    query = request.args.get("q","").strip()
    users = []
    if query:
        with get_db() as conn:
            users = conn.execute('''
                SELECT u.*, (SELECT 1 FROM follows WHERE follower_id=? AND following_id=u.id) AS i_follow
                FROM users u WHERE (u.username LIKE ? OR u.name LIKE ?) AND u.id!=?
                LIMIT 20
            ''', (me["id"], f"%{query}%", f"%{query}%", me["id"])).fetchall()
    return render_template("search.html", me=me, users=users, query=query, pic_url=pic_url)


# ─────────────────────────────────────────────
# Messages
# ─────────────────────────────────────────────
@app.route("/messages")
@login_required
def messages():
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    with get_db() as conn:
        convos = conn.execute('''
            SELECT u.*,
                   (SELECT body FROM messages
                    WHERE (sender_id=me.id AND receiver_id=u.id) OR (sender_id=u.id AND receiver_id=me.id)
                    ORDER BY created_at DESC LIMIT 1) AS last_msg,
                   (SELECT created_at FROM messages
                    WHERE (sender_id=me.id AND receiver_id=u.id) OR (sender_id=u.id AND receiver_id=me.id)
                    ORDER BY created_at DESC LIMIT 1) AS last_time,
                   (SELECT COUNT(*) FROM messages WHERE sender_id=u.id AND receiver_id=me.id AND is_read=0) AS unread
            FROM users u, users me
            WHERE me.username=? AND u.id!=me.id
              AND u.id IN (
                SELECT CASE WHEN sender_id=me2.id THEN receiver_id ELSE sender_id END
                FROM messages, users me2 WHERE me2.username=?
                  AND (sender_id=me2.id OR receiver_id=me2.id)
              )
            ORDER BY last_time DESC
        ''', (session["username"], session["username"])).fetchall()
        unread_count = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE receiver_id=? AND is_read=0", (me["id"],)
        ).fetchone()[0]
    return render_template("messages.html", me=me, convos=convos, pic_url=pic_url, unread_count=unread_count)


@app.route("/messages/<int:other_id>")
@login_required
def chat(other_id):
    me    = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    other = get_user_by_id(other_id)
    if not other: return redirect(url_for("messages"))
    with get_db() as conn:
        msgs = conn.execute('''
            SELECT m.*, u.username, u.profile_pic
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)
            ORDER BY m.created_at ASC
        ''', (me["id"], other_id, other_id, me["id"])).fetchall()
        conn.execute("UPDATE messages SET is_read=1 WHERE sender_id=? AND receiver_id=? AND is_read=0",
                     (other_id, me["id"]))
        conn.commit()
        unread_count = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE receiver_id=? AND is_read=0", (me["id"],)
        ).fetchone()[0]
    return render_template("chat.html", me=me, other=other, msgs=msgs, pic_url=pic_url, unread_count=unread_count)


@app.route("/messages/send/<int:other_id>", methods=["POST"])
@login_required
def send_message(other_id):
    me   = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    body = request.json.get("body","").strip()
    if not body: return jsonify({"error": "Empty"}), 400
    with get_db() as conn:
        conn.execute("INSERT INTO messages (sender_id,receiver_id,body) VALUES (?,?,?)",
                     (me["id"], other_id, body))
        conn.commit()
    return jsonify({"status": "sent", "body": body, "username": me["username"], "pic": pic_url(me)})


@app.route("/messages/poll/<int:other_id>")
@login_required
def poll_messages(other_id):
    me    = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    since = request.args.get("since", "1970-01-01 00:00:00")
    with get_db() as conn:
        msgs = conn.execute('''
            SELECT m.*, u.username, u.profile_pic
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE ((m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?))
              AND m.created_at > ?
            ORDER BY m.created_at ASC
        ''', (me["id"], other_id, other_id, me["id"], since)).fetchall()
        conn.execute("UPDATE messages SET is_read=1 WHERE sender_id=? AND receiver_id=? AND is_read=0",
                     (other_id, me["id"]))
        conn.commit()
    return jsonify([{"id": m["id"], "body": m["body"], "username": m["username"],
                     "sender_id": m["sender_id"], "me_id": me["id"],
                     "pic": pic_url(m), "created_at": m["created_at"]} for m in msgs])
# ─────────────────────────────────────────────
# Profile pic upload (modal)
# ─────────────────────────────────────────────
@app.route("/upload_profile_pic", methods=["POST"])
@login_required
def upload_profile_pic():
    me = get_user(session["username"])
    if me is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    f  = request.files.get("profile_pic")
    if not f or not allowed_file(f.filename, ALLOWED_IMAGES):
        return jsonify({"success": False, "error": "Invalid file"}), 400
    if me["profile_pic"]:
        old = os.path.join(UPLOAD_FOLDER, "profile_pics", me["profile_pic"])
        if os.path.exists(old): os.remove(old)
    filename = save_file(f, "profile_pics")
    with get_db() as conn:
        conn.execute("UPDATE users SET profile_pic=? WHERE username=?", (filename, session["username"]))
        conn.commit()
    return jsonify({"success": True, "url": url_for("static", filename=f"uploads/profile_pics/{filename}")})


@app.route("/remove_profile_pic", methods=["POST"])
@login_required
def remove_profile_pic():
    me = get_user(session["username"])
    if me["profile_pic"]:
        old = os.path.join(UPLOAD_FOLDER, "profile_pics", me["profile_pic"])
        if os.path.exists(old): os.remove(old)
    with get_db() as conn:
        conn.execute("UPDATE users SET profile_pic=NULL WHERE username=?", (session["username"],))
        conn.commit()
    return jsonify({"success": True})



if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
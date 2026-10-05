import os
import time
import uuid
import re
import secrets
import sqlite3
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, jsonify, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask_wtf import CSRFProtect
from datetime import timedelta

# App & Upload Config

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["WTF_CSRF_ENABLED"] = True

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1GB

VIDEO_EXT = {".mp4", ".mov", ".m4v", ".webm", ".avi", ".mkv"}
DOC_EXT = {".pdf", ".doc", ".docx", ".txt", ".md", ".ppt", ".pptx"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

CATEGORIES = [
    "Computer Science", "Business", "Design", "Mathematics",
    "Information Security", "Other"
]
LEVELS = ["BEGINNER", "INTERMEDIATE", "ADVANCED"]

csrf = CSRFProtect(app)

# DB Init
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        content TEXT,
        instructor TEXT,
        image TEXT,
        category TEXT DEFAULT 'Other',
        level TEXT DEFAULT 'BEGINNER'
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS user_courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        course_id INTEGER,
        UNIQUE(user_id, course_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(course_id) REFERENCES courses(id)
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER,
        title TEXT,
        filename TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(course_id) REFERENCES courses(id)
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER,
        title TEXT,
        filename TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(course_id) REFERENCES courses(id)
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS course_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    completed INTEGER DEFAULT 0,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, course_id)
    )
    """)

    # Topic updates / announcements posted by the course instructor
    c.execute("""
    CREATE TABLE IF NOT EXISTS course_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER NOT NULL,
        author TEXT NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(course_id) REFERENCES courses(id)
    )
    """)

    # --- Migrations for databases created before these columns existed ---
    c.execute("PRAGMA table_info(courses)")
    columns = [col[1] for col in c.fetchall()]
    if "content" not in columns:
        c.execute("ALTER TABLE courses ADD COLUMN content TEXT")
    if "category" not in columns:
        c.execute("ALTER TABLE courses ADD COLUMN category TEXT DEFAULT 'Other'")
    if "level" not in columns:
        c.execute("ALTER TABLE courses ADD COLUMN level TEXT DEFAULT 'BEGINNER'")

    conn.commit()
    conn.close()


init_db()


# ----------------------------
# Helpers
# ----------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def allowed_file(filename, allowed):
    ext = os.path.splitext(filename)[1].lower()
    return ext in allowed


def unique_filename(filename):
    name, ext = os.path.splitext(secure_filename(filename))
    return f"{int(time.time())}_{uuid.uuid4().hex[:8]}_{name}{ext}"


def current_user():
    return session.get("user")


def login_required():
    """Redirect helper: returns a redirect response if not logged in, else None."""
    if "user" not in session:
        return redirect(url_for("login"))
    return None


def instructor_required():
    redir = login_required()
    if redir:
        return redir
    if session["user"]["role"] != "Instructor":
        flash("Only instructors can perform this action.", "error")
        return redirect(url_for("dashboard"))
    return None


# ----------------------------
# CSRF token access for templates
# ----------------------------
@app.template_global()
def csrf_token():
    from flask_wtf.csrf import generate_csrf
    return generate_csrf()


@app.template_global()
def now_iso():
    return datetime.now().strftime("%b %d, %Y")


CSRF_ERROR_MESSAGE = "The form you submitted has expired. Please try again."


@app.errorhandler(400)
def handle_csrf_400(e):
    desc = getattr(e, "description", "") or ""
    if "CSRF" in desc:
        flash(CSRF_ERROR_MESSAGE, "error")
        return redirect(request.referrer or url_for("main"))
    return e


# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def main():
    return render_template('index.html')


# ----- Signup -----
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        password_raw = request.form["password"]
        role = request.form.get("role")

        # Validation
        if not username:
            return render_template("signup.html", error="Username is required!")
        if not role:
            return render_template("signup.html", error="Please select an account type!")
        if len(password_raw) < 8:
            return render_template("signup.html", error="Password must be at least 8 characters long.")
        if len(password_raw) > 16:
            return render_template("signup.html", error="Password must be less than 16 characters")
        if not re.search(r"[A-Z]", password_raw):
            return render_template("signup.html", error="Password must contain an uppercase letter.")
        if not re.search(r"[a-z]", password_raw):
            return render_template("signup.html", error="Password must contain a lowercase letter.")
        if not re.search(r"[0-9]", password_raw):
            return render_template("signup.html", error="Password must have a number.")
        if not re.match(r"^[A-Za-z0-9_]+$", username):
            return render_template("signup.html", error="Username can only contain letters, numbers, and underscores.")

        hashed_password = generate_password_hash(password_raw)

        conn = get_db()
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, role)
            )
            conn.commit()

            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("signup.html", error="Username already exists!")
        finally:
            conn.close()

    return render_template("signup.html")


# ----- Login -----
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session.permanent = True
            session["user"] = {"id": user[0], "username": user[1], "role": user[3]}
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid username or password!")

    return render_template("login.html")


# ----- Logout -----
@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out.", "success")
    return redirect(url_for("login"))


# ----- Dashboard -----
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    user = session["user"]
    conn = get_db()
    c = conn.cursor()

    if user["role"] == "Instructor":
        c.execute("SELECT * FROM courses WHERE instructor=?", (user["username"],))
        created_courses = c.fetchall()

        total_courses = len(created_courses)

        c.execute("""
            SELECT COUNT(*)
            FROM user_courses
            JOIN courses ON user_courses.course_id = courses.id
            WHERE courses.instructor=?
        """, (user["username"],))
        total_students = c.fetchone()[0]

        conn.close()
        return render_template(
            "instructor_dashboard.html",
            user=user,
            created_courses=created_courses,
            total_courses=total_courses,
            total_students=total_students,
            categories=CATEGORIES,
            levels=LEVELS
        )

    # Student
    c.execute("""
        SELECT courses.* FROM courses
        JOIN user_courses ON courses.id = user_courses.course_id
        WHERE user_courses.user_id=?
    """, (user["id"],))
    enrolled_courses = c.fetchall()

    c.execute("""
        SELECT * FROM courses WHERE id NOT IN
        (SELECT course_id FROM user_courses WHERE user_id=?)
        ORDER BY id DESC
    """, (user["id"],))
    recommended = c.fetchall()

    progress = int(get_user_progress(user["id"]))

    conn.close()
    return render_template(
    "student_dashboard.html",
    user=user,
    enrolled_courses=enrolled_courses,
    recommended=recommended,
    enrolled_count=len(enrolled_courses),
    progress=progress,
    categories=CATEGORIES,
    levels=LEVELS
    )


# ----- Profile -----
@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("profile.html", user=session["user"])


# ----- Create Course (Instructor) -----
@app.route("/create_course", methods=["GET", "POST"])
def create_course():
    guard = instructor_required()
    if guard:
        return guard

    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form.get("description", "").strip()
        content = request.form.get("content", "").strip()
        category = request.form.get("category", "Other").strip() or "Other"
        level = request.form.get("level", "BEGINNER").strip().upper()
        if level not in LEVELS:
            level = "BEGINNER"
        instructor = session["user"]["username"]

        file = request.files.get("image")
        image_filename = None

        if file and file.filename != "":
            if allowed_file(file.filename, IMAGE_EXT):
                image_filename = unique_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], image_filename))
            else:
                flash("Unsupported image format.", "error")
                return redirect(request.url)

        conn = get_db()
        c = conn.cursor()

        c.execute(
            "INSERT INTO courses (title, description, instructor, image, content, category, level) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (title, description, instructor, image_filename, content, category, level)
        )
        conn.commit()
        conn.close()
        flash("Course created!", "success")
        return redirect(url_for("dashboard"))

    return render_template("create_course.html", categories=CATEGORIES, levels=LEVELS)


# ----- Course Detail (videos + assignments + posts) -----
@app.route("/course/<int:course_id>")
def course_detail(course_id):
    if "user" not in session:
        return redirect(url_for("login"))

    user = session["user"]
    user_id = user["id"]
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Get course
    c.execute("SELECT * FROM courses WHERE id = ?", (course_id,))
    course = c.fetchone()
    if not course:
        conn.close()
        flash("Course not found.", "error")
        return redirect(url_for("dashboard"))

    # Get videos
    c.execute("SELECT * FROM videos WHERE course_id = ? ORDER BY id ASC", (course_id,))
    videos = c.fetchall()

    # Get assignments
    c.execute("SELECT * FROM assignments WHERE course_id = ? ORDER BY id ASC", (course_id,))
    assignments = c.fetchall()

    # Topic updates: only enrolled students and the instructor see posts
    is_instructor = (user["role"] == "Instructor" and course["instructor"] == user["username"])
    is_enrolled = False
    if user["role"] != "Instructor":
        c.execute("SELECT 1 FROM user_courses WHERE user_id = ? AND course_id = ?", (user_id, course_id))
        is_enrolled = c.fetchone() is not None

    posts = []
    if is_instructor or is_enrolled:
        c.execute("SELECT * FROM course_posts WHERE course_id = ? ORDER BY id DESC", (course_id,))
        posts = c.fetchall()

    # Check if course is completed
    c.execute("""
        SELECT completed FROM course_progress
        WHERE user_id = ? AND course_id = ?
    """, (user_id, course_id))
    progress_row = c.fetchone()
    is_completed = bool(progress_row and progress_row["completed"] == 1)

    conn.close()

    return render_template(
        "course_detail.html",
        course=course,
        videos=videos,
        assignments=assignments,
        posts=posts,
        is_completed=is_completed,
        is_instructor=is_instructor,
        is_enrolled=is_enrolled,
        categories=CATEGORIES,
        levels=LEVELS
    )


# ----- Topic updates: create / edit / delete (instructor only) -----
@app.route("/course/<int:course_id>/post", methods=["POST"])
def create_post(course_id):
    guard = instructor_required()
    if guard:
        return guard

    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    if not title or not body:
        flash("Post needs a title and a message.", "error")
        return redirect(url_for("course_detail", course_id=course_id))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT instructor FROM courses WHERE id = ?", (course_id,))
    row = c.fetchone()
    if not row or row[0] != session["user"]["username"]:
        conn.close()
        abort(403)
    c.execute(
        "INSERT INTO course_posts (course_id, author, title, body) VALUES (?, ?, ?, ?)",
        (course_id, session["user"]["username"], title, body)
    )
    conn.commit()
    conn.close()
    flash("Update posted to enrolled students.", "success")
    return redirect(url_for("course_detail", course_id=course_id))


@app.route("/post/<int:post_id>/edit", methods=["POST"])
def edit_post(post_id):
    guard = instructor_required()
    if guard:
        return guard

    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    if not title or not body:
        flash("Post needs a title and a message.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT p.course_id FROM course_posts p
        JOIN courses c ON p.course_id = c.id
        WHERE p.id = ? AND c.instructor = ?
    """, (post_id, session["user"]["username"]))
    row = c.fetchone()
    if not row:
        conn.close()
        abort(403)
    c.execute("UPDATE course_posts SET title = ?, body = ? WHERE id = ?", (title, body, post_id))
    conn.commit()
    conn.close()
    flash("Update edited.", "success")
    return redirect(url_for("course_detail", course_id=row[0]))


@app.route("/post/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    guard = instructor_required()
    if guard:
        return guard

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT p.course_id FROM course_posts p
        JOIN courses c ON p.course_id = c.id
        WHERE p.id = ? AND c.instructor = ?
    """, (post_id, session["user"]["username"]))
    row = c.fetchone()
    if not row:
        conn.close()
        abort(403)
    c.execute("DELETE FROM course_posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    flash("Update deleted.", "success")
    return redirect(url_for("course_detail", course_id=row[0]))


# ----- Mark Course as Done -----
@app.route("/course/<int:course_id>/done", methods=["POST"])
def mark_course_done(course_id):
    if "user" not in session:
        flash("Please log in to mark progress.", "error")
        return redirect(url_for("login"))

    user_id = session["user"]["id"]

    conn = get_db()
    c = conn.cursor()

    # Mark course as completed
    c.execute("""
        INSERT INTO course_progress (user_id, course_id, completed)
        VALUES (?, ?, 1)
        ON CONFLICT(user_id, course_id)
        DO UPDATE SET completed = 1, completed_at = CURRENT_TIMESTAMP
    """, (user_id, course_id))

    conn.commit()
    conn.close()

    flash("Course completed!", "success")
    return redirect(url_for("my_courses"))


# ----- Add Course (Student) -----
@app.route("/add_course/<int:course_id>")
def add_course(course_id):
    if "user" not in session:
        return redirect(url_for("login"))
    user_id = session["user"]["id"]

    conn = get_db()
    c = conn.cursor()

    # Ensure course exists
    c.execute("SELECT id FROM courses WHERE id=?", (course_id,))
    if not c.fetchone():
        conn.close()
        flash("Course not found.", "error")
        return redirect(url_for("dashboard"))

    # Enroll
    try:
        c.execute(
            "INSERT OR IGNORE INTO user_courses (user_id, course_id) VALUES (?, ?)",
            (user_id, course_id)
        )
        conn.commit()
        if c.rowcount == 0:
            flash("You already added this course.", "error")
        else:
            flash("Course added to your list!", "success")
    finally:
        conn.close()

    return redirect(request.referrer or url_for("dashboard"))


# ----- My Courses (Student) -----
@app.route("/my_courses")
def my_courses():
    if "user" not in session:
        return redirect(url_for("login"))

    user = session["user"]

    # Block instructors from accessing this route
    if user["role"].lower() == "instructor":
        return redirect(url_for("dashboard"))

    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Student: get their enrolled courses
    c.execute("""
        SELECT c.* FROM courses c
        JOIN user_courses uc ON c.id = uc.course_id
        WHERE uc.user_id = ?
    """, (user["id"],))
    courses = c.fetchall()
    conn.close()

    # Calculate overall progress for the student
    progress = int(get_user_progress(user["id"]))

    return render_template(
        "my_courses.html",
        courses=courses,
        role=user["role"],
        progress=progress
    )


# ----- Upload Video (Instructor) -----
@app.route("/upload_video", methods=["GET", "POST"])
def upload_video():
    guard = instructor_required()
    if guard:
        return guard

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM courses WHERE instructor=?", (session["user"]["username"],))
    courses = c.fetchall()

    if request.method == "POST":
        course_id = request.form["course_id"]
        title = request.form["title"].strip()
        file = request.files.get("video")

        if not file or file.filename == "":
            flash("Select a video file.", "error")
        elif not allowed_file(file.filename, VIDEO_EXT):
            flash("Unsupported video format.", "error")
        else:
            filename = unique_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            c.execute(
                "INSERT INTO videos (course_id, title, filename) VALUES (?, ?, ?)",
                (course_id, title, filename)
            )
            conn.commit()
            flash("Video uploaded successfully!", "success")
            conn.close()
            # Redirect to course detail instead of dashboard
            return redirect(url_for("course_detail", course_id=course_id))

    conn.close()
    return render_template("upload_video.html", courses=courses)


# ----- Upload Assignment (Instructor) -----
@app.route("/upload_assignment", methods=["GET", "POST"])
def upload_assignment():
    guard = instructor_required()
    if guard:
        return guard

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM courses WHERE instructor=?", (session["user"]["username"],))
    courses = c.fetchall()

    if request.method == "POST":
        course_id = request.form["course_id"] 
        title = request.form["title"].strip()
        file = request.files.get("assignment")

        if not file or file.filename == "":
            flash("Select an assignment file.", "error")
        elif not allowed_file(file.filename, DOC_EXT):
            flash("Unsupported document format.", "error")
        else:
            filename = unique_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            c.execute(
                "INSERT INTO assignments (course_id, title, filename) VALUES (?, ?, ?)",
                (course_id, title, filename)
            )
            conn.commit()
            flash("Assignment uploaded successfully!", "success")
            conn.close()
            # Redirect to course detail instead of dashboard
            return redirect(url_for("course_detail", course_id=course_id))

    conn.close()
    return render_template("upload_assignment.html", courses=courses)


# ----- Serve Uploads -----
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


def delete_user_from_db(user_id):
    """Remove a user and their related data (including uploaded files) from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get user role and username
    cursor.execute("SELECT username, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return
    username, role = user

    if role == "Instructor":
        # Get all courses created by the instructor
        cursor.execute("SELECT id, image FROM courses WHERE instructor = ?", (username,))
        courses = cursor.fetchall()

        for course_id, image_filename in courses:
            # --- Delete videos and their files ---
            cursor.execute("SELECT filename FROM videos WHERE course_id = ?", (course_id,))
            for (filename,) in cursor.fetchall():
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
            cursor.execute("DELETE FROM videos WHERE course_id = ?", (course_id,))

            # --- Delete assignments and their files ---
            cursor.execute("SELECT filename FROM assignments WHERE course_id = ?", (course_id,))
            for (filename,) in cursor.fetchall():
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
            cursor.execute("DELETE FROM assignments WHERE course_id = ?", (course_id,))

            # --- Delete posts for the course ---
            cursor.execute("DELETE FROM course_posts WHERE course_id = ?", (course_id,))

            # --- Delete enrollments for the course ---
            cursor.execute("DELETE FROM user_courses WHERE course_id = ?", (course_id,))

            # --- Delete course image ---
            if image_filename:
                file_path = os.path.join(UPLOAD_FOLDER, image_filename)
                if os.path.exists(file_path):
                    os.remove(file_path)

        # Finally, delete the instructor's courses
        cursor.execute("DELETE FROM courses WHERE instructor = ?", (username,))

    # For both students & instructors: remove their enrollments and progress record
    cursor.execute("DELETE FROM user_courses WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM course_progress WHERE user_id = ?", (user_id,))

    # Delete the user account
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

    conn.commit()
    conn.close()


@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user" not in session:
        flash("You need to log in first.")
        return redirect(url_for("login"))

    user_id = session["user"]["id"]

    delete_user_from_db(user_id)

    session.clear()
    flash("Your account has been deleted successfully.", "success")
    return redirect(url_for("login"))


@app.route("/search")
def search():
    term = request.args.get("q", "").strip()
    results = []

    if term:
        conn = get_db()
        c = conn.cursor()
        like_term = f"%{term}%"

        # Search courses (case-insensitive)
        c.execute("SELECT id, title FROM courses WHERE title LIKE ? COLLATE NOCASE", (like_term,))
        for course in c.fetchall():
            results.append({"id": course[0], "name": course[1], "type": "course"})
        conn.close()

    return jsonify(results)


# --- Global Progress ---
def get_user_progress(user_id):
    conn = get_db()
    c = conn.cursor()

    # total enrolled (fix table name if needed)
    c.execute("SELECT COUNT(*) FROM user_courses WHERE user_id = ?", (user_id,))
    total = c.fetchone()[0]

    # completed courses
    c.execute("""
        SELECT COUNT(*)
        FROM course_progress
        WHERE user_id = ? AND completed = 1
    """, (user_id,))
    completed = c.fetchone()[0]

    conn.close()

    progress = (completed / total * 100) if total > 0 else 0
    return round(progress, 2)


@app.route("/delete_course/<int:course_id>", methods=["POST"])
def delete_course(course_id):
    guard = instructor_required()
    if guard:
        return guard

    conn = get_db()
    c = conn.cursor()

    # Ensure instructor only deletes their own course
    c.execute("SELECT * FROM courses WHERE id = ? AND instructor = ?", (course_id, session["user"]["username"]))
    course = c.fetchone()
    if not course:
        flash("Course not found or you do not have permission to delete it.", "error")
        conn.close()
        return redirect(url_for("dashboard"))

    # --- Delete videos and their files ---
    c.execute("SELECT filename FROM videos WHERE course_id = ?", (course_id,))
    for (filename,) in c.fetchall():
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    c.execute("DELETE FROM videos WHERE course_id = ?", (course_id,))

    # --- Delete assignments and their files ---
    c.execute("SELECT filename FROM assignments WHERE course_id = ?", (course_id,))
    for (filename,) in c.fetchall():
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    c.execute("DELETE FROM assignments WHERE course_id = ?", (course_id,))

    # --- Delete topic updates ---
    c.execute("DELETE FROM course_posts WHERE course_id = ?", (course_id,))

    # --- Delete enrollments & progress ---
    c.execute("DELETE FROM user_courses WHERE course_id = ?", (course_id,))
    c.execute("DELETE FROM course_progress WHERE course_id = ?", (course_id,))

    # --- Delete course image ---
    if course[5]:  # 'image' is the 6th column (index 5)
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], course[5])
        if os.path.exists(image_path):
            os.remove(image_path)

    # --- Finally, delete the course itself ---
    c.execute("DELETE FROM courses WHERE id = ?", (course_id,))

    conn.commit()
    conn.close()

    flash("Course deleted successfully.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True, port=7700)

import os
import time
import sqlite3
import re
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ----------------------------
# App & Upload Config
# ----------------------------
app = Flask(__name__)
app.secret_key = "supersecret"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1GB 

VIDEO_EXT = {".mp4", ".mov", ".m4v", ".webm", ".avi", ".mkv"}
DOC_EXT = {".pdf", ".doc", ".docx", ".txt", ".md", ".ppt", ".pptx"}

# DB Init
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        instructor TEXT,
        image TEXT
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

    conn.commit()
    conn.close()

init_db()

# ----------------------------
# Helpers
# ----------------------------
def get_db():
    return sqlite3.connect(DB_PATH)

def allowed_file(filename, allowed):
    ext = os.path.splitext(filename)[1].lower()
    return ext in allowed

def unique_filename(filename):
    name, ext = os.path.splitext(secure_filename(filename))
    return f"{int(time.time())}_{name}{ext}"

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def main():
    return redirect(url_for("login"))

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
        if not re.search(r"[A-Z]", password_raw):
            return render_template("signup.html", error="Password must contain an uppercase letter.")
        if not re.search(r"[a-z]", password_raw):
            return render_template("signup.html", error="Password must contain a lowercase letter.")
        if not re.search(r"[0-9]", password_raw):
            return render_template("signup.html", error="Password must contain a number.")

        hashed_password = generate_password_hash(password_raw)

        conn = get_db()
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (Username, password, role) VALUES (?, ?, ?)",
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
        c.execute("SELECT * FROM users WHERE Username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
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
            total_students=total_students
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

    conn.close()
    return render_template(
        "student_dashboard.html",
        user=user,
        enrolled_courses=enrolled_courses,
        recommended=recommended,
        enrolled_count=len(enrolled_courses)
    )

# ----- Profile -----
@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("profile.html", user=session["user"])

# ----- Create Course (Instructor) -----
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

@app.route("/create_course", methods=["GET", "POST"])
def create_course():
    if "user" not in session or session["user"]["role"] != "Instructor":
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form.get("description", "").strip()
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
            "INSERT INTO courses (title, description, instructor, image) VALUES (?, ?, ?, ?)",
            (title, description, instructor, image_filename)
        )
        conn.commit()
        conn.close()
        flash("Course created!", "success")
        return redirect(url_for("dashboard"))

    return render_template("create_course.html")


# ----- Course Detail (videos + assignments) -----
@app.route("/course/<int:course_id>")
def course_detail(course_id):
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM courses WHERE id=?", (course_id,))
    course = c.fetchone()
    if not course:
        conn.close()
        flash("Course not found.", "error")
        return redirect(url_for("dashboard"))

    c.execute("SELECT * FROM videos WHERE course_id=? ORDER BY id DESC", (course_id,))
    videos = c.fetchall()

    c.execute("SELECT * FROM assignments WHERE course_id=? ORDER BY id DESC", (course_id,))
    assignments = c.fetchall()

    conn.close()
    return render_template(
        "course_detail.html",
        user=session["user"],
        course=course,
        videos=videos,
        assignments=assignments
    )

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
    user_id = session["user"]["id"]

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT courses.* FROM courses
        JOIN user_courses ON courses.id = user_courses.course_id
        WHERE user_courses.user_id=?
        ORDER BY courses.id DESC
    """, (user_id,))
    courses = c.fetchall()
    conn.close()
    return render_template("my_courses.html", user=session["user"], courses=courses)

# ----- Upload Video (Instructor) -----
@app.route("/upload_video", methods=["GET", "POST"])
def upload_video():
    if "user" not in session or session["user"]["role"] != "Instructor":
        return redirect(url_for("login"))

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
            return redirect(url_for("dashboard"))

    conn.close()
    return render_template("upload_video.html", courses=courses)

# ----- Upload Assignment (Instructor) -----
@app.route("/upload_assignment", methods=["GET", "POST"])
def upload_assignment():
    if "user" not in session or session["user"]["role"] != "Instructor":
        return redirect(url_for("login"))

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
            return redirect(url_for("dashboard"))

    conn.close()# ✅ match login session
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
    cursor.execute("SELECT Username, role FROM users WHERE id = ?", (user_id,))
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

            # --- Delete enrollments for the course ---
            cursor.execute("DELETE FROM user_courses WHERE course_id = ?", (course_id,))

            # --- Delete course image ---
            if image_filename:
                file_path = os.path.join(UPLOAD_FOLDER, image_filename)
                if os.path.exists(file_path):
                    os.remove(file_path)

        # Finally, delete the instructor's courses
        cursor.execute("DELETE FROM courses WHERE instructor = ?", (username,))

    # For both students & instructors: remove their enrollments
    cursor.execute("DELETE FROM user_courses WHERE user_id = ?", (user_id,))

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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7700))  # Render provides PORT
    app.run(host="0.0.0.0", port=port, debug=False)


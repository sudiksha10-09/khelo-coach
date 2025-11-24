# app.py
import os
from dotenv import load_dotenv

# Load .env first so os.getenv() works below
load_dotenv()

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Optional integrations (Authlib + Google Sheets)
try:
    from authlib.integrations.flask_client import OAuth
except Exception:
    OAuth = None

try:
    import gspread
    from google.oauth2.service_account import Credentials
except Exception:
    gspread = None
    Credentials = None

# -----------------------------------------------------------------------------
# APP + DB CONFIG
# -----------------------------------------------------------------------------

app = Flask(__name__, static_folder="static", template_folder="templates")

# Secret key, read from .env or fallback (change in production)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sqlite_path = os.path.join(BASE_DIR, "khelo_coach.db")
default_sqlite_uri = "sqlite:///" + sqlite_path

# Use DATABASE_URL (Postgres on Render) if provided, else sqlite for local dev
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", default_sqlite_uri)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Upload settings
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_RESUME_EXTENSIONS = {"pdf", "doc", "docx"}

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


def allowed_file(filename: str, allowed_extensions: set) -> bool:
    return (
        bool(filename)
        and "."
        in filename
        and filename.rsplit(".", 1)[1].lower() in allowed_extensions
    )


# -----------------------------------------------------------------------------
# MODELS
# -----------------------------------------------------------------------------

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False, default="")
    role = db.Column(db.String(20), nullable=False)  # "coach" or "recruiter"

    coach_profile = db.relationship("CoachProfile", backref="user", uselist=False)
    jobs = db.relationship("Job", backref="recruiter", lazy=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            # SSO-only user, no local password
            return False
        return check_password_hash(self.password_hash, password)


class CoachProfile(db.Model):
    __tablename__ = "coach_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    sport = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    experience_years = db.Column(db.Integer, nullable=False, default=0)

    certificates = db.Column(db.String(255))
    locations_served = db.Column(db.String(255))
    rate = db.Column(db.String(100))
    availability = db.Column(db.String(255))
    bio = db.Column(db.Text)

    # Image fields
    photo_url = db.Column(db.String(255))
    photo_filename = db.Column(db.String(255))  # stored in static/uploads/

    # Resume
    resume_filename = db.Column(db.String(255))  # stored in static/uploads/


class Job(db.Model):
    __tablename__ = "jobs"

    id = db.Column(db.Integer, primary_key=True)
    recruiter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    title = db.Column(db.String(200), nullable=False)
    sport = db.Column(db.String(50))
    location = db.Column(db.String(100), nullable=False)
    salary = db.Column(db.String(100))
    experience_required = db.Column(db.String(100))
    description = db.Column(db.Text)

    # Optional logo for recruiter / job
    logo_url = db.Column(db.String(255))


class JobApplication(db.Model):
    __tablename__ = "job_applications"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("jobs.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    experience = db.Column(db.String(255))
    notes = db.Column(db.Text)

    # Optional resume upload per application
    resume_filename = db.Column(db.String(255))


@login_manager.user_loader
def load_user(user_id):
    # SQLAlchemy 2.x style
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


# -----------------------------------------------------------------------------
# GOOGLE SHEETS INTEGRATION (OPTIONAL)
# -----------------------------------------------------------------------------

GOOGLE_SHEETS_ID = os.getenv("GOOGLE_SHEETS_ID")
GOOGLE_CREDS_FILE = os.getenv("GOOGLE_CREDS_FILE", "google_creds.json")
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]


def get_sheet():
    """
    Returns a gspread worksheet if configured, otherwise None.
    Safe for local development: it will return None when not configured.
    """
    if not (GOOGLE_SHEETS_ID and gspread and Credentials):
        return None

    try:
        creds = Credentials.from_service_account_file(GOOGLE_CREDS_FILE, scopes=SCOPES)
        client = gspread.authorize(creds)
        return client.open_by_key(GOOGLE_SHEETS_ID).sheet1
    except Exception as e:
        print("⚠️ Google Sheets error:", e)
        return None


# -----------------------------------------------------------------------------
# GOOGLE SSO (Authlib - OpenID Connect)
# -----------------------------------------------------------------------------

oauth = OAuth(app) if OAuth else None
google_oauth = None

# Register OIDC-enabled Google provider if credentials present
if oauth and os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"):
    google_oauth = oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        # Use the OpenID Connect discovery endpoint (recommended)
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


# -----------------------------------------------------------------------------
# ROUTES
# -----------------------------------------------------------------------------

@app.route("/")
def home():
    featured_coaches = CoachProfile.query.limit(3).all()
    featured_jobs = Job.query.limit(3).all()
    return render_template(
        "home.html",
        featured_coaches=featured_coaches,
        featured_jobs=featured_jobs,
        google_oauth_enabled=bool(google_oauth),
    )


# ---------- Coach listing & profile ----------------------------------------

@app.route("/coaches")
def coach_listing():
    sport = request.args.get("sport", "").strip()
    location = request.args.get("location", "").strip()
    q = request.args.get("q", "").strip()

    query = CoachProfile.query

    if sport:
        query = query.filter(CoachProfile.sport.ilike(f"%{sport}%"))
    if location:
        query = query.filter(CoachProfile.location.ilike(f"%{location}%"))
    if q:
        query = query.join(User).filter(
            db.or_(
                User.full_name.ilike(f"%{q}%"),
                CoachProfile.sport.ilike(f"%{q}%"),
                CoachProfile.location.ilike(f"%{q}%"),
                CoachProfile.bio.ilike(f"%{q}%"),
            )
        )

    coaches = query.all()
    return render_template(
        "coach_listing.html",
        coaches=coaches,
        sport=sport,
        location=location,
        q=q,
    )


@app.route("/coaches/<int:coach_id>")
def coach_profile(coach_id):
    coach = CoachProfile.query.get_or_404(coach_id)
    return render_template("coach_profile.html", coach=coach)


# ---------- Become / edit coach profile -----------------------------------

@app.route("/become-a-coach", methods=["GET", "POST"])
@login_required
def become_coach():
    if current_user.role != "coach":
        flash("Only coach accounts can create a coach profile.", "warning")
        return redirect(url_for("home"))

    profile = current_user.coach_profile

    if request.method == "POST":
        if not profile:
            profile = CoachProfile(user_id=current_user.id)

        profile.sport = request.form.get("sport") or ""
        profile.location = request.form.get("location") or ""
        try:
            profile.experience_years = int(request.form.get("experience") or 0)
        except ValueError:
            profile.experience_years = 0
        profile.certificates = request.form.get("certificates")
        profile.locations_served = request.form.get("locations_served")
        profile.rate = request.form.get("rate")
        profile.availability = request.form.get("availability")
        profile.bio = request.form.get("bio")
        profile.photo_url = request.form.get("photo_url")

        # Handle image file upload
        photo_file = request.files.get("photo_upload")
        if photo_file and photo_file.filename:
            if allowed_file(photo_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                filename = secure_filename(photo_file.filename)
                base, ext = os.path.splitext(filename)
                filename = f"coach_{current_user.id}_{base}{ext}"
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                photo_file.save(save_path)
                profile.photo_filename = filename
            else:
                flash("Invalid image file type.", "danger")

        # Handle resume upload
        resume_file = request.files.get("resume_upload")
        if resume_file and resume_file.filename:
            if allowed_file(resume_file.filename, ALLOWED_RESUME_EXTENSIONS):
                filename = secure_filename(resume_file.filename)
                base, ext = os.path.splitext(filename)
                filename = f"resume_{current_user.id}_{base}{ext}"
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                resume_file.save(save_path)
                profile.resume_filename = filename
            else:
                flash("Invalid resume file type.", "danger")

        db.session.add(profile)
        db.session.commit()
        flash("Your coach profile has been saved.", "success")
        return redirect(url_for("coach_profile", coach_id=profile.id))

    return render_template("become_coach.html", profile=profile)


# ---------- Jobs listing, posting, applying --------------------------------

@app.route("/jobs")
def jobs_listing():
    sport = request.args.get("sport", "").strip()
    location = request.args.get("location", "").strip()

    query = Job.query
    if sport:
        query = query.filter(Job.sport.ilike(f"%{sport}%"))
    if location:
        query = query.filter(Job.location.ilike(f"%{location}%"))

    jobs = query.all()
    return render_template("jobs_listing.html", jobs=jobs, sport=sport, location=location)


@app.route("/jobs/new", methods=["GET", "POST"])
@login_required
def new_job():
    if current_user.role != "recruiter":
        flash("Only recruiter accounts can post jobs.", "warning")
        return redirect(url_for("jobs_listing"))

    if request.method == "POST":
        title = request.form.get("title")
        sport = request.form.get("sport")
        location = request.form.get("location")
        salary = request.form.get("salary")
        experience_required = request.form.get("experience_required")
        description = request.form.get("description")
        logo_url = request.form.get("logo_url")

        job = Job(
            recruiter_id=current_user.id,
            title=title,
            sport=sport,
            location=location,
            salary=salary,
            experience_required=experience_required,
            description=description,
            logo_url=logo_url,
        )
        db.session.add(job)
        db.session.commit()
        flash("Job posted successfully.", "success")
        return redirect(url_for("jobs_listing"))

    return render_template("job_new.html")


@app.route("/jobs/<int:job_id>/apply", methods=["GET", "POST"])
def apply_for_job(job_id):
    job = Job.query.get_or_404(job_id)

    if request.method == "POST":
        name = request.form.get("name")
        experience = request.form.get("experience")
        notes = request.form.get("notes")

        app_obj = JobApplication(
            job_id=job.id,
            name=name,
            experience=experience,
            notes=notes,
        )

        # Optional resume upload per job application
        resume_file = request.files.get("resume_upload")
        if resume_file and resume_file.filename:
            if allowed_file(resume_file.filename, ALLOWED_RESUME_EXTENSIONS):
                filename = secure_filename(resume_file.filename)
                base, ext = os.path.splitext(filename)
                filename = f"application_{job.id}_{base}{ext}"
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                resume_file.save(save_path)
                app_obj.resume_filename = filename
            else:
                flash("Invalid resume file type.", "danger")

        db.session.add(app_obj)
        db.session.commit()

        # Optional: push to Google Sheets
        sheet = get_sheet()
        if sheet:
            try:
                sheet.append_row(
                    [
                        job.id,
                        job.title,
                        job.location,
                        name,
                        experience,
                        notes,
                        "yes" if app_obj.resume_filename else "no",
                    ]
                )
            except Exception as e:
                print("⚠️ Could not append to Google Sheet:", e)

        flash("Application submitted!", "success")
        return redirect(url_for("jobs_listing"))

    return render_template("apply_for_job.html", job=job)


# ---------- AUTH: combined login + signup -----------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # login form posted
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("home"))

        flash("Invalid credentials.", "danger")

    # show combined auth page (login & signup side-by-side)
    return render_template(
        "auth.html",
        mode="login",
        google_oauth_enabled=bool(google_oauth),
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role") or "coach"

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        user = User(full_name=full_name, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash("Registration successful.", "success")
        return redirect(url_for("home"))

    return render_template(
        "auth.html",
        mode="signup",
        google_oauth_enabled=bool(google_oauth),
    )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("home"))


# ---------- Google SSO routes -----------------------------------------------

@app.route("/login/google")
def login_google():
    if not google_oauth:
        flash("Google login not configured yet.", "warning")
        return redirect(url_for("login"))

    redirect_uri = url_for("auth_google_callback", _external=True)
    return google_oauth.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def auth_google_callback():
    if not google_oauth:
        flash("Google login not configured.", "warning")
        return redirect(url_for("login"))

    # Exchange code for token and fetch userinfo using OIDC discovery
    token = google_oauth.authorize_access_token()
    # Preferred: use .userinfo() when registered with server_metadata_url
    try:
        userinfo = google_oauth.userinfo()
    except Exception:
        # fallback to manual userinfo endpoint
        resp = google_oauth.get("userinfo")
        userinfo = resp.json() if resp else None

    if not userinfo:
        flash("Could not fetch Google user info.", "danger")
        return redirect(url_for("login"))

    email = userinfo.get("email")
    name = userinfo.get("name") or (email.split("@")[0] if email else "Google User")

    if not email:
        flash("Google account didn't return an email. Try another account.", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        # default to coach role for SSO signups; you can show a role selection later
        user = User(full_name=name, email=email, role="coach", password_hash="")
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash("Logged in with Google.", "success")
    return redirect(url_for("home"))


# ---------- Serve uploaded files (download) ---------------------------------

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # public route to download uploaded files (resumes / images)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Helpful: If you want to (re)create tables from this file:
    #   python app.py init-db
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "init-db":
        with app.app_context():
            db.create_all()
            print("✅ DB tables created (or already existed).")
        sys.exit(0)

    # Regular run
    app.run(debug=True)

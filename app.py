import os

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

# Optional integrations (Google SSO + Google Sheets)
try:
    from authlib.integrations.flask_client import OAuth
except ImportError:
    OAuth = None

try:
    import gspread
    from google.oauth2.service_account import Credentials
except ImportError:
    gspread = None
    Credentials = None


# -----------------------------------------------------------------------------
# APP + DB CONFIG
# -----------------------------------------------------------------------------

app = Flask(__name__)

# Secret key (override in env on Render)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sqlite_path = os.path.join(BASE_DIR, "khelo_coach.db")
default_sqlite_uri = "sqlite:///" + sqlite_path

# If DATABASE_URL is set (e.g. Render Postgres), use that. Otherwise SQLite.
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", default_sqlite_uri)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

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
    experience_years = db.Column(db.Integer, nullable=False)

    certificates = db.Column(db.String(255))
    locations_served = db.Column(db.String(255))
    rate = db.Column(db.String(100))
    availability = db.Column(db.String(255))
    bio = db.Column(db.Text)


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


class JobApplication(db.Model):
    __tablename__ = "job_applications"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("jobs.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    experience = db.Column(db.String(255))
    notes = db.Column(db.Text)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -----------------------------------------------------------------------------
# GOOGLE SHEETS INTEGRATION (OPTIONAL)
# -----------------------------------------------------------------------------

GOOGLE_SHEETS_ID = os.getenv("GOOGLE_SHEETS_ID")  # set this on Render/local .env
GOOGLE_CREDS_FILE = os.getenv("GOOGLE_CREDS_FILE", "google_creds.json")
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]


def get_sheet():
    """
    Returns a gspread worksheet if configured, otherwise None.
    Safe for local development (no crash if not set).
    """
    if not (GOOGLE_SHEETS_ID and gspread and Credentials):
        return None

    try:
        creds = Credentials.from_service_account_file(
            GOOGLE_CREDS_FILE, scopes=SCOPES
        )
        client = gspread.authorize(creds)
        return client.open_by_key(GOOGLE_SHEETS_ID).sheet1
    except Exception as e:
        print("⚠️ Google Sheets error:", e)
        return None


# -----------------------------------------------------------------------------
# GOOGLE SSO (OPTIONAL)
# -----------------------------------------------------------------------------

oauth = OAuth(app) if OAuth else None
google_oauth = None

if oauth and os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"):
    google_oauth = oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        access_token_url="https://oauth2.googleapis.com/token",
        authorize_url="https://accounts.google.com/o/oauth2/auth",
        api_base_url="https://www.googleapis.com/oauth2/v2/",
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
    )


# ---------------------- Coach listing & profile ------------------------------

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


# ------------------- Become / edit coach profile ----------------------------

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

        profile.sport = request.form.get("sport")
        profile.location = request.form.get("location")
        profile.experience_years = int(request.form.get("experience") or 0)
        profile.certificates = request.form.get("certificates")
        profile.locations_served = request.form.get("locations_served")
        profile.rate = request.form.get("rate")
        profile.availability = request.form.get("availability")
        profile.bio = request.form.get("bio")

        db.session.add(profile)
        db.session.commit()
        flash("Your coach profile has been saved.", "success")
        return redirect(url_for("coach_profile", coach_id=profile.id))

    return render_template("become_coach.html", profile=profile)


# ---------------------- Jobs listing, posting, applying ---------------------

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
    return render_template(
        "jobs_listing.html",
        jobs=jobs,
        sport=sport,
        location=location,
    )


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

        job = Job(
            recruiter_id=current_user.id,
            title=title,
            sport=sport,
            location=location,
            salary=salary,
            experience_required=experience_required,
            description=description,
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
                    ]
                )
            except Exception as e:
                print("⚠️ Could not append to Google Sheet:", e)

        flash("Application submitted!", "success")
        return redirect(url_for("jobs_listing"))

    return render_template("apply_for_job.html", job=job)


# ---------------------- AUTH: register, login, logout -----------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")  # coach / recruiter

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

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("home"))

        flash("Invalid credentials.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("home"))


# ---------------------- Google SSO routes (optional) ------------------------

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

    token = google_oauth.authorize_access_token()
    resp = google_oauth.get("userinfo")
    userinfo = resp.json()

    email = userinfo.get("email")
    name = userinfo.get("name") or email.split("@")[0]

    user = User.query.filter_by(email=email).first()
    if not user:
        # default to coach; can later add "choose role" UI
        user = User(full_name=name, email=email, role="coach", password_hash="")
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash("Logged in with Google.", "success")
    return redirect(url_for("home"))


# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # First time, run a Python shell and do:
    # >>> from app import app, db
    # >>> with app.app_context(): db.create_all()
    app.run(debug=True)

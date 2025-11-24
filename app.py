import os
from dotenv import load_dotenv
from sqlalchemy import func
import traceback

load_dotenv()  # load variables from .env
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
from werkzeug.utils import secure_filename

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

# Upload settings
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_RESUME_EXTENSIONS = {"pdf", "doc", "docx"}

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


def allowed_file(filename: str, allowed_extensions: set) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


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
    # Use SQLAlchemy 2.x style
    return db.session.get(User, int(user_id))


# -----------------------------------------------------------------------------
# GOOGLE SHEETS INTEGRATION (OPTIONAL)
# -----------------------------------------------------------------------------
GOOGLE_SHEETS_ID = os.getenv("GOOGLE_SHEETS_ID")  # and set this env var
GOOGLE_CREDS_FILE = os.getenv("GOOGLE_CREDS_FILE")
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]

def get_sheet():
    """
    Returns a gspread worksheet if configured, otherwise None.
    Also prints a detailed error in the console when something goes wrong.
    """
    # 1. Check basic config first
    if not GOOGLE_SHEETS_ID:
        print("⚠️ Google Sheets error: GOOGLE_SHEETS_ID is not set (check .env).")
        return None
    if not gspread or not Credentials:
        print("⚠️ Google Sheets error: gspread or google-auth not installed.")
        return None
    if not os.path.exists(GOOGLE_CREDS_FILE):
        print(f"⚠️ Google Sheets error: creds file not found at '{GOOGLE_CREDS_FILE}'.")
        return None

    # 2. Try connecting
    try:
        creds = Credentials.from_service_account_file(GOOGLE_CREDS_FILE, scopes=SCOPES)
        client = gspread.authorize(creds)
        sheet = client.open_by_key(GOOGLE_SHEETS_ID).sheet1
        # Optional: print once so you know it worked
        # print("✅ Connected to Google Sheet:", GOOGLE_SHEETS_ID)
        return sheet
    except Exception as e:
        print("⚠️ Google Sheets error (detailed):", repr(e))
        traceback.print_exc()
        return None

# -----------------------------------------------------------------------------
# GOOGLE SSO (Authlib)
# -----------------------------------------------------------------------------

oauth = OAuth(app) if OAuth else None
google_oauth = None

if oauth and os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"):
    google_oauth = oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        # Fixed server metadata URL for Google
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


# -----------------------------------------------------------------------------
# ROUTES
# -----------------------------------------------------------------------------

@app.route("/")
def home():
    # Featured items (existing)
    featured_coaches = CoachProfile.query.limit(3).all()
    featured_jobs = Job.query.limit(3).all()

    # --- Live snapshot data (dynamic) ---
    # total counts
    total_coaches = db.session.query(func.count(CoachProfile.id)).scalar() or 0
    total_jobs = db.session.query(func.count(Job.id)).scalar() or 0

    # top sports by number of coach profiles (limit 4)
    top_sports = (
        db.session.query(CoachProfile.sport, func.count(CoachProfile.id).label("cnt"))
        .group_by(CoachProfile.sport)
        .order_by(func.count(CoachProfile.id).desc())
        .limit(4)
        .all()
    )
    # convert to simple list of strings "Sport · X"
    top_sports_tags = [f"{row.sport} · {row.cnt} coaches" for row in top_sports if row.sport]

    # top locations by coaches (limit 4)
    top_locations = (
        db.session.query(CoachProfile.location, func.count(CoachProfile.id).label("cnt"))
        .group_by(CoachProfile.location)
        .order_by(func.count(CoachProfile.id).desc())
        .limit(4)
        .all()
    )
    top_location_tags = [f"{row.location} · {row.cnt}" for row in top_locations if row.location]

    # Recent coaches (show name, sport, location) - limit 3
    recent_coaches = (
        db.session.query(CoachProfile).order_by(CoachProfile.id.desc()).limit(3).all()
    )

    # hero image path (you uploaded an illustration). We pass it to template.
    # Developer note: this is the uploaded local path you supplied — if you want it served
    # via /static, copy the file to static/img and use that URL instead.
    hero_img_url = "/mnt/data/287b4d9f-3c48-45bd-97ca-11c1b1935dc2.png"

    return render_template(
        "home.html",
        featured_coaches=featured_coaches,
        featured_jobs=featured_jobs,
        google_oauth_enabled=bool(google_oauth),
        # dynamic snapshot
        snapshot_total_coaches=total_coaches,
        snapshot_total_jobs=total_jobs,
        snapshot_sports=top_sports_tags,
        snapshot_locations=top_location_tags,
        snapshot_recent_coaches=recent_coaches,
        hero_img_url=hero_img_url,  # template will use this for hero illustration
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
        profile.photo_url = request.form.get("photo_url")

        # Handle image upload
        photo_file = request.files.get("photo_upload")
        if photo_file and photo_file.filename:
            if allowed_file(photo_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                filename = secure_filename(photo_file.filename)
                # avoid overwrite by adding user id
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


# ---------------------- AUTH: register, login, logout -----------------------

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

    # render combined page, with login tab active
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

    # render combined page, with signup tab active
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


# ---------------------- Google SSO routes (FIXED) ------------------------

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

    # 1. Exchange code for token (automatically validates JWKS now)
    token = google_oauth.authorize_access_token()
    
    # 2. Get user info (updated to work with server_metadata_url)
    userinfo = google_oauth.userinfo()
    
    if not userinfo:
         flash("Could not fetch Google user info.", "danger")
         return redirect(url_for("login"))

    email = userinfo.get("email")
    name = userinfo.get("name") or email.split("@")[0]

    user = User.query.filter_by(email=email).first()
    if not user:
        # default to coach; later you can allow role selection
        user = User(full_name=name, email=email, role="coach", password_hash="")
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash("Logged in with Google.", "success")
    return redirect(url_for("home"))

from flask import send_from_directory

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def setup_database():
    """
    Checks if tables exist, creates them, and adds seed data if empty.
    Runs automatically on app startup.
    """
    with app.app_context():
        # 1. Create tables
        db.create_all()
        
        # 2. Check if data exists
        if User.query.first():
            return  # Data exists, do nothing

        print("🌱 Seeding database with initial data...")
        
        # Create users
        coach1 = User(full_name="Nishant Joshi", email="nishant@example.com", role="coach")
        coach1.set_password("password123")
        coach2 = User(full_name="Aisha Khan", email="aisha@example.com", role="coach")
        coach2.set_password("password123")
        recruiter1 = User(full_name="Elite Sports Academy", email="academy@example.com", role="recruiter")
        recruiter1.set_password("password123")

        db.session.add_all([coach1, coach2, recruiter1])
        db.session.commit()

        # Create profiles
        profile1 = CoachProfile(
            user_id=coach1.id, sport="Football", location="Gurugram", experience_years=20,
            certificates="AFC C License", locations_served="Gurugram", 
            rate="₹1,500/session", availability="Weekends", 
            bio="Senior football coach with 20 years experience."
        )
        profile2 = CoachProfile(
            user_id=coach2.id, sport="Basketball", location="Mumbai", experience_years=7,
            certificates="FIBA L1", locations_served="Mumbai", 
            rate="₹1,200/session", availability="Evenings", 
            bio="Passionate youth basketball trainer."
        )
        db.session.add_all([profile1, profile2])

        # Create jobs
        job1 = Job(
            recruiter_id=recruiter1.id, title="Football Coach – School Team", sport="Football", 
            location="Mumbai", salary="₹25k/month", experience_required="2y", 
            description="Managing U-16 boys team."
        )
        job2 = Job(
            recruiter_id=recruiter1.id, title="Cricket Coach", sport="Cricket", 
            location="Pune", salary="₹30k/month", experience_required="3y", 
            description="Weekend academy coach."
        )
        db.session.add_all([job1, job2])
        
        db.session.commit()
        print("✅ Database seeded successfully!")

# Run the setup immediately when this file is imported/run
setup_database()

if __name__ == "__main__":
    app.run(debug=True)
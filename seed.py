from app import app, db, User, CoachProfile, Job

# Run: python seed.py
if __name__ == "__main__":
    with app.app_context():
        # Only seed if main demo recruiter doesn't exist
        if User.query.filter_by(email="academy@example.com").first():
            print("ℹ️ Demo data already exists, skipping.")
        else:
            # --- Users ---
            coach1 = User(full_name="Nishant Joshi",
                          email="nishant@example.com",
                          role="coach")
            coach1.set_password("password123")

            coach2 = User(full_name="Aisha Khan",
                          email="aisha@example.com",
                          role="coach")
            coach2.set_password("password123")

            recruiter = User(full_name="Elite Sports Academy",
                             email="academy@example.com",
                             role="recruiter")
            recruiter.set_password("password123")

            db.session.add_all([coach1, coach2, recruiter])
            db.session.commit()

            # --- Coach profiles ---
            profile1 = CoachProfile(
                user_id=coach1.id,
                sport="Football",
                location="Gurugram",
                experience_years=20,
                certificates="AFC C License, CPR Certified",
                locations_served="Gurugram, Delhi NCR",
                rate="₹1,500 per session · ₹40,000 per month",
                availability="Weekdays 5–8 PM, Weekends",
                bio="Senior football coach with 20 years of experience coaching school and academy teams.",
                photo_url="https://images.pexels.com/photos/932440/pexels-photo-932440.jpeg",  # sample
            )

            profile2 = CoachProfile(
                user_id=coach2.id,
                sport="Basketball",
                location="Mumbai",
                experience_years=7,
                certificates="NIS Certified, FIBA Level 1",
                locations_served="Mumbai, Thane",
                rate="₹1,200 per session",
                availability="Evenings & Weekends",
                bio="Passionate about youth basketball and fundamentals training.",
                photo_url="https://images.pexels.com/photos/1103829/pexels-photo-1103829.jpeg",  # sample
            )

            db.session.add_all([profile1, profile2])
            db.session.commit()

            # --- Jobs ---
            job1 = Job(
                recruiter_id=recruiter.id,
                title="Football Coach – School Team",
                sport="Football",
                location="Mumbai",
                salary="₹25k – ₹35k / month",
                experience_required="2–4 years",
                description="Looking for an experienced football coach to manage the school under-16 boys team.",
                logo_url="https://images.pexels.com/photos/399187/pexels-photo-399187.jpeg",  # sample
            )

            job2 = Job(
                recruiter_id=recruiter.id,
                title="Cricket Coach – Weekend Academy",
                sport="Cricket",
                location="Pune",
                salary="₹30k – ₹45k / month",
                experience_required="3–5 years",
                description="Weekend coaching for U-14 and U-19 age groups. Focus on skills + match preparation.",
            )

            job3 = Job(
                recruiter_id=recruiter.id,
                title="Swimming Instructor – Club",
                sport="Swimming",
                location="Bengaluru",
                salary="₹20k – ₹30k / month",
                experience_required="1–3 years",
                description="Swimming instructor for kids and adults. Morning and evening batches.",
            )

            db.session.add_all([job1, job2, job3])
            db.session.commit()

            print("✅ Demo users, coach profiles, and jobs inserted.")

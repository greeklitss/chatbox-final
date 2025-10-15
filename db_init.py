# ΑΛΛΑΓΗ! Εισάγουμε και το Session
from server import db, User, Setting, app 
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.sql import text

# 🚨 ΠΡΟΣΘΗΚΗ: Χρειάζεται για να ικανοποιήσει το import στο server.py, παρόλο που χρησιμοποιούμε SQL
from flask_session import Session 

# Χρησιμοποιούμε το application context
with app.app_context():
    try:
        # Δημιουργία όλων των πινάκων αν δεν υπάρχουν
        print("Δημιουργία ή ενημέρωση πινάκων βάσης δεδομένων...")
        db.create_all()

        # --- 🚨 ΠΡΟΣΘΗΚΗ: ΔΗΜΙΟΥΡΓΙΑ ΠΙΝΑΚΑ FLASK_SESSIONS ---
        print("Έλεγχος και δημιουργία πίνακα 'flask_sessions'...")
        create_sessions_table_sql = """
        CREATE TABLE IF NOT EXISTS flask_sessions (
            id VARCHAR(256) PRIMARY KEY,
            session TEXT NOT NULL,
            expiry TIMESTAMP WITHOUT TIME ZONE NOT NULL
        )
        """
        db.session.execute(text(create_sessions_table_sql))
        db.session.commit()
        # --- ΤΕΛΟΣ ΠΡΟΣΘΗΚΗΣ ---

        # --- ΕΛΕΓΧΟΣ ΚΑΙ MIGRATION ΓΙΑ avatar_url ---
        print("Έλεγχος για στήλη 'avatar_url' στον πίνακα 'user'...")
        try:
            db.session.query(User.avatar_url).limit(1).all()
            print("Η στήλη 'avatar_url' υπάρχει ήδη.")
        except ProgrammingError:
            print("Η στήλη 'avatar_url' δεν βρέθηκε. Προσθήκη...")
            db.session.rollback()
            
            try:
                # 🚨 Σημείωση: Αλλάζω το VARCHAR(200) σε VARCHAR(256) για συνέπεια
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN avatar_url VARCHAR(256)'))
                db.session.commit()
                print("Η στήλη 'avatar_url' προστέθηκε επιτυχώς.")
            except Exception as e:
                db.session.rollback()
                print(f"Σφάλμα κατά την προσθήκη της στήλης (ενδέχεται να έχει προστεθεί από άλλη διεργασία): {e}")

        # --- Έλεγχος για Default Ρυθμίσεις (Π.χ. chat_enabled) ---
        if not Setting.query.filter_by(key='chat_enabled').first():
            print("Προσθήκη ρύθμισης 'chat_enabled'...")
            default_setting = Setting(key='chat_enabled', value='true')
            db.session.add(default_setting)
            db.session.commit()
            print("Προστέθηκε ρύθμιση 'chat_enabled'.")
            
        print("Το Setup της βάσης δεδομένων ολοκληρώθηκε επιτυχώς.")

    except Exception as e:
        print(f"Σοβαρό σφάλμα κατά το setup της βάσης δεδομένων: {e}")
        db.session.rollback()
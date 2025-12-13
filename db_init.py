# Το script αρχικοποίησης της βάσης δεδομένων (π.χ. db_init.py)

import os
# Εισάγετε ό,τι χρειάζεστε από το server.py
from server import create_app, db, User, Settings, get_default_color_by_role, select 
from flask_migrate import upgrade
from werkzeug.security import generate_password_hash

# 1. Δημιουργία της εφαρμογής (Application Factory)
# ΠΡΟΣΟΧΗ: Αυτή η κλήση (create_app) εκτελείται πρώτη
app = create_app()

# 2. Είσοδος σε Application Context
# 🟢 Όλες οι ενέργειες που χρειάζονται το Flask (όπως η χρήση του 'db', 'url_for', ή 'upgrade')
#    ΠΡΕΠΕΙ να βρίσκονται μέσα σε αυτό το μπλοκ.
with app.app_context():
    print("--- 🛠️ Database Initialization Started ---")

    # 🚨 ΚΡΙΣΙΜΗ ΔΙΟΡΘΩΣΗ (ΒΗΜΑ 3): Δημιουργία όλων των πινάκων ως fallback/αρχική ρύθμιση
    # Αυτό εγγυάται ότι οι πίνακες υπάρχουν πριν από οποιοδήποτε query.
    try:
        db.create_all()
        print("✅ Database tables created/ensured successfully via db.create_all().")
    except Exception as e:
        # Αν η βάση έχει ήδη δεδομένα/σχήμα, αυτό μπορεί να αποτύχει. Είναι συνήθως ασφαλές να συνεχίσετε.
        print(f"⚠️ Warning: db.create_all() failed: {e}. If tables exist, this is normal.")

    # 4. Εκτέλεση μεταναστεύσεων (Flask-Migrate upgrade)
    try:
        upgrade()
        print("✅ Database migration (upgrade) completed successfully.")
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        # Αν το σφάλμα είναι κρίσιμο, μπορεί να χρειαστεί έξοδος

    # 5. Έλεγχος/Δημιουργία Owner χρήστη (Τώρα αυτό το query θα λειτουργήσει!)
    owner_role = 'owner'
    # Χρησιμοποιούμε select(User).filter_by για συμβατότητα με SQLAlchemy 2.0
    owner_check = db.session.execute(select(User).filter_by(role=owner_role)).first()
    
    if owner_check is None:
        print(f"⚠️ No '{owner_role}' user found. Creating initial Owner user.")
        
        # Λήψη credentials από Environment Variables
        initial_owner_username = os.environ.get('INITIAL_OWNER_USERNAME', 'owner')
        initial_owner_email = os.environ.get('INITIAL_OWNER_EMAIL', 'owner@example.com')
        # ΠΡΕΠΕΙ να οριστεί ισχυρή τιμή στο env var INITIAL_OWNER_PASSWORD
        initial_owner_password = os.environ.get('INITIAL_OWNER_PASSWORD', 'supersecurepassword')
        
        # ... (Λογική προειδοποίησης) ...
             
        initial_owner = User(
            display_name=initial_owner_username,
            email=initial_owner_email,
            password_hash=generate_password_hash(initial_owner_password),
            role=owner_role,
            # Η get_default_color_by_role είναι από το server.py
            color=get_default_color_by_role(owner_role)
        )
        db.session.add(initial_owner)
        db.session.commit()
        print(f"✅ Owner user '{initial_owner_username}' created successfully.")
    else:
        print(f"ℹ️ Owner user already exists: {owner_check[0].display_name}")

    # 6. Έλεγχος/Δημιουργία Global Settings
    settings_check = db.session.execute(select(Settings)).first()

    if settings_check is None:
        print("⚠️ No Global Settings found. Creating default settings.")
        default_settings = Settings()
        db.session.add(default_settings)
        db.session.commit()
        print("✅ Default settings created successfully.")
    else:
        print("ℹ️ Global Settings already exist.")
        
    print("--- 🏁 Database initialization complete ---")
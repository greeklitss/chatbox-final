# db_init.py

import os # 🚨 ΔΙΟΡΘΩΣΗ: Προσθέτουμε την εισαγωγή του 'os'
from werkzeug.security import generate_password_hash # Χρειάζεται για τη δημιουργία Owner
from server import create_app, db, User, Settings, get_default_color_by_role, select

# 1. Δημιουργία του αντικειμένου της εφαρμογής
app = create_app()

# 2. Είσοδος στο Application Context
with app.app_context():
    # 3. Δημιουργία πινάκων
    db.create_all()
    print("Database initialized or already exists.")

    # 4. Έλεγχος/Δημιουργία του Owner User
    owner_display_name = os.environ.get('OWNER_DISPLAY_NAME', 'Owner')
    
    # Χρησιμοποιούμε select() από την SQLAlchemy 2.0
    owner = db.session.execute(select(User).where(User.display_name == owner_display_name)).scalar_one_or_none()

    if not owner:
        # Αν δεν υπάρχει, δημιουργούμε τον Owner με ένα τυχαίο password
        owner_password = os.environ.get('OWNER_PASSWORD', 'default_secret_password')
        
        owner = User(
            display_name=owner_display_name,
            password_hash=generate_password_hash(owner_password),
            role='owner',
            color=get_default_color_by_role('owner') # Χρησιμοποιούμε τη συνάρτηση από server.py
        )
        db.session.add(owner)
        db.session.commit()
        print(f"Default Owner user '{owner_display_name}' created. Password: {owner_password}")

    # 5. Έλεγχος/Δημιουργία Global Settings (π.χ. CHAT_STATUS)
    settings_key = 'CHAT_STATUS'
    chat_status_setting = db.session.execute(select(Settings).where(Settings.key == settings_key)).scalar_one_or_none()
    
    if not chat_status_setting:
        new_setting = Settings(key=settings_key, value='on')
        db.session.add(new_setting)
        db.session.commit()
        print(f"Default setting '{settings_key}' created.")
# db_init.py (Τελική Έκδοση)

import os
from werkzeug.security import generate_password_hash
from server import create_app, db, User, Settings, get_default_color_by_role, select

app = create_app()

with app.app_context():
    # 🚨 ΣΗΜΕΙΩΣΗ: Η δημιουργία/αναβάθμιση του σχήματος (db.create_all()/flask db upgrade) 
    # θα εκτελεστεί από την εντολή Build του Render, ΟΧΙ εδώ.

    # 1. Έλεγχος/Δημιουργία του Owner User
    owner_display_name = os.environ.get('OWNER_DISPLAY_NAME', 'Owner')
    
    # Αυτή η γραμμή θα λειτουργήσει μόνο αφού γίνει το migration
    owner = db.session.execute(select(User).where(User.display_name == owner_display_name)).scalar_one_or_none()

    if not owner:
        # Αν δεν υπάρχει, δημιουργούμε τον Owner
        owner_password = os.environ.get('OWNER_PASSWORD', 'default_secret_password')
        
        owner = User(
            display_name=owner_display_name,
            password_hash=generate_password_hash(owner_password),
            role='owner',
            color=get_default_color_by_role('owner')
        )
        db.session.add(owner)
        db.session.commit()
        print(f"Default Owner user '{owner_display_name}' created.")

    # 2. Έλεγχος/Δημιουργία Global Settings
    settings_key = 'CHAT_STATUS'
    chat_status_setting = db.session.execute(select(Settings).where(Settings.key == settings_key)).scalar_one_or_none()
    
    if not chat_status_setting:
        new_setting = Settings(key=settings_key, value='on')
        db.session.add(new_setting)
        db.session.commit()
        print(f"Default setting '{settings_key}' created.")
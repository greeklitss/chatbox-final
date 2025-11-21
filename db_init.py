# db_init.py (Αυτό εκτελείται από το Render κατά το build)

import os
import sys
# Υποθέτουμε ότι το server.py βρίσκεται στον φάκελο src/
from server import create_app, db 

try:
    # 1. Δημιουργία App Instance
    app = create_app()

    # 2. Εκτέλεση εντολής βάσης δεδομένων εντός του Application Context
    with app.app_context():
        print("Initializing database tables (db.create_all())...")
        # Αυτό δημιουργεί όλους τους πίνακες αν δεν υπάρχουν (ασφαλές).
        db.create_all()
        print("Database initialization complete. Existing tables were preserved.")

except Exception as e:
    error_message = str(e)
    print(f"FATAL DB INIT ERROR: {error_message}", file=sys.stderr)
    
    # Επιτρέπουμε στο build να ολοκληρωθεί ακόμα και αν αποτύχει η αρχική σύνδεση
    if "password authentication failed" in error_message or "connection refused" in error_message or "InvalidRequestError" in error_message:
         print("Ignoring connection/authentication/model error during build, assuming it will resolve during runtime.")
    else:
        sys.exit(1) # Αποτυχία για σοβαρά σφάλματα κώδικα
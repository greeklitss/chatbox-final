import os
import sys

# Προσθέτουμε τον τρέχοντα φάκελο στο path για να βρούμε το server.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 🚨 Κρίσιμη εισαγωγή: Εισάγουμε όλα τα απαραίτητα μοντέλα και συναρτήσεις
try:
    # ΠΡΟΣΟΧΗ: Εισάγουμε και τα μοντέλα που χρησιμοποιούνται στο server.py
    from server import db, create_app, initialize_settings, initialize_emoticons, User, Message, Setting, Emoticon
    app = create_app()
except ImportError as e:
    print(f"FATAL ERROR: Could not import models/functions from server.py. Ensure server.py is updated.")
    print(f"Original Error: {e}")
    sys.exit(1)


def init_db():
    print("--- Starting Database Initialization ---")
    with app.app_context():
        try:
            # 1. Δημιουργία όλων των πινάκων (User, Message, Setting, Emoticon, Session)
            # Χρησιμοποιούμε try-except για να αγνοήσουμε τυχόν ProgrammingError (π.χ. αν ο πίνακας υπάρχει ήδη)
            try:
                db.create_all() 
                print("Successfully created all database tables.")
            except OperationalError as e:
                # Αυτό μπορεί να συμβεί σε κάποια περιβάλλοντα αν η db υπάρχει ήδη
                print(f"DB Warning: Could not create tables (might already exist): {e}")
            
            # 2. Αρχικοποίηση default ρυθμίσεων
            initialize_settings()
            print("Settings initialized.")
            
            # 3. Αρχικοποίηση default emoticons
            # 🚨 Τώρα θα εισαχθούν οι νέοι CDN σύνδεσμοι
            initialize_emoticons()
            print("Emoticons initialized with CDN links.")
            
        except Exception as e:
            print(f"An error occurred during DB initialization: {e}")
            sys.exit(1)

    print("--- Database Initialization Complete ---")

if __name__ == '__main__':
    init_db()
# db_init.py
import os
import sys

# Προσθέτουμε τον τρέχοντα φάκελο στο path για να βρούμε το server.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 🚨 Κρίσιμη εισαγωγή: Εισάγουμε όλα τα απαραίτητα μοντέλα και συναρτήσεις
try:
    from server import db, app, initialize_settings, initialize_emoticons, User, Message, Setting, Emoticon
except ImportError as e:
    print(f"FATAL ERROR: Could not import models/functions from server.py. Ensure server.py is updated.")
    print(f"Original Error: {e}")
    sys.exit(1)


def init_db():
    print("--- Starting Database Initialization ---")
    with app.app_context():
        try:
            # 1. Δημιουργία όλων των πινάκων (User, Message, Setting, Emoticon, Session)
            db.create_all() 
            print("Successfully created all database tables.")
            
            # 2. Αρχικοποίηση default ρυθμίσεων
            initialize_settings()
            print("Settings initialized.")
            
            # 3. Αρχικοποίηση default emoticons
            initialize_emoticons()
            print("Emoticons initialized.")
            
        except Exception as e:
            print(f"An error occurred during DB initialization: {e}")
            sys.exit(1)
            
    print("--- Database Initialization Complete ---")


if __name__ == '__main__':
    init_db()
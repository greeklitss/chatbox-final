import os
import sys

# Προσθέτουμε τον τρέχοντα φάκελο στο path για να βρούμε το server.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 🚨 Κρίσιμη εισαγωγή: Εισάγουμε όλα τα απαραίτητα μοντέλα και συναρτήσεις
try:
    # 💡 ΔΙΟΡΘΩΣΗ: Εισάγουμε τη συνάρτηση create_app() αντί για την app
    # και το μοντέλο Settings (αν δεν υπήρχε)
    from server import db, create_app, initialize_settings, initialize_emoticons, User, Message, Setting, Emoticon 
except ImportError as e:
    print(f"FATAL ERROR: Could not import models/functions from server.py. Ensure server.py is updated.")
    print(f"Original Error: {e}")
    sys.exit(1)


def init_db():
    # 🚨 ΚΡΙΣΙΜΟ: Καλούμε την create_app() για να πάρουμε την instance του app 
    # και να δημιουργήσουμε το application context.
    # Αυτό ΔΕΝ προκαλεί διπλή αρχικοποίηση, καθώς δεν καλείται η socketio.run().
    app = create_app() 
    
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
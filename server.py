    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('chat_page'))
        return render_template('index.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login_page():
        if current_user.is_authenticated: return redirect(url_for('chat_page'))
        if request.method == 'POST':
            user = User.query.filter_by(display_name=request.form.get('username')).first()
            if user and user.check_password(request.form.get('password')):
                login_user(user, remember=True)
                return redirect(url_for('chat_page'))
            flash('Λάθος στοιχεία.')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login_page'))

    @app.route('/google_login')
    def google_login():
        nonce = secrets.token_urlsafe(16)
        session['nonce'] = nonce
        redirect_uri = url_for('google_auth', _external=True, _scheme='https')
        return oauth.google.authorize_redirect(url_for('google_auth', _external=True), nonce=nonce)

    @app.route('/google_auth')
    def google_auth():
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token, nonce=session.pop('nonce', None))
        user = User.query.filter_by(email=user_info.get('email')).first()
        if not user:
            user = User(email=user_info.get('email'), display_name=user_info.get('name'), 
                        role='user', color=random.choice(CHAT_COLORS), avatar_url=user_info.get('picture'))
            db.session.add(user)
            db.session.commit()
        login_user(user, remember=True)
        return redirect(url_for('chat_page'))

    @app.route('/chat')
    @login_required
    def chat_page():
        # Φόρτωση ιστορικού (τελευταία 50 μηνύματα)
        history = Message.query.order_by(Message.timestamp.asc()).limit(50).all()
        return render_template('chat.html', 
                             display_name=current_user.display_name, 
                             role=current_user.role, 
                             color=current_user.color, 
                             avatar_url=current_user.avatar_url,
                             history=history)

    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            ONLINE_USERS[request.sid] = {
                'id': current_user.id, 
                'display_name': current_user.display_name, 
                'role': current_user.role, 
                'color': current_user.color, 
                'avatar_url': current_user.avatar_url
            }
            emit('users_update', get_online_users_list(), broadcast=True)

    @socketio.on('disconnect')
    def handle_disconnect():
        if request.sid in ONLINE_USERS:
            del ONLINE_USERS[request.sid]
            emit('users_update', get_online_users_list(), broadcast=True)

    @socketio.on('message')
    def handle_message(data):
        if current_user.is_authenticated:
            # Αποθήκευση στη βάση
            new_msg = Message(content=data['content'], author=current_user)
            db.session.add(new_msg)
            db.session.commit()
            
            # Αποστολή real-time
            emit('message', {
                'display_name': current_user.display_name, 
                'content': data['content'], 
                'color': current_user.color, 
                'avatar_url': current_user.avatar_url
            }, broadcast=True)

    @socketio.on('update_profile')
    def update_profile(data):
        if current_user.is_authenticated:
            user = User.query.get(current_user.id)
            if 'new_avatar' in data: user.avatar_url = data['new_avatar']
            db.session.commit()
            emit('profile_updated', broadcast=True)

    @socketio.on('clear_chat_request')
    def clear_chat():
        if current_user.is_authenticated and current_user.role == 'owner':
            Message.query.delete()
            db.session.commit()
            emit('clear_chat_client', broadcast=True)

    with app.app_context():
        db.create_all()

    return app

app = create_app()

if __name__ == '__main__':

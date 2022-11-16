import os

from flask import Flask, render_template, request, flash, redirect, session, g, url_for
#from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from forms import UserAddForm, LoginForm, MessageForm, UserProfileForm, UserProfileAdminForm, PasswordResetForm
from models import db, connect_db, User, Message, Likes, PrivateAccountRequests
from functools import wraps

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

# Get DB_URI from environ variable (useful for production/testing) or,
# if not set there, use development local db.
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL', 'postgresql:///warbler'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
#app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "it's a secret")
#toolbar = DebugToolbarExtension(app)

connect_db(app)

##############################################################################
# User signup/login/logout


@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])
    else:
        g.user = None
    

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

def login_required(f):
    @wraps(f)

    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash("You need to be logged in to perform that operation.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id


def do_logout():
    """Logout user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]


@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If the there already is a user with that username: flash message
    and re-present form.
    """

    form = UserAddForm()

    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                image_url=form.image_url.data or User.image_url.default.arg,
            )
            db.session.commit()

        except IntegrityError:
            flash("Username already taken", 'danger')
            return render_template('users/signup.html', form=form)

        do_login(user)

        return redirect(url_for('homepage'))

    else:
        return render_template('users/signup.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Handle user login."""

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(form.username.data,
                                 form.password.data)

        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
            return redirect(url_for('homepage'))

        flash("Invalid credentials.", 'danger')

    return render_template('users/login.html', form=form)


@app.route('/logout')
def logout():
    """Handle logout of user."""

    do_logout()

    flash('You have successfully logged out of the application.', 'success')

    return redirect(url_for('login'))


##############################################################################
# General user routes:

@app.route('/users')
def list_users():
    """Page with listing of users.

    Can take a 'q' param in querystring to search by that username.
    """

    search = request.args.get('q')

    if not search:
        users = User.query.all()
    else:
        users = User.query.filter(User.username.like(f"%{search}%")).all()

    return render_template('users/index.html', users=users)


@app.route('/users/<int:user_id>')
@login_required
def users_show(user_id):
    """Show user profile."""

    user = User.query.get_or_404(user_id)
    
    # snagging messages in order from the database;
    # user.messages won't be in order by default
    messages = (Message
                .query
                .filter(Message.user_id == user_id)
                .order_by(Message.timestamp.desc())
                .limit(100)
                .all())

    if user.private and user != g.user:
        req = PrivateAccountRequests.query.filter_by(requesting_user_id=g.user.id, private_user_id=user.id).one_or_none()
        if req != None:
            if req.approved:
                return render_template('users/show.html', user=user, messages=messages)
            else:
                return render_template('users/show.html', user=user, messages=[])
        else: 
            return render_template('users/show.html', user=user, messages=[])   
    elif g.user.admin:
        return render_template('users/show.html', user=user, messages=messages)
    else:
        return render_template('users/show.html', user=user, messages=messages)



@app.route('/users/<int:user_id>/reset_password', methods=["GET", "POST"])
@login_required
def reset_password(user_id):
    """Handle user password change form"""

    if user_id != g.user.id and not g.user.admin:
        return render_template('401.html'), 401
    form = PasswordResetForm()

    if form.validate_on_submit():
        if form.current_password.data == form.new_password.data:
            flash("New password can't match the old one. Please try again.", 'danger')
            return redirect(url_for('users_show', user_id=user_id))
            
        user = User.authenticate(g.user.username, form.current_password.data)
        if user:
            if form.new_password.data == form.confirm_password.data:        
                User.change_password(user, form.new_password.data)
                flash("Password successfully updated!", 'success')
                return redirect(url_for('homepage'))
            else:
                flash("New passwords don't match. Please try again.", 'danger')
                return redirect(request.referrer)
        else: 
            flash('Unable to authenticate. Please try again.', 'danger')
            return redirect(request.referrer)

    return render_template('users/reset_password.html', form=form)

@app.route('/users/<int:user_id>/likes')
def show_likes(user_id):

    messages = User.query.get_or_404(user_id).likes
    return render_template('/users/likes.html', user=g.user, messages=messages)

@app.route('/users/<int:user_id>/following')
@login_required
def show_following(user_id):
    """Show list of people this user is following."""

    user = User.query.get_or_404(user_id)
    return render_template('users/following.html', user=user)


@app.route('/users/<int:user_id>/followers')
@login_required
def show_followers(user_id):
    """Show list of followers of this user."""

    user = User.query.get_or_404(user_id)
    return render_template('users/followers.html', user=user)

@app.route('/users/<int:user_id>/follow_requests')
@login_required
def follow_requests(user_id):
    """Show list of accounts wishing to follow a user's private account"""

    user = User.query.get_or_404(user_id)
    approvals = PrivateAccountRequests.query.filter_by(private_user_id=user_id).filter_by(approved=False).all()

    unapproved_requests = [User.query.get(approval.requesting_user_id) for approval in approvals]

    return render_template('users/follow_requests.html', user=user, requests=unapproved_requests)

@app.route('/users/<int:follow_id>/follow_requests/approve', methods=["POST"])
def approve_request(follow_id):
    req = PrivateAccountRequests.query.get_or_404((follow_id, g.user.id))
    req.approved = True
    db.session.add(req)
    new_follower = User.query.get_or_404(follow_id)
    new_follower.following.append(g.user)
    db.session.commit()

    flash(f'{new_follower.username} can now see your posts!', 'success')

    return redirect(request.referrer)

@app.route('/users/follow/<int:follow_id>', methods=['POST'])
@login_required
def add_follow(follow_id):
    """Add a follow for the currently-logged-in user."""

    followed_user = User.query.get_or_404(follow_id)

    if followed_user.private:
        req = PrivateAccountRequests(requesting_user_id=g.user.id, private_user_id=follow_id, approved=False)
        db.session.add(req)
        flash('The account you wish to follow is private. Once they have approved your follow request, you will be able to view their posts.', 'success')
    else:
        g.user.following.append(followed_user)
    db.session.commit()

    return redirect(request.referrer)


@app.route('/users/stop-following/<int:follow_id>', methods=['POST'])
@login_required
def stop_following(follow_id):
    """Have currently-logged-in-user stop following this user."""

    followed_user = User.query.get_or_404(follow_id)
    g.user.following.remove(followed_user)
    db.session.commit()

    return redirect(url_for('show_following', user_id=g.user.id))


@app.route('/users/profile/<int:user_id>', methods=["GET", "POST"])
def profile(user_id):
    """Update profile for current user."""

    if user_id != g.user.id and not g.user.admin:
        return render_template('401.html'), 401

    user = User.query.get_or_404(user_id)
    form = None
    
    if g.user.admin:
        form = UserProfileAdminForm(obj=user)
    else:
        form = UserProfileForm(obj=user)

    if form.validate_on_submit():
        if not g.user.admin:
            user = User.authenticate(form.username.data,
                                    form.password.data)

        if user:
            #data = {k: v for k, v in form.data.items() if k not in ("csrf_token", 'Password')}
            #user = User(**data)
            if user.username != form.username.data:
                user.username = form.username.data
            if user.email != form.email.data:
                user.email = form.email.data
            if user.image_url != form.image_url.data:
                user.image_url = form.image_url.data
            if user.header_image_url != form.header_image_url.data:
                user.header_image_url = form.header_image_url.data
            if user.location != form.location.data:
                user.location = form.location.data
            if user.bio != form.bio.data:
                user.bio = form.bio.data
            if user.private != form.private.data:
                user.private = form.private.data
            if g.user.admin:
                user.admin = form.admin.data

            db.session.add(user)
            db.session.commit()

            return redirect(url_for('users_show', user_id=user.id))
        else:
            flash("Bad password. Profile not updated. Please try again!", 'danger')
            return redirect(request.referrer)

    return render_template('users/edit.html', form=form, id=user.id)


@app.route('/users/manage_likes/<int:message_id>', methods=['POST'])
@login_required
def manage_like(message_id):

    user_id = g.user.id
    liked_msg = Likes.query.filter_by(message_id=message_id).filter_by(user_id=user_id).one_or_none()

    if liked_msg == None:
        like = Likes(user_id=user_id, message_id=message_id)
        db.session.add(like)
    else:
        db.session.delete(liked_msg)
    db.session.commit()

    return redirect(request.referrer)

@app.route('/users/delete/<int:user_id>', methods=["POST"])
@login_required
def delete_user(user_id):
    """Delete user."""

    if user_id != g.user.id and not g.user.admin:
        return render_template('401.html'), 401

    if not g.user.admin:
        do_logout()

    db.session.delete(User.query.get_or_404(user_id))
    db.session.commit()

    return redirect(url_for('homepage'))


##############################################################################
# Messages routes:

@app.route('/messages/new', methods=["GET", "POST"])
@login_required
def messages_add():
    """Add a message:

    Show form if GET. If valid, update message and redirect to user page.
    """

    form = MessageForm()

    if form.validate_on_submit():
        msg = Message(text=form.text.data)
        g.user.messages.append(msg)
        db.session.commit()

        return redirect(url_for('users_show', user_id=g.user.id))

    return render_template('messages/new.html', form=form)


@app.route('/messages/<int:message_id>', methods=["GET"])
def messages_show(message_id):
    """Show a message."""

    msg = Message.query.get_or_404(message_id)
    return render_template('messages/show.html', message=msg)


@app.route('/messages/<int:message_id>/delete', methods=["POST"])
@login_required
def messages_destroy(message_id):
    """Delete a message."""

    msg = Message.query.get_or_404(message_id)
    id = msg.user.id
    if msg.user_id != g.user.id and not g.user.admin:
        return render_template('401.html'), 401

    db.session.delete(msg)
    db.session.commit()

    return redirect(url_for('users_show', user_id=id))


##############################################################################
# Homepage and error pages


@app.route('/')
def homepage():
    """Show homepage:

    - anon users: no messages
    - logged in: 100 most recent messages of followed_users
    """

    if g.user:
        following = [following.id for following in g.user.following]
        messages = (Message.query.filter( (Message.user_id == g.user.id) | (Message.user_id.in_(following)) )
                .order_by(Message.timestamp.desc()).limit(100).all())
        
        if not g.user.admin:
            not_approved = PrivateAccountRequests.query.filter_by(requesting_user_id=g.user.id).filter_by(approved=False).all()
            messages = [message for message in messages if message.user.id not in [na.private_user_id for na in not_approved]]

        return render_template('home.html', messages=messages)

    else:
        return render_template('home-anon.html')

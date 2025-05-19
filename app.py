from flask import Flask, flash, render_template, request, redirect, url_for, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, generate_csrf
import logging

app = Flask(__name__)
app.config.from_object('config.Config')

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

from models import User, Event, UserRole, EventStatus, Like, Notification, RSVP
from forms import LoginForm, RegistrationForm, EventForm, ProfileForm

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    events_query = Event.query.filter_by(status=EventStatus.APPROVED).order_by(Event.date, Event.time)
    category = request.args.get('category')
    date_filter = request.args.get('date')
    if category:
        events_query = events_query.filter_by(category=category)
    if date_filter:
        events_query = events_query.filter(Event.date == date.fromisoformat(date_filter))
    events = events_query.paginate(page=page, per_page=per_page, error_out=False)
    categories = sorted(set(event.category for event in Event.query.all() if event.category))
    panel_type = 'Admin Panel' if current_user.role == UserRole.ADMIN else 'Dashboard'
    if current_user.role == UserRole.ADMIN:
        return render_template('index_admin.html', events=events, categories=categories, category_filter=category, date_filter=date_filter, panel_type=panel_type)
    return render_template('index.html', events=events, categories=categories, category_filter=category, date_filter=date_filter, panel_type=panel_type)
@app.route('/api/events', methods=['GET'])
def get_events():
    query = Event.query.filter_by(status=EventStatus.APPROVED)
    category = request.args.get('category')
    date = request.args.get('date')
    
    if category:
        query = query.filter_by(category=category)
    if date:
        try:
            date_obj = datetime.strptime(date, '%Y-%m-%d').date()
            query = query.filter(Event.date == date_obj)
        except ValueError:
            logger.error(f"Invalid date format: {date}")
            pass
    
    events = query.order_by(Event.date, Event.time).all()
    
    events_data = [
        {
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'date': event.date.strftime('%Y-%m-%d'),
            'time': event.time.strftime('%H:%M'),
            'location': event.location,
            'category': event.category,
            'organizer': event.organizer.email,
            'likes': len(event.likes),
            'rsvps': len(event.rsvps)
        } for event in events
    ]
    
    return jsonify(events_data)

@app.route('/api/events', methods=['POST'])
@login_required
def create_event():
    data = request.get_json()
    
    try:
        event = Event(
            title=data['title'],
            description=data['description'],
            date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
            time=datetime.strptime(data['time'], '%H:%M').time(),
            location=data['location'],
            category=data['category'],
            status=EventStatus.PENDING,
            user_id=current_user.id
        )
        db.session.add(event)
        db.session.commit()
        logger.info(f"Event created: {event.title} by {current_user.email}")
        return jsonify({'message': 'Event created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating event: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/events/<int:event_id>', methods=['GET'])
def get_event(event_id):
    event = Event.query.get_or_404(event_id)
    liked = False
    rsvped = False
    if current_user.is_authenticated:
        liked = Like.query.filter_by(user_id=current_user.id, event_id=event_id).first() is not None
        rsvped = RSVP.query.filter_by(user_id=current_user.id, event_id=event_id).first() is not None
    try:
        return jsonify({
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'date': event.date.strftime('%Y-%m-%d'),
            'time': event.time.strftime('%H:%M'),
            'location': event.location,
            'category': event.category,
            'organizer': event.organizer.email,
            'likes': len(event.likes),
            'liked': liked,
            'rsvps': len(event.rsvps),
            'rsvped': rsvped
        })
    except Exception as e:
        logger.error(f"Error fetching event {event_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/events/<int:event_id>', methods=['PUT'])
@login_required
def update_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    if event.organizer.id != current_user.id and current_user.role != UserRole.ADMIN:
        logger.warning(f"Unauthorized update attempt by {current_user.email} on event {event_id}")
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    try:
        event.title = data.get('title', event.title)
        event.description = data.get('description', event.description)
        event.date = datetime.strptime(data.get('date'), '%Y-%m-%d').date() if data.get('date') else event.date
        event.time = datetime.strptime(data.get('time'), '%H:%M').time() if data.get('time') else event.time
        event.location = data.get('location', event.location)
        event.category = data.get('category', event.category)
        
        db.session.commit()
        logger.info(f"Event {event_id} updated by {current_user.email}")
        return jsonify({'message': 'Event updated successfully'})
    except ValueError as e:
        logger.error(f"Invalid date/time format: {str(e)}")
        return jsonify({'error': 'Invalid date or time format'}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating event {event_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/events/<int:event_id>/delete', methods=['POST'])
@login_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    if event.organizer.id != current_user.id and current_user.role != UserRole.ADMIN:
        logger.warning(f"Unauthorized delete attempt by {current_user.email} on event {event_id}")
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        db.session.delete(event)
        db.session.commit()
        logger.info(f"Event {event_id} deleted by {current_user.email}")
        return jsonify({'message': 'Event deleted successfully'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting event {event_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/events/<int:event_id>/like', methods=['POST'])
@login_required
def like_event(event_id):
    event = Event.query.get_or_404(event_id)

    if event.status != EventStatus.APPROVED:
        logger.warning(f"Attempt to like unapproved event {event_id} by {current_user.email}")
        return jsonify({'error': 'Can only like approved events'}), 400

    existing_like = Like.query.filter_by(user_id=current_user.id, event_id=event_id).first()
    
    try:
        if existing_like:
            # Remove like
            db.session.delete(existing_like)

            # Also remove the related notification
            notification = Notification.query.filter_by(
                user_id=event.organizer.id,
                event_id=event.id,
                message=f"{current_user.username} liked your event '{event.title}'"
            ).first()

            if notification:
                db.session.delete(notification)

            db.session.commit()
            logger.info(f"Like removed from event {event_id} by {current_user.email}")
            return jsonify({'message': 'Like removed', 'likes': len(event.likes), 'liked': False})

        else:
            # Add like
            like = Like(user_id=current_user.id, event_id=event_id)
            db.session.add(like)

            # Add notification only if organizer is not the one liking
            if event.organizer.id != current_user.id:
                existing_notification = Notification.query.filter_by(
                    user_id=event.organizer.id,
                    event_id=event.id,
                    message=f"{current_user.username} liked your event '{event.title}'"
                ).first()

                if not existing_notification:
                    notification = Notification(
                        user_id=event.organizer.id,
                        message=f"{current_user.username} liked your event '{event.title}'",
                        event_id=event.id
                    )
                    db.session.add(notification)

            db.session.commit()
            logger.info(f"Event {event_id} liked by {current_user.email}")
            return jsonify({'message': 'Event liked', 'likes': len(event.likes), 'liked': True})

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing like for event {event_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/events/<int:event_id>/rsvp', methods=['POST'])
@login_required
def rsvp_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event.status != EventStatus.APPROVED:
        logger.warning(f"Attempt to RSVP unapproved event {event_id} by {current_user.email}")
        return jsonify({'error': 'Can only RSVP approved events'}), 400
    
    existing_rsvp = RSVP.query.filter_by(user_id=current_user.id, event_id=event_id).first()
    
    try:
        if existing_rsvp:
            db.session.delete(existing_rsvp)
            db.session.commit()
            logger.info(f"RSVP removed from event {event_id} by {current_user.email}")
            return jsonify({'message': 'RSVP removed', 'rsvps': len(event.rsvps), 'rsvped': False})
        else:
            rsvp = RSVP(user_id=current_user.id, event_id=event_id)
            db.session.add(rsvp)
            if event.organizer.id != current_user.id:
                notification = Notification(
                    user_id=event.organizer.id,
                    message=f"{current_user.email} RSVP'd to your event '{event.title}'",
                    event_id=event.id
                )
                db.session.add(notification)
            db.session.commit()
            logger.info(f"Event {event_id} RSVP'd by {current_user.email}")
            return jsonify({'message': 'RSVP confirmed', 'rsvps': len(event.rsvps), 'rsvped': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing RSVP for event {event_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/notifications', methods=['GET'])
@login_required
def get_notifications():
    try:
        notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()
        logger.info(f"Fetched {len(notifications)} notifications for {current_user.email}")
        return jsonify([
            {
                'id': n.id,
                'message': n.message,
                'created_at': n.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'event_id': n.event_id
            } for n in notifications
        ])
    except Exception as e:
        logger.error(f"Error fetching notifications for {current_user.email}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/notifications/<int:notification_id>/dismiss', methods=['POST'])
@login_required
def dismiss_notification(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        logger.warning(f"Unauthorized dismiss attempt by {current_user.email} on notification {notification_id}")
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        notification.is_read = True
        db.session.commit()
        logger.info(f"Notification {notification_id} dismissed by {current_user.email}")
        return jsonify({'message': 'Notification dismissed'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error dismissing notification {notification_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(email=form.email.data, username=form.email.data.split('@')[0], password_hash=hashed_password)
        try:
            db.session.add(user)
            db.session.commit()
            login_user(user)
            logger.info(f"User registered and logged in: {user.email}")
            flash('Registration successful! Welcome!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error registering user {form.email.data}: {str(e)}")
            flash('Error: Email or username may already be in use.', 'danger')
    
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{field.capitalize()}: {error}", 'danger')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            try:
                login_user(user, remember=form.remember.data)
                logger.info(f"User logged in successfully: {user.email}, is_active: {user.is_active}")
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                logger.error(f"Error logging in user {user.email}: {str(e)}")
                flash('Error during login.', 'danger')
        else:
            logger.warning(f"Failed login attempt for {form.email.data}")
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logger.info(f"User logged out: {current_user.email}")
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/create_event_page', methods=['GET', 'POST'])
@login_required
def create_event_page():
    form = EventForm()
    
    if form.validate_on_submit():
        event = Event(
            title=form.title.data,
            description=form.description.data,
            date=form.date.data,
            time=form.time.data,
            location=form.location.data,
            category=form.category.data,
            user_id=current_user.id,
            status=EventStatus.PENDING
        )
        try:
            db.session.add(event)
            db.session.commit()
            logger.info(f"Event created: {event.title} by {current_user.email}")
            flash('Event created and pending approval!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating event: {str(e)}")
            flash('Error creating event.', 'danger')
    role= 'admin' if current_user.role == UserRole.ADMIN else 'user'
    return render_template('create_event.html', form=form, role=role)

@app.route('/edit_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_event_page(event_id):
    event = Event.query.get_or_404(event_id)
    
    if event.organizer.id != current_user.id and current_user.role != UserRole.ADMIN:
        logger.warning(f"Unauthorized edit attempt by {current_user.email} on event {event_id}")
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))
    
    form = EventForm(obj=event)
    
    if form.validate_on_submit():
        try:
            event.title = form.title.data
            event.description = form.description.data
            event.date = form.date.data
            event.time = form.time.data
            event.location = form.location.data
            event.category = form.category.data
            db.session.commit()
            logger.info(f"Event {event_id} updated by {current_user.email}")
            flash('Event updated successfully!', 'success')
            return redirect(url_for('get_event_page', event_id=event.id))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating event {event_id}: {str(e)}")
            flash('Error updating event.', 'danger')
    
    return render_template('edit_event.html', form=form, event=event)

@app.route('/events/<int:event_id>')
@login_required
def get_event_page(event_id):
    event = Event.query.get_or_404(event_id)
    role= 'admin' if current_user.role == UserRole.ADMIN else 'user'
    return render_template('event.html', event=event,role=role)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == UserRole.ADMIN:
        return redirect(url_for('admin_dashboard'))
    return render_template('dashboard.html', events=current_user.events)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    
    if form.validate_on_submit():
        try:
            current_user.username = form.username.data
            current_user.email = form.email.data
            if form.password.data:
                current_user.password_hash = generate_password_hash(form.password.data)
            db.session.commit()
            logger.info(f"Profile updated for {current_user.email}")
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating profile for {current_user.email}: {str(e)}")
            flash('Error updating profile: Email or username may already be in use.', 'danger')
    if current_user.role==UserRole.ADMIN:
        return render_template('profile.html', form=form, user=current_user, role='admin')
    return render_template('profile.html', form=form, user=current_user,role='user')

@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_profile():
    try:
        Event.query.filter_by(user_id=current_user.id).delete()
        db.session.delete(current_user)
        db.session.commit()
        logger.info(f"Account deleted: {current_user.email}")
        logout_user()
        return jsonify({'message': 'Account deleted successfully'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting account {current_user.email}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != UserRole.ADMIN:
        logger.warning(f"Unauthorized admin dashboard access by {current_user.email}")
        abort(403)
    
    pending_events = Event.query.filter_by(status=EventStatus.PENDING).all()
    return render_template('admin.html', events=pending_events)

@app.route('/admin/events/<int:event_id>/<action>', methods=['GET', 'POST'])
@login_required
def admin_event_action(event_id, action):
    if current_user.role != UserRole.ADMIN:
        logger.warning(f"Unauthorized admin action by {current_user.email} on event {event_id}")
        return jsonify({'error': 'Unauthorized'}), 403
    
    event = Event.query.get_or_404(event_id)
    
    try:
        if action == 'approve':
            event.status = EventStatus.APPROVED
            notification = Notification(
                user_id=event.organizer.id,
                message=f"Your event '{event.title}' has been approved",
                event_id=event.id
            )
            db.session.add(notification)
            db.session.commit()
            logger.info(f"Event {event_id} approved by {current_user.email}")
            return jsonify({'message': 'Event approved successfully'})
        elif action == 'reject':
            notification = Notification(
                user_id=event.organizer.id,
                message=f"Your event '{event.title}' has been rejected and deleted",
                event_id=None
            )
            db.session.add(notification)
            db.session.delete(event)
            db.session.commit()
            logger.info(f"Event {event_id} rejected and deleted by {current_user.email}")
            return jsonify({'message': 'Event rejected and deleted successfully'})
        else:
            logger.error(f"Invalid action {action} on event {event_id}")
            return jsonify({'error': 'Invalid action'}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing admin action {action} on event {event_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/events')
@login_required
def all_events():
    if current_user.role != UserRole.ADMIN:
        logger.warning(f"Unauthorized all events access by {current_user.email}")
        abort(403)
    
    events = Event.query.order_by(Event.date).all()
    role= 'admin' if current_user.role == UserRole.ADMIN else 'user'
    return render_template('all_events.html', events=events,role=role)

@app.route('/admin/events/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_event(event_id):
    if current_user.role != UserRole.ADMIN:
        logger.warning(f"Unauthorized admin edit attempt by {current_user.email} on event {event_id}")
        abort(403)
    
    event = Event.query.get_or_404(event_id)
    form = EventForm(obj=event)
    
    if form.validate_on_submit():
        try:
            form.populate_obj(event)
            db.session.commit()
            logger.info(f"Event {event_id} edited by admin {current_user.email}")
            flash('Event updated successfully!', 'success')
            return redirect(url_for('all_events'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error editing event {event_id}: {str(e)}")
            flash('Error updating event.', 'danger')
    
    return render_template('admin_edit_event.html', form=form, event=event)

@app.route('/get-csrf-token', methods=['GET'])
def get_csrf_token():
    try:
        return jsonify({'csrf_token': generate_csrf()})
    except Exception as e:
        logger.error(f"Error generating CSRF token: {str(e)}")
        return jsonify({'error': str(e)}), 500
@app.cli.command("create-admin")
def create_admin():
    """Create an admin user."""
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if admin is None:
            admin = User(
                username='admin',
                email='ine_event@admin.ma',
                password_hash=generate_password_hash('12345678'),
                role=UserRole.ADMIN
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created successfully!")
        else:
            print("⚠️ Admin user already exists.")

if __name__ == '__main__':
    app.config['DEBUG'] = True
    app.run(debug=True)
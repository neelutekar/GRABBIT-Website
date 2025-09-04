import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from models import db, User, Listing
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    q = request.args.get('q')
    category = request.args.get('category')
    listings = Listing.query
    if q:
        listings = listings.filter(Listing.title.contains(q))
    if category:
        listings = listings.filter_by(category=category)
    listings = listings.all()
    return render_template('index.html', listings=listings)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome, {user.username}!')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_listing():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        category = request.form['category']
        image = request.files['image']
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        listing = Listing(title=title, description=description, price=price,
                          category=category, image=filename, user_id=current_user.id)
        db.session.add(listing)
        db.session.commit()
        flash("Ad posted successfully!")

        return redirect(url_for('index'))
    return render_template('create_listing.html')

@app.route('/listing/<int:listing_id>')
def listing_detail(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    return render_template('listing_detail.html', listing=listing)

@app.route('/profile')
@login_required
def profile():
    user = current_user
    user_listings = Listing.query.filter_by(owner=user).all()
    return render_template('profile.html', user=user, listings=user_listings)

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        new_username = request.form.get('username')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')

        # Update username
        if new_username and new_username != current_user.username:
            if User.query.filter_by(username=new_username).first():
                flash('Username already taken.', 'danger')
            else:
                current_user.username = new_username
                flash('Username updated.', 'success')

        # Update password
        if current_password and new_password:
            if check_password_hash(current_user.password, current_password):
                current_user.password = generate_password_hash(new_password)
                flash('Password updated successfully.', 'success')
            else:
                flash('Current password is incorrect.', 'danger')

        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=current_user)

@app.route('/listing/<int:listing_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    if listing.owner != current_user:
        flash('You are not authorized to edit this listing.', 'danger')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        listing.title = request.form['title']
        listing.description = request.form['description']
        listing.price = float(request.form['price'])
        listing.category = request.form['category']
        db.session.commit()
        flash('Listing updated successfully.', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_listing.html', listing=listing)

@app.route('/listing/<int:listing_id>/delete', methods=['POST'])
@login_required
def delete_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    if listing.owner != current_user:
        flash('You are not authorized to delete this listing.', 'danger')
        return redirect(url_for('profile'))

    db.session.delete(listing)
    db.session.commit()
    flash('Listing deleted successfully.', 'success')
    return redirect(url_for('profile'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

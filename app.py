from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object('config.Config')
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_name = db.Column(db.String(150), nullable=False)
    item_name = db.Column(db.String(150), nullable=False)
    item_description = db.Column(db.String(500), nullable=False)
    item_price = db.Column(db.Float, nullable=False)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        return redirect(url_for('menu_form'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            return redirect(url_for('menu_form'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/menu_form', methods=['GET', 'POST'])
def menu_form():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        restaurant_name = request.form['restaurant_name']
        item_name = request.form['item_name']
        item_description = request.form['item_description']
        item_price = request.form['item_price']
        new_item = MenuItem(
            restaurant_name=restaurant_name,
            item_name=item_name,
            item_description=item_description,
            item_price=item_price
        )
        db.session.add(new_item)
        db.session.commit()
        flash('Menu item added successfully', 'success')
    return render_template('menu_form.html')

@app.route('/menu_items')
def menu_items():
    items = MenuItem.query.all()
    return render_template('menu_items.html', items=items)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=1654)

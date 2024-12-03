from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)  # Store the hashed password

    def set_password(self, password):
        # Generate a hash for the password
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Verify the password against the hashed password
        return check_password_hash(self.password_hash, password)

# Todo model
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class TodoForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    submit = SubmitField('Save Todo')

# Load user for login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))

        user = User(username=form.username.data)
        user.set_password(form.password.data)  # Hash the password
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):  # Check the hashed password
            login_user(user)
            return redirect(url_for('index'))
        flash('Login failed. Check your username and password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Log out the current user
    flash('You have been logged out successfully!')  # Flash message to inform the user
    return redirect(url_for('login'))  # Redirect to the login page


@app.route('/', methods=['GET', 'POST'])  # Ensure POST is allowed
@login_required
def index():
    todos = Todo.query.filter_by(user_id=current_user.id).all()
    form = TodoForm()
    if form.validate_on_submit():  # Check if form was submitted and is valid
        todo = Todo(title=form.title.data, user_id=current_user.id)
        db.session.add(todo)
        db.session.commit()
        flash('Task added successfully!')
        return redirect(url_for('index'))
    return render_template('index.html', todos=todos, form=form)

@app.route('/edit/<int:todo_id>', methods=['GET', 'POST'])
@login_required
def edit(todo_id):
    todo = Todo.query.get(todo_id)
    if todo and todo.user_id == current_user.id:
        form = TodoForm(title=todo.title)
        if form.validate_on_submit():
            todo.title = form.title.data
            db.session.commit()
            flash('Todo updated successfully.')
            return redirect(url_for('index'))
        return render_template('edit.html', form=form)
    else:
        flash('You are not authorized to edit this todo.')
        return redirect(url_for('index'))

@app.route('/delete/<int:todo_id>')
@login_required
def delete(todo_id):
    todo = Todo.query.get(todo_id)
    if todo and todo.user_id == current_user.id:
        db.session.delete(todo)
        db.session.commit()
        flash('Todo deleted successfully.')
    else:
        flash('You are not authorized to delete this todo.')
    return redirect(url_for('index'))

@app.route('/complete/<int:todo_id>', methods=['POST'])
@login_required
def complete(todo_id):
    todo = Todo.query.get(todo_id)
    if todo and todo.user_id == current_user.id:
        todo.completed = not todo.completed  # Toggle completed status
        db.session.commit()
        flash('Todo marked as completed.' if todo.completed else 'Todo marked as incomplete.')
    else:
        flash('You are not authorized to modify this todo.')
    return redirect(url_for('index'))

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # Run the application
    app.run(debug=True)

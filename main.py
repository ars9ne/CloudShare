import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip'}  # пофиксить зип



app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def connect_to_database():
    return mysql.connector.connect(
        host="localhost",
        database="cloudshare",
        user="root",
        password="####"
    )

def generate_api_key():
    return secrets.token_urlsafe(16)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        api_key = generate_api_key()

        conn = connect_to_database()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password, api_key) VALUES (%s, %s, %s)', (username, hashed_password, api_key))
            conn.commit()
            return redirect(url_for('index'))
        except mysql.connector.Error as e:
            return str(e)
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = connect_to_database()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            session['username'] = user[1]
            session['user_id'] = user[0]  #тут тоже иногда ошибки
            cursor.close()
            conn.close()
            return redirect(url_for('dashboard'))
        else:
            cursor.close()
            conn.close()
            return 'Invalid username or password'

    return render_template('login.html')



@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('api_key', None)
    return redirect(url_for('index'))


#нужен фикс зипа!!1
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'

    file = request.files['file']

    if file.filename == '':
        return 'No selected file'

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        if 'username' in session:
            username = session['username']
            conn = connect_to_database()
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            user_id = cursor.fetchone()[0]
            cursor.execute('INSERT INTO user_files (filename, filepath, user_id) VALUES (%s, %s, %s)',
                           (filename, filepath, user_id))
            conn.commit()
            cursor.close()
            conn.close()

        return redirect(url_for('dashboard'))
    else:
        return 'Invalid file type'


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        conn = connect_to_database()
        cursor = conn.cursor()
        cursor.execute('SELECT filename, filepath FROM user_files WHERE user_id = %s', (session['user_id'],))

        user_files = cursor.fetchall()
        cursor.close()
        conn.close()

        return render_template('dashboard.html', username=session['username'], user_files=user_files)
    return redirect(url_for('login'))


@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/delete/<filename>')
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)

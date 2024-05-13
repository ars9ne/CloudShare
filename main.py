import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
import asyncio
import threading
import uuid
import qrcode
from io import BytesIO

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z'}

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
server_address = "37.204.221.44:5000"


def connect_to_database():
    return mysql.connector.connect(
        host="localhost",
        database="cloudshare",
        user="root",
        password="121940"
    )

def generate_api_key():
    return secrets.token_urlsafe(16)

def generate_share_link():
    return str(uuid.uuid4())

def extract_identifier(link):
    return link.split('/')[-1]


def generate_qr_code(link):


    identifier = extract_identifier(link)
    full_link = f'http://{server_address}/s/{identifier}'  # Form the correct URL with the external address

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4
    )
    qr.add_data(full_link)  # Add the corrected full link
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    return img_io


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if len(username) < 3 or len(password) < 6:
            error = 'Имя пользователя должно иметь длину не менее 3 символов, а пароль — не менее 6 символов.'
            return render_template('register.html', error=error)
        if not username.isalnum() or not password.isalnum():
            error = 'Имя пользователя и пароль должны содержать только буквенно-цифровые символы.'
            return render_template('register.html', error=error)
        conn = connect_to_database()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        existing_user = cursor.fetchone()
        cursor.close()
        conn.close()
        if existing_user:
            error = 'Пользователь с таким именем уже существует.'
            return render_template('register.html', error=error)
        hashed_password = generate_password_hash(password)
        api_key = generate_api_key()
        conn = connect_to_database()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password, api_key) VALUES (%s, %s, %s)', (username, hashed_password, api_key))
            conn.commit()
            message = 'Регистрация прошла успешно! Теперь вы можете войти.'
            return redirect(url_for('index', message=message))
        except mysql.connector.Error as e:
            error = str(e)
            return render_template('register.html', error=error)
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
            session['user_id'] = user[0]
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

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_files(user_id):
    conn = connect_to_database()
    cursor = conn.cursor()
    cursor.execute('SELECT filename, filepath FROM user_files WHERE user_id = %s', (user_id,))
    user_files = cursor.fetchall()
    cursor.close()
    conn.close()
    return user_files


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        session['error'] = 'No file part'
        return redirect(url_for('dashboard'))

    file = request.files['file']  # Correct key based on your form's input name

    if file.filename == '':
        session['error'] = 'No selected file'
        return redirect(url_for('dashboard'))

    # Continue with your existing code...

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        user_id = session.get('user_id')
        if user_id is None:
            session['error'] = 'User not logged in'
            return redirect(url_for('login'))
        upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'uploads_{user_id}')
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        filepath = os.path.join(upload_folder, filename)
        max_file_size = 10 * 1024 * 1024  # 10MB
        if request.content_length > max_file_size:
            session['error'] = 'File size exceeds the maximum allowed size (10MB)'
            return redirect(url_for('dashboard'))
        file.save(filepath)
        share_link = generate_share_link()
        conn = connect_to_database()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO user_files (filename, filepath, user_id, share_link) VALUES (%s, %s, %s, %s)',
                           (filename, filepath, user_id, share_link))
            conn.commit()
            session['message'] = 'File uploaded successfully'
        except mysql.connector.Error as e:
            session['error'] = str(e)
        finally:
            cursor.close()
            conn.close()
        return redirect(url_for('dashboard'))
    else:
        session['error'] = 'Invalid file type'
        return redirect(url_for('dashboard'))

async def clean_up_uploads():
    while True:
        await asyncio.sleep(30)
        user_folders = [f.path for f in os.scandir(app.config['UPLOAD_FOLDER']) if f.is_dir()]
        conn = connect_to_database()
        cursor = conn.cursor()
        try:
            for folder_path in user_folders:
                user_id = os.path.basename(folder_path).split('_')[1]
                files_in_uploads = set(os.listdir(folder_path))
                cursor.execute('SELECT filename FROM user_files WHERE user_id = %s', (user_id,))
                files_in_database = {row[0] for row in cursor.fetchall()}
                files_to_delete = files_in_database - files_in_uploads
                for filename in files_to_delete:
                    cursor.execute('DELETE FROM user_files WHERE filename = %s AND user_id = %s', (filename, user_id))
                    conn.commit()
        except mysql.connector.Error as e:
            print("Error:", e)
        finally:
            cursor.close()
            conn.close()

def run_cleanup():
    asyncio.run(clean_up_uploads())

cleanup_thread = threading.Thread(target=run_cleanup, daemon=True)
cleanup_thread.start()

@app.route('/dashboard')
def dashboard():
    message = session.pop('message', None)
    error = session.pop('error', None)
    if 'username' in session:
        user_id = session.get('user_id')
        if user_id is None:
            return 'User not logged in'
        conn = connect_to_database()
        cursor = conn.cursor()
        cursor.execute('SELECT filename, filepath, share_link FROM user_files WHERE user_id = %s', (user_id,))
        user_files = [(filename, os.path.join(app.config['UPLOAD_FOLDER'], f'uploads_{user_id}', filename), share_link) for filename, filepath, share_link in cursor.fetchall()]
        cursor.close()
        conn.close()
        return render_template('dashboard.html', username=session['username'], user_files=user_files, message=message, error=error, server_address=server_address)
    return redirect(url_for('login'))


@app.route('/download/<filename>')
def download_file(filename):
    user_id = session.get('user_id')
    if user_id is None:
        return 'User not logged in'
    user_specific_folder = f'uploads_{user_id}'
    try:
        return send_from_directory(
            os.path.join(app.config['UPLOAD_FOLDER'], user_specific_folder),
            filename,
            as_attachment=True
        )
    except FileNotFoundError:
        return 'File not found', 404

@app.route('/delete/<filename>')
def delete_file(filename):
    user_id = session.get('user_id')
    if user_id is None:
        return 'User not logged in'
    upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'uploads_{user_id}')
    file_path = os.path.join(upload_folder, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        conn = connect_to_database()
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM user_files WHERE filename = %s AND user_id = %s', (filename, user_id))
            conn.commit()
        except mysql.connector.Error as e:
            print("Error:", e)
        finally:
            cursor.close()
            conn.close()
    return redirect(url_for('dashboard'))

@app.route('/s/<share_link>')
def share(share_link):
    conn = connect_to_database()
    cursor = conn.cursor()
    cursor.execute('SELECT filepath FROM user_files WHERE share_link = %s', (share_link,))
    file_data = cursor.fetchone()
    cursor.close()
    conn.close()
    if file_data:
        return send_from_directory(os.path.dirname(file_data[0]), os.path.basename(file_data[0]), as_attachment=True)
    else:
        return 'Link is invalid or the file has been removed', 404

@app.route('/qr/<link>')
def generate_qr(link):
    img_io = generate_qr_code(request.host_url + 's/' + link)
    return send_file(img_io, mimetype='image/png')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # public
    #app.run(debug=True)  # local

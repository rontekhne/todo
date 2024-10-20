import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from functools import wraps
import secrets
import random
import os

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))

# Função para inicializar o banco de dados
def init_db():
    conn = sqlite3.connect('todo.db')
    cursor = conn.cursor()

    # tabela de tarefas
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')

    # tabela de usuários
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,     
        is_admin BOOLEAN NOT NULL,
        is_verified BOOLEAN NOT NULL DEFAULT 0,
        verification_code TEXT
    )             
    ''')

    conn.commit()
    conn.close()

# Inicializa o banco de dados quando o app começa
init_db()

################
 
# USER area

# Protege as rotas que precisam de autenticação
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Rota para o index
@app.route('/')
@login_required
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']

    conn = sqlite3.connect('todo.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tasks WHERE user_id = ?', (user_id,))
    tasks = cursor.fetchall()
    conn.close()
    return render_template('index.html', tasks=tasks)

# Rota para adicionar tarefas
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        user_id = session['user_id']

        conn = sqlite3.connect('todo.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO tasks (title, description, user_id) VALUES (?, ?, ?)', (title, description, user_id))
        conn.commit()
        conn.close()

        return redirect(url_for('index'))
    
    return render_template('add_task.html')

# Rota para editar tarefas
@app.route('/edit/<int:id>', methods=('GET', 'POST'))
@login_required
def edit_task(id):
    user_id = session['user_id']

    conn = sqlite3.connect('todo.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (id, user_id))
    task = cursor.fetchone()
    if task is None:
        conn.close()
        return "Acesso negado"

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        cursor.execute('UPDATE tasks SET title = ?, description = ? WHERE id = ?', (title, description, id))
        conn.commit()
        conn.close()

        return redirect(url_for('index'))
    
    conn.close()
    return render_template('add_task.html', task=task)

# Rota para excluir tarefas
@app.route('/delete/<int:id>')
@login_required
def delete_task(id):
    user_id = session['user_id']

    conn = sqlite3.connect('todo.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (id, user_id))
    task = cursor.fetchone
    if task is None:
        conn.close()
        return "Acesso negado"
    
    cursor.execute('DELETE FROM tasks WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

# Rota para registro do usuário
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Gerar código de verificação de 6 dítios
        verification_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])

        # hash da senha
        hashed_password = generate_password_hash(password)

        # verifica se o usuário e email já existe
        conn = sqlite3.connect('todo.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return "Usuário já existe!"
        
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_email = cursor.fetchone()

        if existing_email:
            return "Email já existe!"
        
        # Insere o novo usuário no banco de dados
        cursor.execute('INSERT INTO users (username, email, password, is_admin, is_verified, verification_code) VALUES (?, ?, ?, ?, ?, ?)', (username, email, hashed_password, False, False, verification_code))
        conn.commit()
        conn.close()

        # Salva o e-mail na sessão
        session['email'] = email

        # Envia o email de verificação
        send_verification_email(email, verification_code)

        return redirect(url_for('verify_email'))
    
    return render_template('register.html')

# Verificação por email
load_dotenv()

def send_verification_email(email, code):
    sender_email = os.getenv('EMAIL_USER')
    sender_password = os.getenv('EMAIL_PASSWORD')

    if not sender_email or not sender_password:
        raise ValueError("As credenciais de email não estão definidas")

    msg = MIMEText(f"Seu código de verificação é: {code}")
    msg['Subject'] = 'Verificação de Conta'
    msg['From'] = sender_email
    msg['To'] = email

    # Envia email usando SMTP
    server = smtplib.SMTP('smtp.gmail.com', 587) 
    server.ehlo()
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, email, msg.as_string())
    server.quit()

# Rota para verificar o código de verificação
@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        email = session.get('email')
        code = request.form['code']

        conn = sqlite3.connect('todo.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ? AND verification_code = ?', (email, code))
        user = cursor.fetchone()

        if user:
            # Atualiza o status do usuário para verificado
            cursor.execute('UPDATE users SET is_verified = 1 WHERE email = ?', (email,))
            conn.commit()
            conn.close()
            return render_template('verification_success.html')
        else:
            return render_template('invalid_verification_code.html')
        

    return render_template('verify.html')

# Rota de login do usuário
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('todo.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            if user[5] == 0 and user[4] == 0:
                return 'Por favor, verifique seu email!'
            
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[4]
            return redirect(url_for('index'))
        else:
            return 'Nome ou senha inválidos!'
        
    return render_template('login.html')

##########

# ADM area

# Rota para o admin
@app.route('/admin')
@login_required
def admin():
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('todo.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()

    return render_template('admin.html', users=users)

# Rota para adicionar usuários
@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    is_admin = request.form.get('is_admin') == 'true'

    hashed_password = generate_password_hash(password)

    conn = sqlite3.connect('todo.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)', (username, email, hashed_password, is_admin))
    conn.commit()
    conn.close()

    return redirect(url_for('admin'))

# Rota para editar usuários
@app.route('/edit_user/<int:id>', methods=['POST'])
@login_required
def edit_user(id):
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    is_admin = request.form.get('is_admin', False)

    hashed_password = generate_password_hash(password)

    conn = sqlite3.connect('todo.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET username = ?, email = ?, password = ?, is_admin = ? WHERE id = ?', (username, email, hashed_password, is_admin, id))

    conn.commit()
    conn.close()

    return redirect(url_for('admin'))

# Rota para excluir usuários
@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('todo.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (id,))

    conn.commit()
    conn.close()

    return redirect(url_for('admin'))

# Rota para sair
@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
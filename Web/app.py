from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = '321vvdd21'
AUTHORIZED_SESSION_KEY = '5d2b2fb904c798485b04b43c1a7fe9f444a939d2142ebef6e3e539a6d2f305b4'

def init_question_db():
    conn = sqlite3.connect('questions.db')
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS questions (
            id TEXT NOT NULL,
            contents TEXT NOT NULL,
            sender TEXT NOT NULL,
            answer TEXT
        )
    """)
    conn.commit()
    conn.close()

def init_users_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(""" 
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            password BLOB NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def init_db():
    init_question_db()
    init_users_db()

@app.before_request
def create_tables():
    session.permanent = True
    init_db()

@app.route('/', methods=['GET'])
def index():
    user_id = session.get('username')
    conn = sqlite3.connect('questions.db')
    cursor = conn.cursor()
    cursor.execute('SELECT contents, answer FROM questions WHERE id = ?', (user_id,))
    question_data = cursor.fetchall()
    conn.close()
    return render_template('index.html', user_id=user_id, questions=question_data)

@app.route('/signin')
def signin():
    return render_template('Signin.html')

@app.route('/signin', methods=['POST'])
def submit():
    user_id = request.form['username']
    name = request.form['name']
    password = request.form['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = sqlite3.connect('users.db', isolation_level=None)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM users WHERE id = ?', (user_id,))
    if cursor.fetchone()[0] > 0:
        error = "Username already exists."
        return render_template('Signin.html', error=error)
    else:
        try:
            cursor.execute('INSERT INTO users (id, name, password) VALUES (?, ?, ?)', (user_id, name, hashed_password))
        except sqlite3.OperationalError as e:
            print(f"OperationalError: {e}")
        finally:
            conn.commit()
            conn.close()
    return redirect('/signin')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        inputid = request.form['username']
        inputpassword = request.form['password'].encode('utf-8')
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        session_cookie = request.cookies.get('session') 
        
        if inputid == "admin":
            if session_cookie == AUTHORIZED_SESSION_KEY:
                session['username'] = inputid
                return redirect(url_for('index'))
            else:
                error = 'You are not an admin' 
                return render_template('login.html', error=error)

        cursor.execute('SELECT password FROM users WHERE id = ?', (inputid,))
        stored_password = cursor.fetchone()
        conn.close()
        if stored_password and bcrypt.checkpw(inputpassword, stored_password[0]):
            session['username'] = inputid
            return redirect(url_for('index'))
        else:
            error = 'Wrong ID or password'
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route('/ask')
def ask():
    return render_template('ask.html')

@app.route('/submit_question', methods=['POST'])
def send_question():
    if request.method == 'POST':
        senderID = session['username']
        receiverID = request.form.get('receiverID')
        message = request.form.get('question')

        try:
            conn = sqlite3.connect('questions.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO questions (id, contents, sender) VALUES (?, ?, ?)', (receiverID, message, senderID))
            conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            conn.close()

    return redirect(url_for('ask'))

@app.route('/submit_answer', methods=['POST'])
def submit_answer():
    try:
        question_id = request.form['question_id']
        new_answer = request.form['answer']
        conn = sqlite3.connect('questions.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE questions SET answer = ? WHERE contents = ?', (new_answer, question_id))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"ERROR: {e}")

    return redirect(url_for('questions'))

@app.route('/questions', methods=['GET'])
def questions():
    try:
        user_id = session.get('username')
        if not user_id:
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('questions.db')
        cursor = conn.cursor()
        cursor.execute('SELECT contents FROM questions WHERE id = ?', (user_id,))
        questions = cursor.fetchall()
        conn.close()
        return render_template('questions.html', questions=questions, user_id=user_id)
    except Exception as e:
        print(f"An error occurred: {e}") 
        return "An error occurred. Check console."

@app.route('/delete_question', methods=['POST'])
def delete_question():
    question_id = request.form['question_id']
    conn = sqlite3.connect('questions.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM questions WHERE contents = ?', (question_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('questions'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_mysqldb import MySQL
#from data import Groups
from passlib.hash import sha256_crypt
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from functools import wraps


app = Flask(__name__)


dev_groups = []


app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'try'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'


mysql = MySQL(app)


@app.route('/')
def main():
    return render_template("index.html")


def get_db_connection():
    cur = mysql.connection.cursor()
    return cur


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('main'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


@app.route('/register',  methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                    (name, email, username, password))

        mysql.connection.commit()

        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/devices')
@is_logged_in
def devices():
    conn = get_db_connection()

    result = conn.execute("SELECT * FROM devices")

    devs = conn.fetchall()

    if result > 0:
        return render_template('devices.html', devs=devs)

    else:
        msg = "No devices found"
        return render_template('devices.html', msg=msg)

    conn.close()


class RiskForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=200)])
    description = TextAreaField('Description')
    potential = StringField('Rate', [validators.Length(min=1, max=200)])


@app.route('/add_risk', methods=['GET', 'POST'])
def add_risk():
    form = RiskForm(request.form)

    if request.method == 'POST' and form.validate():
        name = form.name.data
        description = form.description.data
        potential = form.potential.data

        conn = get_db_connection()

        # Execute
        conn.execute("INSERT INTO risks(name, description, potential) VALUES(%s, %s, %s)", (name, description, potential))

        mysql.connection.commit()

        conn.close()

        flash('Sucs Added', 'success')

        return redirect(url_for('risks'))

    return render_template('add_risk.html', form=form)


@app.route('/delete/<string:id>', methods=['POST'])
def delete_risk(id):

    conn = get_db_connection()

    conn.execute("DELETE FROM risks WHERE id = %s", [id])

    mysql.connection.commit()

    conn.close()

    flash('Risk Deleted', 'success')

    return redirect(url_for('risks'))


@app.route('/risks')
def risks():
    conn = get_db_connection()

    result = conn.execute("SELECT * FROM risks")

    all_risks = conn.fetchall()

    #if result > 0:
    return render_template('risks.html', risks=all_risks)


@app.route('/groups', methods=['POST', 'GET'])
@is_logged_in
def groups():
    #print(groups)
    return render_template('groups.html', groups=dev_groups)


@app.route('/create_group', methods=['GET', 'POST'])
@is_logged_in
def create_group():
    conn = get_db_connection()

    conn.execute("SELECT * FROM devices")

    devs = conn.fetchall()

    group = []

    if request.method == 'POST':
        #print("ghjk")
        group = request.form.getlist('mychek')
        #print(request.form.getlist('mychek'))
        #return 'Done'
        dev_groups.append(group)
        #print(dev_groups)
        return render_template("groups.html", groups=dev_groups)

    return render_template("create_group.html", devs=devs)


@app.route('/group')
@is_logged_in
def group():
    return render_template('group.html')


if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.run(debug=True)

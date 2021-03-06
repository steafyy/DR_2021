import os, nmap
from functools import wraps

from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_mysqldb import MySQL

from passlib.hash import sha256_crypt
from wtforms import Form, StringField, TextAreaField, PasswordField, validators

app = Flask(__name__)

app.secret_key = os.urandom(24)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'DRdb_2021'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

assets = []


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()

        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            data = cur.fetchone()
            password = data['password']

            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                print(session['username'])

                return redirect(url_for('index'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)

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
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cur = mysql.connection.cursor()

        cur.execute("INSERT IGNORE INTO users(username, password) VALUES(%s, %s)",
                    (username, password))

        mysql.connection.commit()

        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


class RiskForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=200)])
    description = TextAreaField('Description')


@app.route('/add_risk', methods=['GET', 'POST'])
@is_logged_in
def add_risk():
    form = RiskForm(request.form)

    if request.method == 'POST' and form.validate():
        name = form.name.data
        description = form.description.data

        conn = mysql.connection.cursor()

        conn.execute("INSERT INTO risks(name, description) VALUES(%s, %s)",
                     (name, description))

        mysql.connection.commit()

        conn.close()

        flash('Sucs Added', 'success')

        return redirect(url_for('risks'))

    return render_template('add_risk.html', form=form)


@app.route('/edit_risk/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_risk(id):
    cur = mysql.connection.cursor()

    #cur.execute("SELECT * FROM risks WHERE id = %s", [id])

    #risk = cur.fetchone()
    cur.close()

    form = RiskForm(request.form)

    name = form.name.data
    description = form.description.data

    if request.method == 'POST' and form.validate():
        cur = mysql.connection.cursor()

        cur.execute("UPDATE risks SET name =%s, description=%s WHERE id=%s", (name, description, id))

        mysql.connection.commit()

        cur.close()

        flash('Risk Updated', 'success')

        return redirect(url_for('risks'))

    return render_template('edit_risk.html', form=form)


@app.route('/delete/<string:id>', methods=['POST'])
def delete_risk(id):

    conn = mysql.connection.cursor()

    conn.execute("DELETE FROM risks WHERE id = %s", [id])

    mysql.connection.commit()

    conn.close()

    flash('Risk Deleted', 'success')

    return redirect(url_for('risks'))


@app.route('/risks')
def risks():
    conn = mysql.connection.cursor()

    conn.execute("SELECT * FROM risks")

    all_risks = conn.fetchall()

    return render_template('risks.html', risks=all_risks)


@app.route('/groups', methods=['GET', 'POST'])
@is_logged_in
def groups():
    #da se proveri userseseiqta
    if len(assets) == 0:
        msg = "No groups created"
        return render_template("groups.html", msg=msg)
    return render_template('groups.html', assets=assets)


@app.route('/create_group/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def create_group(id):
    conn = mysql.connection.cursor()

    conn.execute("SELECT * FROM devices WHERE network_id=%s", [id])

    devices = conn.fetchall()

    conn.execute("SELECT * FROM risks")

    risks = conn.fetchall()

    if request.method == 'POST':
        choosen_devices = request.form.getlist('associated_devices')

        choosen_risks = request.form.getlist('associated_risks')

        impact = request.form.get('impact')
        print("impact", impact)

        possibility = request.form.get('possibility')
        print("possibility", possibility)

        devices = []
        for device in choosen_devices:
            conn.execute("SELECT * FROM devices WHERE ip=%s", [device])
            device = conn.fetchone()
            devices.append(device)

        n = 0
        risks = []
        for risk in choosen_risks:
            conn.execute("SELECT * FROM risks WHERE id=%s", [risk])
            risk = conn.fetchone()

            risk['evaluation'] = int(impact) * int(possibility)
            print(risk)
            risks.append(risk)
            n = n + 1

        group = {
            "id": id,
            "devices": devices,
            "risks": risks
        }

        assets.append(group)

        return redirect(url_for('groups', assets=assets))

    return render_template("create_group.html", devices=devices, risks=risks)


@app.route('/devices')
@is_logged_in
def devices():
    conn = mysql.connection.cursor()

    conn.execute("SELECT id FROM users WHERE username=%s", [session['username']])

    user_id = conn.fetchone()

    conn.execute("SELECT * from networks WHERE user_id=%s", [user_id['id']])

    networks = conn.fetchall()

    result = []
    for net in networks:

        conn.execute("SELECT id FROM networks WHERE address=%s", [net['address']])

        network_id = conn.fetchone()

        conn.execute("SELECT * FROM devices WHERE network_id=%s", [network_id['id']])

        devs = conn.fetchall()

        result.append(devs)

    if len(result) != 0:
        return render_template('devices.html', devs=result)

    else:
        msg = "No devices found"
        return render_template('devices.html', msg=msg)


class NetworkForm(Form):
    net = StringField('Network IP', [validators.Length(min=1, max=20)])
    #prefix = StringField('Prefix')


def scan_net(net):
    nmscan = nmap.PortScanner()

    nmscan.scan(net)

    conn = mysql.connection.cursor()

    conn.execute("SELECT id FROM users WHERE username=%s", [session['username']])

    user_id = conn.fetchone()

    conn.execute("INSERT INTO networks(address, user_id) VALUES(%s, %s)", [net, user_id['id']])

    conn.execute("SELECT id FROM networks WHERE address=%s", [net])

    net_id = conn.fetchone()


    for host in nmscan.all_hosts():
        print(net, nmscan[host].hostname(), host)

        conn.execute("INSERT INTO devices(ip, hostname, os, network_id) VALUES(%s, %s, %s, %s)", [host, nmscan[host].hostname(), 'unav', net_id['id']])

        mysql.connection.commit()

    conn.close()


@app.route('/scan', methods=['GET', 'POST'])
@is_logged_in
def scan():
    form = NetworkForm(request.form)

    net = form.net.data
    #prefix = form.prefix.data

    if request.method == 'POST' and form.validate():
        scan_net(net)
        #v edna sesiq ne stava poveche ot 1 skanirane?
        return redirect(url_for('devices'))

    return render_template('scan.html', form=form)


if __name__ == '__main__':
    app.run()

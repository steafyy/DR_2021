from flask import Flask, render_template, request, url_for, redirect, flash
from flask_mysqldb import MySQL
#from data import Groups
from wtforms import Form, StringField, TextAreaField, validators


app = Flask(__name__)


dev_groups = []


app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'try'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'


mysql = MySQL(app)


def get_db_connection():
    cur = mysql.connection.cursor()
    return cur


@app.route('/')
def main():
    return render_template("index.html")


@app.route('/devices')
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
def groups():
    #print(groups)
    return render_template('groups.html', groups=dev_groups)


@app.route('/create_group', methods=['GET', 'POST'])
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
def group():
    return render_template('group.html')

if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.run(debug=True)

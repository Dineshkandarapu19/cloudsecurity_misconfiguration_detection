from flask import Flask, render_template,  redirect, url_for
app = Flask(__name__)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/scan')
def scan():
    return render_template('scan.html') 

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route("/iam")
def iam():
    return render_template("iam.html")


@app.route("/ec2")
def ec2():
    return render_template("ec2.html")


@app.route("/s3")
def s3():
    return render_template("s3.html")


@app.route("/vpc")
def vpc():
    return render_template("vpc.html")

@app.route("/logout")
def logout():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

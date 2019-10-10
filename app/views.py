from flask import render_template, flash, request, redirect, url_for, session, jsonify
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from app import text_detection, model, db, app
from datetime import timedelta

app.config["allowed_img"] = ["png", "jpg", "jpeg", "fig"]
app.secret_key = os.urandom(24)


def allowed_img(filename):
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1]
    if ext.lower() in app.config["allowed_img"]:
        return True
    else:
        return False


# @app.before_request
# def expire():
#     pass


@app.route('/', methods=["GET", "POST"])
def index():
    if 'user' in session:
        return redirect(url_for('user'))
    return render_template('index2.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if not 2 <= len(username) <= 100:
            flash("Invalid Username!")
            return redirect(request.url)
        if password != confirm_password:
            flash("Passwords do not match!")
            return redirect(request.url)
        if not 2 <= len(password) <= 100:
            flash("Password too long or too short!")
            return redirect(request.url)

        # avoid users with the same username
        dup_user = model.User.query.filter_by(username=username).first()
        if dup_user is not None:
            flash('Username already exists! Please choose another one!')
            return redirect(request.url)

        password = generate_password_hash(password + username)
        candidate_user = model.User(username=username, password=password)
        db.session.add(candidate_user)
        db.session.commit()
        os.system('cd app/static/users && mkdir ' + username)
        os.system('cd app/static/users/' + username + ' && mkdir ' + 'original')
        os.system('cd app/static/users/' + username + ' && mkdir ' + 'processed')
        session['user'] = username
        return redirect(url_for('user'))
    return render_template('signup.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method=='POST':
        username = request.form.get('username')
        password = request.form.get('password')
        candidate_user = model.User.query.filter_by(username=username).first()
        try:
            candidate_user.username
        except:
            flash('Invalid username or password')
            return redirect(url_for('index'))
        if check_password_hash(candidate_user.password, password + username):
            session['user'] = username
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=1440)
            return redirect(url_for('user', username=username))
        else:
            flash('Invalid username or password')
            return redirect(url_for('index'))
    else:
        return render_template('login.html')


@app.route('/logout', methods=["GET", "POST"])
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/user', methods=["GET", "POST"])
def user():
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    username = session['user']
    return render_template('user.html', user=username)


@app.route('/upload', methods=["GET", "POST"])
def upload():
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    username = session['user']
    if request.method == "POST":
        file = request.files['file']
        if request.files:
            if file.filename == "":
                flash("Image must have a filename")
                return redirect(request.url)
            if not allowed_img(file.filename):
                flash("That image extension is not allowed!")
                return redirect(request.url)

            else:
                filename = secure_filename(file.filename)
                name, ext = filename.rsplit(".", 1)
                same_name = os.system('find . -name app/static/users/' + username + '/original/' + filename)
                # print(same_name)
                if same_name != 0:
                    name += '(1)'
                original_name = 'app/static/users/' + username + '/original/' + name + '.' + ext
                new_img_name = 'app/static/users/' + username + '/processed/' + name + '.' + ext
                file.save(os.path.join("app/static/users/" + username + '/original/', name + '.' + ext))
                east_location = "app/frozen_east_text_detection.pb"
                text_detection.process_image(original_name, east_location, new_img_name)
                flash("upload success!")
    return render_template('upload.html')


# display all the images in the folder
@app.route("/preview")
def preview():
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    images = os.listdir('app/static/users/' + session['user'] + '/original')
    hists = []
    for image in images:
        hists.append(image)
    hists.sort()
    return render_template('preview.html', hists=hists, username=session['user'])


@app.route('/fullImg/<img_name>')
def fullImg(img_name):
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    return render_template('full_img.html', img_name=img_name, username=session['user'])


@app.route('/api/register', methods=["POST", "GET"])
def api_register():
    username = request.json['username']
    password = request.json['password']
    if not isinstance(username, str) or not 2 <= len(username) <= 100:
        return jsonify("invalid username!"), 406
    if not isinstance(username, str) or not 2 <= len(password) <= 100:
        return jsonify("invalid password!"), 406
    dup_user = model.User.query.filter_by(username=username).first()
    if dup_user is not None:
        return jsonify("username already exists!"), 406
    password = generate_password_hash(password + username)
    candidate_user = model.User(username=username, password=password)
    db.session.add(candidate_user)
    db.session.commit()
    os.system('cd app/static/users && mkdir ' + username)
    os.system('cd app/static/users/' + username + ' && mkdir ' + 'original')
    os.system('cd app/static/users/' + username + ' && mkdir ' + 'processed')
    return jsonify("user created!"), 201


@app.route('/api/upload', methods=["POST", "GET"])
def api_upload():
    username = request.json['username']
    password = request.json['password']
    file = request.json['file']
    if not isinstance(username, str) or not 2 <= len(username) <= 100:
        return jsonify("invalid username or password!"), 406
    if not isinstance(username, str) or not 2 <= len(password) <= 100:
        return jsonify("invalid username or password!"), 406
    candidate_user = model.User.query.filter_by(username=username).first()
    if candidate_user is None:
        return jsonify("invalid username or password!"), 406
    if not check_password_hash(candidate_user.password, password + username):
        return jsonify("invalid username or password!"), 406
    if file.filename == "":
        return jsonify("Image must have a filename"), 406
    if not allowed_img(file.filename):
        return jsonify("That image extension is not allowed!"), 406
    else:
        filename = secure_filename(file.filename)
        name, ext = filename.rsplit(".", 1)
        same_name = os.system('find . -name app/static/users/' + username + '/original/' + filename)
        # print(same_name)
        if same_name != 0:
            name += '(1)'
        original_name = 'app/static/users/' + username + '/original/' + name + '.' + ext
        new_img_name = 'app/static/users/' + username + '/processed/' + name + '.' + ext
        file.save(os.path.join("app/static/users/" + username + '/original/', name + '.' + ext))
        east_location = "app/frozen_east_text_detection.pb"
        text_detection.process_image(original_name, east_location, new_img_name)
        return jsonify("upload success!"), 201

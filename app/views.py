from flask import render_template, flash, request, redirect, url_for, session, jsonify
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from app import text_detection, model, db, app
from datetime import timedelta

# the following four image extensions are allowed
app.config["allowed_img"] = ["png", "jpg", "jpeg", "fig"]
# the maximum image size is 10m
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
app.secret_key = os.urandom(24)
db.create_all()

def allowed_img(filename):
    # a function which determines whether a filename(extension) is allowed
    # str(filename) -> bool
    # If the file extension in 'png', 'jpg', 'jpeg' and 'gif', return True, otherwise return False
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1]
    if ext.lower() in app.config["allowed_img"]:
        return True
    else:
        return False


@app.route('/', methods=["GET", "POST"])
def index():
    # main page
    # If the user has not logged out, redirect to the user page.
    if 'user' in session:
        return redirect(url_for('user'))
    return render_template('index2.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # registration page
    # On the server side, check whether the username and password are valid or not.
    # username and password must be strings between 2 to 100 characters
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        context={
            'username_valid': 0,
            'password_valid': 0,
            'pawconfirm_valid': 0,
            'username': username
                 }

        flag = False
        if not 2 <= len(username) <= 100:
            context['username_valid'] = 1
            flag = True

        if password != confirm_password:
            context['password_valid'] = 1
            flag = True

        if not 2 <= len(password) <= 100:
            context['password_valid'] = 2
            flag = True

        # users are not allowed to have same username
        dup_user = model.User.query.filter_by(username=username).first()
        if dup_user:
            context['username_valid'] = 2
            flag = True

        if flag:
            return render_template('signup.html', **context)

        # Different users are allowed to have the same password
        # After using salt value for storing passwords, they will look completely different on the server(database)
        # even though they are the same
        password = generate_password_hash(password + username)
        candidate_user = model.User(username=username, password=password)
        db.session.add(candidate_user)
        db.session.commit()
        # two directories are created to store the images later uploaded by the user
        os.system('cd app/static/users && mkdir ' + username)
        os.system('cd app/static/users/' + username + ' && mkdir ' + 'original')
        os.system('cd app/static/users/' + username + ' && mkdir ' + 'processed')
        # log in
        session['user'] = username
        return redirect(url_for('user'))
    context = {
        'username_valid': -1,
        'password_valid': -1,
        'pawconfirm_valid': -1
    }
    return render_template('signup.html', **context)


@app.route('/login', methods=["GET", "POST"])
def login():
    # login page
    # verify the username and password provided by the user
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        candidate_user = model.User.query.filter_by(username=username).first()
        try:
            candidate_user.username
        except:
            flash('Invalid username or password')
            return render_template('login.html', p=1)
        if check_password_hash(candidate_user.password, password + username):
            session['user'] = username
            session.permanent = True
            # after 24 hours, users are required to reenter their usernames and passwords for security purposes
            app.permanent_session_lifetime = timedelta(minutes=1440)
            return redirect(url_for('user', username=username))
        else:
            flash('Invalid username or password')
            return render_template('login.html', p=1)
    else:
        return render_template('login.html')


@app.route('/logout', methods=["GET", "POST"])
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/user', methods=["GET", "POST"])
def user():
    # if the user are not logged in, redirect to the login page
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    username = session['user']
    return render_template('user2.html', user=username)


@app.route('/upload', methods=["GET", "POST"])
def upload():
    # if the user are not logged in, redirect to the login page
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    username = session['user']
    # verify the extension of the image which users want to upload
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
                # use a unique id to mark each image so that images with same name will not overwrite each other
                filename = secure_filename(file.filename)
                uploader = model.User.query.filter_by(username=session['user']).first()
                candidate_file = model.Image(filename=filename)
                candidate_file.uploader = uploader
                db.session.add(candidate_file)
                db.session.commit()
                name, ext = filename.rsplit(".", 1)
                name = str(candidate_file.id)
                original_name = 'app/static/users/' + username + '/original/' + name + '.' + ext
                new_img_name = 'app/static/users/' + username + '/processed/' + name + '.' + ext
                file.save(os.path.join("app/static/users/" + username + '/original/', name + '.' + ext))
                east_location = "app/frozen_east_text_detection.pb"
                # run the text detector and store the new image in the corresponding directory
                text_detection.process_image(original_name, east_location, new_img_name)
                flash("upload success!")
        return render_template('upload_success.html')
    return render_template('upload2.html')


@app.route("/preview")
def preview():
    # display all the images in the users folder so that each user can only see the images he or she uploaded
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    # images = os.listdir('app/static/users/' + session['user'] + '/original')
    current_user = model.User.query.filter_by(username=session['user']).first()
    user_photo = current_user.images
    #  print(user_photo[0].filename)
    hists = {}
    for image in user_photo:
        ext = image.filename.rsplit(".", 1)[1]
        name = str(image.id)
        full_name = name + '.' + ext
        current_img = full_name
        hists[current_img] = image.filename
    return render_template('preview2.html', hists=hists, username=session['user'])


@app.route('/fullImg/<img_id>')
def fullImg(img_id):
    # This function allows user to compared two images. One is the photo before text detection while the other is the
    # one after text detection.
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    return render_template('full_img2.html', img_name=img_id, username=session['user'])


@app.route('/api/register', methods=["POST", "GET"])
def api_register():
    username = request.form.get('username')
    password = request.form.get('password')
    if not isinstance(username, str) or not 2 <= len(username) <= 100:
        return "406, invalid username!"
    if not isinstance(username, str) or not 2 <= len(password) <= 100:
        return "406, invalid password!"
    dup_user = model.User.query.filter_by(username=username).first()
    if dup_user is not None:
        return "406, username already exists!"
    password = generate_password_hash(password + username)
    candidate_user = model.User(username=username, password=password)
    db.session.add(candidate_user)
    db.session.commit()
    os.system('cd app/static/users && mkdir ' + username)
    os.system('cd app/static/users/' + username + ' && mkdir ' + 'original')
    os.system('cd app/static/users/' + username + ' && mkdir ' + 'processed')
    return "201, user created!"


@app.route('/api/upload', methods=["POST", "GET"])
def api_upload():
    username = request.form.get('username')
    password = request.form.get('password')
    file = request.files['file']
    if not isinstance(username, str) or not 2 <= len(username) <= 100:
        return "406, invalid username or password!"
    if not isinstance(username, str) or not 2 <= len(password) <= 100:
        return "406, invalid username or password!"
    candidate_user = model.User.query.filter_by(username=username).first()
    if candidate_user is None:
        return "406, invalid username or password!"
    if not check_password_hash(candidate_user.password, password + username):
        return "406, invalid username or password!"
    if file.filename == "":
        return "406, Image must have a filename"
    if not allowed_img(file.filename):
        return "406, That image extension is not allowed!"
    else:
        filename = secure_filename(file.filename)
        uploader = model.User.query.filter_by(username=username).first()
        candidate_file = model.Image(filename=filename)
        candidate_file.uploader = uploader
        db.session.add(candidate_file)
        db.session.commit()
        name, ext = filename.rsplit(".", 1)
        name = str(candidate_file.id)
        original_name = 'app/static/users/' + username + '/original/' + name + '.' + ext
        new_img_name = 'app/static/users/' + username + '/processed/' + name + '.' + ext
        file.save(os.path.join("app/static/users/" + username + '/original/', name + '.' + ext))
        east_location = "app/frozen_east_text_detection.pb"
        # run the text detector and store the new image in the corresponding directory
        text_detection.process_image(original_name, east_location, new_img_name)
        return "201, upload success!"


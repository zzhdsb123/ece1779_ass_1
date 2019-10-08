from flask import render_template, flash, request, redirect, url_for, session
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from app import text_detection, model, db, app
app.config["allowed_img"] = ["png", "jpg", "jpeg", "fig"]
app.secret_key = b'\xec7-\xae\xf1p\x1f\xf8dgb>,`T\x00'


# TODO: use get method instead of "if 'user' not in session:"
# TODO: use username instead of user in session data
# TODO: use os.random method to generate the secret key

def allowed_img(filename):
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1]
    if ext.lower() in app.config["allowed_img"]:
        return True
    else:
        return False


@app.route('/', methods=["GET", "POST"])
def index(message=None):
    return render_template('index.html', text=message)


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/confirm', methods=["GET", "POST"])
def confirm():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if not 2 <= len(username) <= 20:
        flash("Invalid Username!")
        return render_template('register.html', username=username)
    if password != confirm_password:
        flash("Passwords do not match!")
        return render_template('register.html', username=username)
    if not 2 <= len(password) <= 20:
        flash("Password too long or too short!")
        return render_template('register.html', username=username)
    password = generate_password_hash(password+username)
    candidate_user = model.User(username=username, password=password)
    db.session.add(candidate_user)
    db.session.commit()

    os.system('cd app/static/users && mkdir ' + username)
    os.system('cd app/static/users/' + username + ' && mkdir ' + 'original')
    os.system('cd app/static/users/' + username + ' && mkdir ' + 'processed')
    return redirect(url_for('index'))


@app.route('/login', methods=["GET", "POST"])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    candidate_user = model.User.query.filter_by(username=username).first()
    try:
        candidate_user.username
    except:
        flash('Invalid username or password')
        return redirect(url_for('index'))
    if check_password_hash(candidate_user.password, password+username):
        session['user'] = username
        return redirect(url_for('user', username=username))
    else:
        flash('Invalid username or password')
        return redirect(url_for('index'))


@app.route('/logout', methods=["GET", "POST"])
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/user', methods=["GET", "POST"])
def user():
    message = None
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    username = session['user']
    return render_template('user.html', user=username, message=message)


@app.route('/upload', methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password') + username
        file = request.files['file']
        candidate_user = model.User.query.filter_by(username=username).first()
        try:
            candidate_user.username
        except:
            flash('Invalid username or password!')
            return redirect(request.url)

        if not check_password_hash(candidate_user.password, password):
            flash('Invalid username or password!')
            return redirect(request.url)
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
                same_name = os.system('find . -name app/static/users/'+username+'/original/'+filename)
                print(same_name)
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


    images = os.listdir('app/static/users/'+session['user']+'/original')
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

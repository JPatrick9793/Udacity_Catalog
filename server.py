#! --shebang
from flask import request, g, Flask, jsonify, make_response, render_template
from flask import redirect, url_for, flash
from flask.ext.httpauth import HTTPBasicAuth
from flask import session as login_session

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from models import Base, Items, User

import httplib2
import requests
import json
import random
import string

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)
auth = HTTPBasicAuth()

# read OAuth client_secret and client_id from json file
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


# app route for the homepage
@app.route('/')
@app.route('/home')
def getHomePage():
    users = session.query(User).all()
    # if the user is not logged in, return the basic homepage html
    try:
        return render_template(
            'homepage.html',
            users=users,
            login_session=login_session
            )
    # if the user is logged in, return logged in html
    except:
        return render_template(
            'homepage_loggedout.html',
            users=users
            )


# app route for login
@app.route('/login')
def getLogin():
    # create a login state string and assign it to login_session[]
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    # return the login html
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;'
    output += 'border-radius: 150px;-webkit-border-radius: 150px;'
    output += '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        return redirect(url_for('getHomePage'), code=200)

    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# app route to delete user
# no url is provided to this link from within the html
# used mainly by developer to remove a user created in error
@app.route('/delete/<int:user_id>', methods=['GET', 'POST'])
def deleteUser(user_id):
    # Login user can only access his/her own information
    if user_id != login_session['user_id']:
        return render_template('youShallNotPass.html')
    # query the user from db
    deletedUser = session.query(User).filter_by(id=user_id).one()

    # if 'get' then simply return json of user
    if request.method == 'GET':
        return jsonify(user=deletedUser.serialize)
    # if 'post', delete user
    if request.method == 'POST':
        session.delete(deletedUser)
        session.commit()
        return "User has been removed"


# route to bring up a user's catalog
@app.route('/catalog/<int:user_id>')
def getCatalog(user_id):
    # Login user can only access his/her own information
    if user_id != login_session['user_id']:
        return render_template('youShallNotPass.html')
    # query all users items
    items = session.query(Items).filter_by(
        user_id=login_session['user_id']).all()
    # return the catalog html
    return render_template('getCatalog_GET.html',
                           items=items,
                           login_session=login_session)


# app route to create a new item within a user's catalog
@app.route('/catalog/<int:id>/create', methods=['GET', 'POST'])
def getCreate(id):
    # Login user can only access his/her own information
    if id != login_session['user_id']:
        return render_template('youShallNotPass.html')

    # query user from db
    user = session.query(User).filter_by(id=login_session['user_id']).one()

    # if 'post' then add the new item to the db
    # item.user_id will be the login_session['user_id']
    if request.method == 'POST':
        newItem = Items(
            name=request.form['name'],
            user_id=login_session['user_id'],
            description=request.form['description']
            )
        session.add(newItem)
        session.commit()
        return redirect(url_for('getCatalog', user_id=id))

    # if 'get' return html template to create new item
    if request.method == 'GET':
        return render_template('getCreate_GET.html',
                               user=user,
                               login_session=login_session
                               )


# app route to edit/update an existing item
@app.route('/catalog/<int:user_id>/update/<int:item_id>',
           methods=['GET', 'POST'])
def getUpdate(user_id, item_id):
    # Login user can only access his/her own information
    if user_id != login_session['user_id']:
        return render_template('youShallNotPass.html')

    # query item to be edited
    editedItem = session.query(Items).filter_by(id=item_id).one()

    # if 'get'
    if request.method == 'GET':
        # return html template
        return render_template(
            'getUpdate_GET.html',
            item=editedItem,
            login_session=login_session
            )
    # if 'post'
    if request.method == 'POST':
        # check to see if anything written for 'name'
        if request.form['name']:
            # if so, update item.name
            editedItem.name = request.form['name']
        # check to see if anything written for 'description'
        if request.form['description']:
            # if so, update item.description
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        # redirect user to catalog page
        return redirect(url_for('getCatalog', user_id=user_id))


# app route to delete item
@app.route('/catalog/<int:user_id>/delete/<int:item_id>',
           methods=['GET', 'POST'])
def getDelete(user_id, item_id):
    # Login user can only access his/her own information
    if user_id != login_session['user_id']:
        return render_template('youShallNotPass.html')
    # query user and item in question
    user = session.query(User).filter_by(id=user_id).one()
    deletedItem = session.query(Items).filter_by(id=item_id).one()

    # if 'get'
    if request.method == 'GET':
        return render_template('getDelete_GET.html',
                               item=deletedItem,
                               login_session=login_session
                               )
    # if 'post'
    if request.method == 'POST':
        session.delete(deletedItem)
        session.commit()
        return redirect(
            url_for(
                'getCatalog', user_id=user_id
                )
            )


# app route for json endpoint for particular item
# link for this endpoint IS provided from within html
@app.route('/catalog/<int:user_id>/<int:item_id>/JSON')
def getItemJSON(user_id, item_id):
    # Login user can only access his/her own information
    if user_id != login_session['user_id']:
        return render_template('youShallNotPass.html')
    # query particular item and return json form
    item = session.query(Items).filter_by(id=item_id).one()
    return jsonify(item.serialize)


# function to retrieve a user's ID from the User table
# uses email as parameter because it is used among
# most 3rd party authentication
def getUserID(email):
    # if the email exists within the table, return the associated ID
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    # else return None
    except:
        return None


# function to create a new User
def createUser(login_session):
    newUser = User(
                   username=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture']
                   )
    # user is added to table
    session.add(newUser)
    session.commit()
    # user is queried from table and the ID is returned
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# function that queries the User table
# using the ID and returns the object
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# constructor
if __name__ == '__main__':
    app.secret_key = 'something_very_secret'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)

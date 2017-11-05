from redis import Redis
import time
from functools import update_wrapper
from flask import request, g
from flask import Flask, jsonify 
from models import Base, Items


from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

import json

engine = create_engine('sqlite:///catalog.db')


Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)


app = Flask(__name__)
redis = Redis()


@app.route('/')
@app.route('/home')
def getHomePage():
	return "This will be the HomePage"


@app.route('/login')
def getLogin():
	return "This will be the login page"

@app.route('/logout')
def getLogout():
	return "This will be the logout page"

@app.route('/catalog/<int:user_id>')
def getCatalog(user_id):
	return ("List of all products for user %s" % user_id)

@app.route('/catalog/<int:user_id>/create')
def getCreate(user_id):
	return ("Create a new entry into the database for user %s" % user_id)

@app.route('/catalog/<int:user_id>/update/<int:item_id>')
def getUpdate(user_id, item_id):
	return ("edit a current entry for item %s in the database for user %s" % (item_id, user_id) )

@app.route('/catalog/<int:user_id>/delete/<int:item_id>')
def getDelete(user_id, item_id):
	return ("delete item %s in the database for user %s" % (item_id, user_id) )


if __name__ == '__main__':
    # app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)


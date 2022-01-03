from app import app
import os
import uuid
import boto3
import random
import pathlib
import datetime
import jwt as jwt1
import random as r
import pyshorteners
from models import *
from functools import wraps
from sqlalchemy import desc
from flask_marshmallow import Marshmallow
from werkzeug.utils import secure_filename
from botocore.exceptions import ClientError
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, request, make_response, send_file, session



    # Jwt Authentication

# Function for JWT Required Decorator
def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = None
       if 'x-access-tokens' in request.headers:
           token = request.headers['x-access-tokens']

       if not token:
           return jsonify({'message': 'a valid token is missing'}), 401
       try:
           data = jwt1.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
           current_user = Users.query.filter_by(id=data['id']).first()

           if not current_user:
               current_user = Users.query.filter((Users.id == data['id']) ).first()
       except:
           return jsonify({'message': 'Token is INVALID or EXPIRED'}), 401
       return f(current_user, *args, **kwargs)
   return decorator


# For Login of Admin (User Table)
@app.route('/api/v1/auth', methods=['POST'])
def login_user():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if not username or not password:
        return jsonify({'message':'Please enter Credentials'}), 401

    user = Users.query.filter_by(username=username).first()

    if not user:
        return jsonify({'message':'Login Unsuccessfull'}), 401
    
    if check_password_hash(user.password, password):

        access_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=59)}, app.config['JWT_SECRET_KEY'], "HS256")
        refresh_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=1)}, app.config['JWT_SECRET_KEY'], "HS384")
        resp = jsonify({'access_token': access_token})
        resp.set_cookie('refresh_token', refresh_token, httponly = True)

        return resp, 200

    return jsonify({'message':'Login Unsuccessfull'}), 401


# Refresh the access token
@app.route('/api/v1/refresh', methods=['POST'])
def refresh():
    refresh = request.cookies.get('refresh_token')
    try:
        decoded = jwt1.decode(refresh, app.config['JWT_SECRET_KEY'], algorithms=["HS384"])
        user = Users.query.filter(decoded['id'] == Users.id).first()
        if not user:
            user = Users.query.filter((decoded['id'] == Users.id) ).first()
        if user:
            access_token = jwt1.encode({'id' : user.id,  'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=59)}, app.config['JWT_SECRET_KEY'], "HS256")
            refresh_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(weeks=1)}, app.config['JWT_SECRET_KEY'], "HS384")
            resp = jsonify({'Access Token': access_token})
            resp.set_cookie('refresh_token', refresh_token, httponly = True)
            return resp, 200
    except:
        return jsonify({'msg':'Unauthorized Access'}), 401
    return jsonify({'msg': "Refresh cookies not valid"})


# User Authentication

# Sign Up
@app.route('/api/v1/register', methods=['POST'])
def add_user():
    
    data = request.get_json()
    msg = add_user_api(data)
    
    if msg:
        return jsonify({'message':msg}), 200
    else:
        return jsonify({'message':"Unvalid credentials"}), 400

def add_user_api(data):
    try:
        username = data['username']
    except:
        username = ""
    try:
        password = data['password']
    except:
        password = ""
    
    if not username:
        name = data['name']
        b = name[:3]
        c = name[-2:]
        username = b + c
        username = username + str(r.randint(0,9999))
        username = username.replace(" ", "")

    if not password:
        password = data['name'] + str(r.randint(0,9999))
        password = password.replace(" ", "")
        
    username_checked = check_username(username)
    if username_checked:
        return username_checked

    if data['email']:
        email_checked = check_email(data['email'])
        if email_checked:
            return email_checked        
    
    hashed_password = generate_password_hash(password, method = 'sha256')

    
    user = Users(name = data['name'], username = username, email = data['email'], password = hashed_password)
    app.config['DB'].session.add(user)        
    app.config['DB'].session.commit()
    return ('New User Added')


    
# Sign In
@app.route('/api/v1/login', methods=['POST'])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    if not email or not password:
        return jsonify({'message':'Please enter Credentials'}), 401
    user = Users.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message':'Login Unsuccessfull, please enter valid credentials'}), 401
    a = user.password

    if check_password_hash(a, password):
        access_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=59)}, app.config['JWT_SECRET_KEY'], "HS256")
        refresh_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=1)}, app.config['JWT_SECRET_KEY'], "HS384")
        user_details = {"id":user.uid,'username':user.username,'email':user.email}
        resp = jsonify({'access_token': access_token, "user_data":user_details})
        resp.set_cookie('refresh_token', refresh_token, httponly = True)

        return resp, 200
    return jsonify({'message':'Login Unsuccessfull'}), 401


# Sign Out
@app.route('/api/v1/logout', methods=['GET'])
@token_required
def logout(current_user):
    pass

#All API's

# Check Username if it already existed or not in Database
def check_username(username):
    data = Users.query.filter_by(username=username).first()
    if data:
        return ('Username Already Exists')

# Check Email if it already existed or not in Database
def check_email(email):
    data = Users.query.filter_by(email=email).first()
    if data:
        return ('This Email is already taken by another user')


# Search item by product id and name
@app.route('/api/v1/items', methods=['GET'])
def get_items_multisearch():
    page  = request.args.get('page', type=int ,default=1)
    perpage  = request.args.get('perPage',type=int , default=10)


    alldata = app.config['DB'].session.query(Items).order_by(desc(Items.id)).paginate(page,perpage,error_out=False)
    total = alldata.total
    if alldata:
        result = get_all_items_api(alldata)
        data=1

    if not data:
        return jsonify({'msg':'No Items found'})

    return jsonify({"data":result, "total":total})

# item's API's CRUD Operation with pagination
def get_all_items_api(alldata):

    output = []
    for data in alldata.items:
        x,y=data
        items_data = {}
        items_data['name'] = x.name
        items_data['id'] = x.id
        items_data['description'] = x.description
        items_data['location'] = x.location
        items_data['date'] = x.date
        output.append(items_data)
    return (output)


@app.route("/api/v1/items/<id>", methods=['GET'])
def get_one_item_api(id):
    data = app.config['DB'].session.query(Items).filter( (Items.id == id)).first()
    if not data:
        return jsonify({'message':'No Data found'}), 404
    
    x,y=data
    items_data = {}
    items_data['name'] = x.name
    items_data['id'] = x.id
    items_data['description'] = x.description
    items_data['location'] = x.location
    items_data['date'] = x.date

    return jsonify({'data':items_data})


# Add item Function
def add_items_api(data):
    new_item = Items(name = data['name'],description = data['description'], location = data['location'], date = data['date'])
    
    app.config['DB'].session.add(new_item)        
    app.config['DB'].session.commit()
    return ('New item Created')


# items Add Endpoint for Admin
@app.route('/api/v1/items', methods=['POST'])
@token_required
def add_items(current_user):
    data = request.form
    msg = add_items_api(data)

    return jsonify({'message':msg}), 201


@app.route("/api/v1/items/<id>", methods=['PUT'])
@token_required
def edit_item_api(current_user, id):

    data = request.form
    value = app.config['DB'].session.query(Items).filter(Items.id == id).first()
    if not value:
        return jsonify({'message':'No Item found'}), 404
    x,y = value 

    x.name = data['name']
    x.description = data['description']
    x.location = data['location']
    x.date = data['date']
    
    app.config['DB'].session.commit()
    return jsonify({'message':'items Information Updated'}), 200


@app.route("/api/v1/items/<id>", methods=['DELETE'])
@token_required
def del_item_api(current_user, id):

    item = Items.query.filter_by(id=id).first()

    if not item:
        return jsonify({'message':'No item Found'}), 404

    app.config['DB'].session.delete(item)
    app.config['DB'].session.commit()

    return jsonify({'message':'Item Deleted'}), 200

# TOtal Count API
@app.route('/api/v1/totalCount', methods=['GET'])
def get_total_count_api():

    totalItems = app.config['DB'].session.query(Items.id).count()

    total_data = {}
    total_data['totalItems'] = totalItems

    return jsonify({'data':total_data}), 200
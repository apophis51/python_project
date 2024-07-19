from flask import Flask, request, jsonify, make_response, g # g is designed for storing temporary data in handling a request
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from supabase import create_client, Client
from typing import Optional

from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_APP_KEY")  # Replace with a secure secret key



supabase_url: Optional[str] = str(os.environ.get("SUPABASE_URL"))
supabase_key: Optional[str] = str(os.environ.get("SUPABASE_KEY"))
supabase: Client = create_client(supabase_url, supabase_key)


# Register route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    existing_user = supabase.table("user").select("username").eq("username", username).execute()
    if existing_user.data:
        return 'Username already exists', 400
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256:8000')
    create_supabase_user = supabase.table("user").insert({"username": username, "password": hashed_password}).execute()
    return 'User registered'
 
# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    supabase_user = supabase.table("user").select("username, password").eq("username", username).execute()
    print(supabase_user.data[0]['password'])
    stored_supabase_pass_for_user = supabase_user.data[0]['password']
    print(check_password_hash('stored_supabase_pass_for_user', password))

    if supabase_user and check_password_hash(stored_supabase_pass_for_user, password):
        token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'])
        resp = make_response('Logged in')
        resp.set_cookie('authToken', token, httponly=True)
        return resp
    else:
        return 'Invalid credentials', 401

# Middleware to verify token
def authenticate_token(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.cookies.get('authToken')
        if token:
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                g.user = data
                return f(*args, **kwargs)
            except jwt.ExpiredSignatureError:
                return 'Token expired', 403
            except jwt.InvalidTokenError:
                return 'Invalid token', 403
        else:
            return 'Unauthorized', 401
    return decorator

def check_ownership(func):
    @wraps(func)
    def decoratorr(*args, **kwargs):
        token = request.cookies.get('authToken')
        if token:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_name = data['username']
            get_user_blogs = supabase.table("user").select("*,blogs(*)").eq("username", user_name).execute()
            blog_list = get_user_blogs.data[0]['blogs']
            for blog in blog_list:
                if str(blog['id']) == str(kwargs['id']):
                    return func(*args, **kwargs)
            else:
                return 'Your Not Authorized to Edit That', 403
        else:
            return 'Unauthorized', 401
    return decoratorr

# Protected route
@app.route('/blogs', methods=['GET', 'POST'])
@authenticate_token
def blogs():
    if request.method == 'GET':
        supabase_blog_response = supabase.table("blogs").select("*").execute()
        print(supabase_blog_response)
        return jsonify(supabase_blog_response.data)
    if request.method == 'POST':
        data = request.get_json()
        title = data['title']
        content = data['content']
        get_supabase_user = supabase.table("user").select("*").eq("username", g.user['username']).execute()
        author_id = get_supabase_user.data[0]["id"]
        supabase.table("blogs").insert({"title": title, "content": content, "author": author_id}).execute()
        return 'Blog created'
    return 'Bad request', 400

#Retrive an induvidual blog
@app.get('/blogs/<path:id>')
@authenticate_token
def show_subpath(id):
    try:
        supabase_blog_response = supabase.table("blogs").select("*").eq("id", id).execute()
        print(supabase_blog_response)
        if supabase_blog_response.data == []:
            return 'Blog not found', 404
        return jsonify(supabase_blog_response.data)
    except:
        return 'Blog not found', 404
     
@app.delete('/blogs/<path:id>')
@authenticate_token
@check_ownership
def delete_blog(id):
    supabase.table("blogs").delete().eq("id", id).execute()
    return 'Blog deleted'

@app.put('/blogs/<path:id>')
@authenticate_token
@check_ownership
def update_blog(id):
    data = request.get_json()
    title = data['title']
    content = data['content']
    supabase.table("blogs").update({"title": title, "content": content}).eq("id", id).execute()
    return 'Blog updated'

@app.route('/logout', methods=['POST'])
def logout():
    resp = make_response('Logged out')
    resp.set_cookie('authToken', '', expires=0)
    return resp
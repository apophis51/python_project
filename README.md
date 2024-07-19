# Hello Everyone and Welcome to the BackEnd Python API DEMO!


For convience I have deployed the backend so that you can test the various endpoints using your favorite endpoint tester! (mine is [Postman](https://www.postman.com/downloads/))






You can also run the app locally doing a **git pull** and by pip installing the **requirements.txt** file. It's recomended that you use a virtual environment.


**Note:** to run locally you will need to use my **.env** variables for the Database request (just send me an email if you want to run the app locally). I used a postgres database model to store the data on Supabase. However, running locally is not requirement if you decide to test against my live endpoint.

**Also:** The Remainder of the document assumes that your following along against my live deployed backend. We recommend using Postman(or similar) to demo my endpoints because we rely on jwts/cookies to store the session data. Browsers and Apps like Postman handle cookie transfers right out the box, but testing by other means (curl or requests library for example) might require more setup.

**Disclaimer:** I also wasn't able to finish the unit tests due to a busy work week, so I suppose I'll need to take a hit there

## Registration Route

Make a **Post** request to  'https://pythonproject-production-bcef.up.railway.app/register' and be sure to include the **username** and '**password** in the request body in raw **json** format 

**example:** '{"username":"boss","password":"giveThatGuyTheJob"}

Behind the scenes we use the Flask Native **werkzeug.security** library to hash and store your chosen password into our superbase User Model

```Python
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
```

## Login Route
Make a **POST** request to  'https://pythonproject-production-bcef.up.railway.app/login' and be sure to include the **username** and '**password** in the request body in raw **json** format: 

**example:** '{"username":"boss","password":"giveThatGuyTheJob"}

Behind the scenes we generate an encoded jwt that we then send back with the response so that you can continue to make request without constantly needing to relogin in

```python
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    supabase_user = supabase.table("user").select("username, password").eq("username", username).execute()
    
    stored_supabase_pass_for_user = supabase_user.data[0]['password']
    if supabase_user and check_password_hash(stored_supabase_pass_for_user, password):
        token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'])
        resp = make_response('Logged in')
        resp.set_cookie('authToken', token, httponly=True)
        return resp
    else:
        return 'Invalid credentials', 401
```

## Logout Route
Make a **POST** request to  'https://pythonproject-production-bcef.up.railway.app/logout' 

To make it happen we force your cookie to expire:

```python
@app.route('/logout', methods=['POST'])
def logout():
    resp = make_response('Logged out')
    resp.set_cookie('authToken', '', expires=0)
    return resp
```

## Get All Blogs
Make a **GET** request to  'https://pythonproject-production-bcef.up.railway.app/blogs'

This will send you back a json string with all the blog post. 
The response should look similar to this: 
```bash
[
    {
        "author": "baa1844f-9f06-46ba-a4ce-594d486fc78c",
        "content": "Look at Me I'm A BLOG!",
        "created_at": "2024-07-19T09:49:38.891314+00:00",
        "id": 10,
        "title": "This is a Blog"
    },
    {
        "author": "1600af95-6a9b-4006-9175-08f87aa841d3",
        "content": "Isn't Nonsense Fun to Read?",
        "created_at": "2024-07-19T09:50:33.147921+00:00",
        "id": 11,
        "title": "Look At Me I'm Another Blog"
    }
]
```

**Note:** This route is **protected** and get request will only work if you are **LoggedIN**

Any user can view blogs posted by any user but you account must be authenticated which we validate through custom middleware:

```python
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
```

## Get A Blog By ID
Make a **GET** request to  'https://pythonproject-production-bcef.up.railway.app/blogs/[blogID]'

**example:** try making a get request to **https://pythonproject-production-bcef.up.railway.app/blogs/10**

The response should look similar to this: 
```bash
[
    {
        "author": "baa1844f-9f06-46ba-a4ce-594d486fc78c",
        "content": "Look at Me I'm A BLOG!",
        "created_at": "2024-07-19T09:49:38.891314+00:00",
        "id": 10,
        "title": "This is a Blog"
    }
]
```

Again, any user can view any blog as long as the account is authenticated

## Make A Blog
Make a **POST** request to  'https://pythonproject-production-bcef.up.railway.app/blogs[blogID]' and be sure to include the **title** and '**content** in the request body in raw **json** format: 

**example:** 
1) {"title":"This is a New Blog","content":"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in"}

2) Then make a **GET** request to  'https://pythonproject-production-bcef.up.railway.app/blogs' and you should see your new blog in the response :)

**NOTE:** Any, user can make a blog as long as the account is authenticated.

## Edit A Blog
Make a **PUT** request to  'https://pythonproject-production-bcef.up.railway.app/blogs[blogID]' and be sure to include the nd be sure to include the **title** and '**content** in the request body in raw **json** format 

**example:** 

1) follow the login endpoint to login as {"username": "charlie51", "password":"applesauce"}.  

2) Then make a **PUT** request to  https://pythonproject-production-bcef.up.railway.app/blogs10 to edit his blog with the new blog information

   {"title":"This is a New Blog","content":"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in"}

3) Then Make a **GET** request to  'https://pythonproject-production-bcef.up.railway.app/blogs/10'  and you should see your new blog in the response :)

**Note** Users can only edit blogs that they created! For that we use custom middleware to validate that the user is thw owner of the blog before the request is validated

```python
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
```

## Delete A Blog
Make a **DELETE** request to  'https://pythonproject-production-bcef.up.railway.app/blogs[blogID]'

Only Users can delete the blogs they created



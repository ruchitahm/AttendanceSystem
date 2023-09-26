# from flask import Flask, session, request, redirect

# app = Flask(__name__)

# GOOGLE_CLIENT_ID = "617873100676-141omc8170h7eucop5hlh2fptunpv790.apps.googleusercontent.com"
# GOOGLE_CLIENT_SECRET = "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"

# @app.route("/login")
# def login():
#     if request.args.get("next"):
#         session["next"] = request.args.get("next")
#     return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?scope=https://www.googleapis.com/auth/userinfo.profile&access_type=offline&include_granted_scopes=true&response_type=code&redirect_uri=https://127.0.0.1:5000/authorized&client_id={GOOGLE_CLIENT_ID}")

# @app.route("/authorized")
# def authorized():
#     r = requests.post("https://oauth2.googleapis.com/token", data={
#         "cleint_id": GOOGLE_CLIENT_ID,
#         "client_secret": GOOGLE_CLIENT_SECRET,
#         "code": request.args.get("code"),
#         "grant_type": "code",
#         "redirect_uri": "https://127.0.0.1:5000/authorized"
#     })
#     return r.json()


#     ===========


# # app.py
# from flask import Flask, request, redirect, session, jsonify
# import requests
# import os

# secret_key = os.urandom(24)

# app = Flask(__name__)

# app.secret_key = os.urandom(24)  # Change this to a secure secret key

# # Google OAuth configuration
# GOOGLE_CLIENT_ID = '617873100676-141omc8170h7eucop5hlh2fptunpv790.apps.googleusercontent.com'  # Replace with your actual Google Client ID
# GOOGLE_CLIENT_SECRET = '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'  # Replace with your actual Google Client Secret
# GOOGLE_REDIRECT_URI = 'http://localhost:5000/auth/google/callback'  # Adjust the URL as needed

# # Google OAuth endpoints
# GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
# GOOGLE_TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'
# GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'

# @app.route('/auth/google')
# def google_login():
#     # Generate the Google OAuth URL
#     # auth_url = f'{GOOGLE_AUTH_URL}?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=email profile'
#     auth_url = GOOGLE_AUTH_URL + "?client_id=" + GOOGLE_CLIENT_ID + "&redirect_uri=" + GOOGLE_REDIRECT_URI + "&response_type=code&scope=email profile"
#     return redirect(auth_url)

# @app.route('/auth/google/callback')
# def google_callback():
#     # Handle the Google OAuth callback
#     auth_code = request.args.get('code')
    
#     if auth_code:
#         # Exchange the authorization code for an access token
#         token_data = {
#             'code': auth_code,
#             'client_id': GOOGLE_CLIENT_ID,
#             'client_secret': GOOGLE_CLIENT_SECRET,
#             'redirect_uri': GOOGLE_REDIRECT_URI,
#             'grant_type': 'authorization_code'
#         }
        
#         token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
#         token_json = token_response.json()
        
#         if 'access_token' in token_json:
#             # Fetch user information using the access token
#             access_token = token_json['access_token']
#             # user_info_response = requests.get(GOOGLE_USERINFO_URL, headers={'Authorization': f'Bearer {access_token}'})
#             user_info_response = requests.get(GOOGLE_USERINFO_URL, headers={'Authorization': 'Bearer {}'.format(access_token)})
#             user_info_json = user_info_response.json()
            
#             # Store user information in the session
#             session['user_info'] = user_info_json
            
#             # Redirect to a success page or handle the user data as needed
#             return redirect('/success')
    
#     # Handle authentication failure
#     return 'Google authentication failed.'

# @app.route('/success')
# def success():
#     # Access user information from the session
#     user_info = session.get('user_info')
    
#     if user_info:
#         return jsonify({'message': 'Login successful', 'user_info': user_info})
#     else:
#         return 'User information not found.'

# @app.route('/logout')
# def logout():
#     # Clear the session when logging out
#     session.clear()
#     return 'Logged out successfully'

# if __name__ == '__main__':
#     app.run(debug=True)


import os
import pathlib

import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests


app = Flask("__name__")
app.secret_key = "test.com"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "463425613111-pnpd0n1jfasn9r97bh65eh2c0b8lt21q.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)
    # session["google_id"] = "Test"
    # return redirect("/protected_area")

@app.route("/callback")
def callback():
    # pass
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")

@app.route("/logout")
def logout():
    session.clear()
    # return redirect("/")
    global flow  # Use a global variable for the flow
    flow = Flow.from_client_secrets_file(
        client_secrets_file=client_secrets_file,
        scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
        redirect_uri="http://127.0.0.1:5000/callback"
    )
    return redirect("/")

@app.route("/")
def index():
    return "Hello World <a href='/login'><button>Login</button></a>"

@app.route("/protected_area")
@login_is_required
def protected_area():
    return "Protected <a href='/logout'><button>Logout</button></a>"

if __name__ == "__main__":
    app.run(debug=True)
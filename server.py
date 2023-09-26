import json

import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, redirect, render_template, session, url_for, request, jsonify
from flask_cors import CORS
import secrets
import json

app = Flask(__name__)
CORS(app)  # Allow CORS for all routes

appConf = {
    "OAUTH2_CLIENT_ID": "463425613111-pnpd0n1jfasn9r97bh65eh2c0b8lt21q.apps.googleusercontent.com",
    "OAUTH2_CLIENT_SECRET": "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",
    "OAUTH2_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": "0004rfe-fefnk-f43r32",
    "FLASK_PORT": 5000
}
# app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
# app.secret_key = appConf.get("FLASK_SECRET")

oauth = OAuth(app)
# list of google scopes - https://developers.google.com/identity/protocols/oauth2/scopes
oauth.register(
    "myApp",
    client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
        # 'code_challenge_method': 'S256'  # enable PKCE
    },
    server_metadata_url=f'{appConf.get("OAUTH2_META_URL")}',
)


# @app.route("/")
# def home():
#     # return render_template('home.html')
#     return render_template("home.html", session=session.get("user"),
#                            pretty=json.dumps(session.get("user"), indent=4))

@app.route("/")
def home():
    userinfo = session.get("user")
    return render_template("home.html", userinfo=userinfo, 
                            pretty=json.dumps(userinfo, indent=4))

@app.route('/generate_token', methods=['GET'])
def generate_token():
    token = secrets.token_hex(32)  # Generate a unique token
    session['token'] = token  # Store the token in the session
    return jsonify({'token': token})

@app.route("/callback")
def googleCallback():
    # fetch access token and id token using authorization code
    token = oauth.myApp.authorize_access_token()

    # google people API - https://developers.google.com/people/api/rest/v1/people/get
    # Google OAuth 2.0 playground - https://developers.google.com/oauthplayground
    # make sure you enable the Google People API in the Google Developers console under "Enabled APIs & services" section

    # fetch user data with access token
    # personDataUrl = "https://people.googleapis.com/v1/people/me?personFields=genders,birthdays"
    # personData = requests.get(personDataUrl, headers={
    #     "Authorization": f"Bearer {token['access_token']}"
    # }).json()
    # token["personData"] = personData
    # set complete user information in the session

    # Save user data to a JSON file
    with open('user_data.json', 'w') as json_file:
        json.dump(token, json_file)

    # set complete user information in the session
    session["user"] = token
    session["userinfo"] = {
    "preferred_username": "username",
    "email": "user@example.com",
    # Add other user data here
}
    return redirect(url_for("home"))

@app.route('/get_user_data', methods=['GET'])
def get_user_data():
    user_data = session.get("userinfo")

    if user_data:
        return jsonify({
            "preferred_username": user_data.get("preferred_username"),
            "email": user_data.get("email"),
            # Add other user data fields here
        })
    else:
        return "User data not found", 404


@app.route("/google-login")
def googleLogin():
    if "user" in session:
        abort(404)
    return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))


@app.route("/logout")
def logout():
    session.clear()
    session.pop("user", None)
    
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=appConf.get(
        "FLASK_PORT"), debug=True)

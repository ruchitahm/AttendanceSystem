<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <title>Generate Token</title>
    <style>
        #generateTokenButton {
            display: block;
            visibility: visible;
        }
    </style>
</head>
<body>
    <h1>One-Time-Use Token Generator</p>
    <button id="generateTokenButton">Generate Token</button>
    <p id="tokenResult"></p>

    <script>

document.getElementById("generateTokenButton").addEventListener("click", async function () {
    try {
        // const response = await fetch('http://127.0.0.1:5000/generate_token');
    //    const response = await fetch('http://127.0.0.1:5000/generate_token');
    const response = await fetch('http://127.0.0.1:5000/generate_token');

        const data = await response.json();
        document.getElementById("tokenResult").textContent = "Token: " + data.token;
    } catch (error) {
        console.error('Error fetching token:', error);
    }
});

    </script>
</body>

</html>


import secrets

from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow CORS for all routes


# app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Set a secret key for session management

@app.route('/generate_token', methods=['GET'])
def generate_token():
    token = secrets.token_hex(32)  # Generate a unique token
    session['token'] = token  # Store the token in the session
    return jsonify({'token': token})

@app.route('/')
def home():
    return render_template('home.html')
              
if __name__ == '__main__':
    app.run(debug=True)

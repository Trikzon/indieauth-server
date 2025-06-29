import base64
from flask import Flask, jsonify, redirect, request, render_template, session
import hashlib
import os
import requests
import secrets
import sqlite3

DATABASE = "tokens.db"

ISSUER = "https://indieauth.tryban.dev/"
AUTHORIZATION_ENDPOINT = "https://indieauth.tryban.dev/auth"
TOKEN_ENDPOINT = "https://indieauth.tryban.dev/token"

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
GITHUB_AUTH_CALLBACK = "http://127.0.0.1:5000/auth/github/callback"

with sqlite3.connect(DATABASE) as conn:
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_codes (
            auth_code             TEXT      PRIMARY KEY,
            client_id             TEXT      NOT NULL,
            redirect_uri          TEXT      NOT NULL,
            code_challenge        TEXT      NOT NULL,
            code_challenge_method TEXT      NOT NULL,
            scope                 TEXT      NOT NULL,
            expires_at TIMESTAMP  TIMESTAMP NOT NULL
        );
    ''')

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]


@app.route("/.well-known/oauth-authorization-server")
def oauth_authorization_server():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": AUTHORIZATION_ENDPOINT,
        # "token_endpoint": TOKEN_ENDPOINT,
        "code_challenge_methods_supported": ["S256"],
    })


def validate_auth_request(args: dict) -> dict:
    if args is None:
        return None
    
    me = args.get("me")
    if me != "https://tryban.dev/":
        return None

    response_type = args.get("response_type")
    if response_type != "code":
        return None

    client_id = args.get("client_id")
    redirect_uri = args.get("redirect_uri")
    state = args.get("state")
    if client_id is None or redirect_uri is None or state is None:
        return None
    
    # TODO: Verify that client_id and redirect_uri are the same or allowed.

    code_challenge = args.get("code_challenge")
    code_challenge_method = args.get("code_challenge_method")
    if code_challenge is None or code_challenge_method != "S256":
        return None

    scope = args.get("scope", "")

    return {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
        "me": me,
    }


def create_auth_code(auth_request: dict) -> str:
    auth_request = validate_auth_request(auth_request)

    if auth_request is None:
        return None
    
    auth_code = secrets.token_urlsafe(32)
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO auth_codes VALUES (?, ?, ?, ?, ?, ?, datetime('now', '+10 minutes'));",
            (
                auth_code,
                auth_request["client_id"],
                auth_request["redirect_uri"],
                auth_request["code_challenge"],
                auth_request["code_challenge_method"],
                auth_request["scope"]
            )
        )
    
    return auth_code


def verify_auth_code(auth_code: str, client_id: str, redirect_uri: str, code_verifier: str) -> bool:
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM auth_codes WHERE auth_code = ?;", (auth_code,))
        row = cursor.fetchone()

        if row is None:
            return False
        
        cursor.execute("DELETE FROM auth_codes WHERE auth_code = ?;", (auth_code,))
        conn.commit()

        cursor.execute("SELECT CURRENT_TIMESTAMP;")
        current_time = cursor.fetchone()[0]

        if row["client_id"] != client_id or row["redirect_uri"] != redirect_uri:
            return False

        if row["expires_at"] <= current_time:
            return False

        if row["code_challenge_method"] != "S256":
            return False
        
        sha256_digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed_challenge = base64.urlsafe_b64encode(sha256_digest).decode("ascii").rstrip("=")

        if computed_challenge != row["code_challenge"]:
            return False
        
        return True


def create_access_token() -> str:
    access_token = secrets.token_urlsafe(32)
    return access_token


@app.route("/auth", methods=["GET", "POST"])
def auth():
    if request.method == "GET":
        auth_request = validate_auth_request(request.args)
        if auth_request is None:
            return "Invalid request."

        return render_template("auth.html", **auth_request)
    
    grant_type = request.form.get("grant_type")
    auth_code = request.form.get("code")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    code_verifier = request.form.get("code_verifier")

    if grant_type != "authorization_code":
        return "Invalid request."
    
    if not verify_auth_code(auth_code, client_id, redirect_uri, code_verifier):
        return "Invalid request."
    
    return jsonify({
        "me": "https://tryban.dev/"
    })


@app.route("/auth/github", methods=["POST"])
def auth_github():
    auth_request = validate_auth_request(request.form)
    if auth_request is None:
        return "Invalid request."
    
    session["auth_request"] = auth_request

    state = secrets.token_urlsafe(32)
    session["github_state"] = state

    return redirect(
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_AUTH_CALLBACK}"
        f"&state={state}"
    )


@app.route("/auth/github/callback")
def auth_github_callback():
    access_token = request.args.get("code")
    state = request.args.get("state")

    if state != session.pop("github_state", None):
        return "Invalid request."
    
    auth_request = validate_auth_request(session.pop("auth_request", None))
    if auth_request is None:
        return "Invalid request."

    resp = requests.post(
        f"https://github.com/login/oauth/access_token"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&client_secret={GITHUB_CLIENT_SECRET}"
        f"&code={access_token}"
        f"&redirect_uri={GITHUB_AUTH_CALLBACK}",
        headers={"Accept": "application/json"}
    )

    access_token = resp.json().get("access_token")

    if not access_token:
        return "Invalid request."
    
    resp = requests.get("https://api.github.com/user", headers={"Authorization": f"token {access_token}"})

    if resp.status_code != 200:
        return "Invalid request."
    
    # TODO: Use rel-me instead of strict comparison
    if resp.json().get("html_url") != "https://github.com/Trikzon":
        return "Invalid request."
    
    auth_code = create_auth_code(auth_request)
    if auth_code is None:
        return "Invalid request."
    
    return redirect(
        f"{auth_request['redirect_uri']}"
        f"?code={auth_code}"
        f"?state={auth_request['state']}"
        f"?iss={ISSUER}"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

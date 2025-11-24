import os
from flask import Flask, render_template, session, request, redirect, url_for
import msal
import requests
from dotenv import load_dotenv

# 環境変数の読み込み
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # セッション管理用のキー

# 設定値の取得
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTHORITY = os.getenv("AUTHORITY")
REDIRECT_PATH = os.getenv("REDIRECT_PATH")
ENDPOINT = os.getenv("ENDPOINT")
SCOPE = [os.getenv("SCOPE")]

# .env に正しい大学のテナントIDを定義しておくこと
TARGET_TENANT_ID = os.getenv("TENANT_ID") 


# MSALアプリの初期化関数
def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=authority or AUTHORITY,
        client_credential=CLIENT_SECRET,
        token_cache=cache
    )

@app.route("/")
def index():
    # セッションにユーザー情報がなければログインページへ
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template('index.html', user=session["user"], version=msal.__version__)

@app.route("/login")
def login():
    # セッションステートを作成（CSRF対策）
    session["flow"] = _build_msal_app().initiate_auth_code_flow(
        SCOPE, redirect_uri=url_for("authorized", _external=True))
    
    # Microsoftのログイン画面へリダイレクト
    return redirect(session["flow"]["auth_uri"])


@app.route(REDIRECT_PATH)
def authorized():
    try:
        cache = msal.SerializableTokenCache()
        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=SCOPE,
            flow=session.get("flow"),
            redirect_uri=url_for("authorized", _external=True))
        
        if "error" in result:
            return "Login failure: " + result.get("error_description")
        
        claims = result.get("id_token_claims")
        
        # --- ここに追加: テナントIDチェック ---
        if claims.get("tid") != TARGET_TENANT_ID:
             return "Error: Access denied. このアプリは愛知工業大学のアカウントでのみ利用可能です。"
        # -----------------------------------

        session["user"] = claims
        return redirect(url_for("index"))
        
    except ValueError:
        return "Invalid Setup or Session Expired"
    

@app.route("/logout")
def logout():
    session.clear()
    # Microsoft側からもログアウトさせる場合のリダイレクト先
    return redirect(
        f"{AUTHORITY}/oauth2/v2.0/logout?post_logout_redirect_uri={url_for('index', _external=True)}"
    )

if __name__ == "__main__":
    # HTTPSでないと動作しない場合があるため、開発中はlocalhostを使用
    app.run(host='localhost', port=5000, debug=True)
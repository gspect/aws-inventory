# okta_auth.py — Shared Okta OIDC auth for Flask apps
import os
import sys
from functools import wraps
from flask import session, redirect, request, Blueprint
from authlib.integrations.flask_client import OAuth

oauth = OAuth()
okta_bp = Blueprint("auth", __name__)

# Set DISABLE_AUTH=1 to run without login (local/trusted-network use only).
AUTH_DISABLED = os.environ.get("DISABLE_AUTH") == "1"
OKTA_CONFIGURED = all(os.environ.get(k) for k in ("OKTA_DOMAIN", "OKTA_CLIENT_ID", "OKTA_CLIENT_SECRET"))


def init_okta(app):
    if AUTH_DISABLED:
        print("WARNING: DISABLE_AUTH=1 - authentication is OFF. Do not expose this app.", file=sys.stderr)
        return
    if not OKTA_CONFIGURED:
        print("WARNING: OKTA_DOMAIN / OKTA_CLIENT_ID / OKTA_CLIENT_SECRET are not all set; "
              "login will fail. Set them, or set DISABLE_AUTH=1 for local use.", file=sys.stderr)
        return
    oauth.init_app(app)
    oauth.register(
        name="okta",
        client_id=os.environ.get("OKTA_CLIENT_ID"),
        client_secret=os.environ.get("OKTA_CLIENT_SECRET"),
        server_metadata_url=f"https://{os.environ.get('OKTA_DOMAIN')}/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if AUTH_DISABLED:
            return f(*args, **kwargs)
        if "user" not in session:
            session["next_url"] = request.url
            base = os.environ.get("APP_BASE_URL", "/aws-inventory")
            return redirect(base + "/auth/login")
        return f(*args, **kwargs)
    return decorated


@okta_bp.route("/auth/login")
def login():
    if not OKTA_CONFIGURED:
        return "Okta is not configured. Set OKTA_DOMAIN, OKTA_CLIENT_ID and OKTA_CLIENT_SECRET.", 500
    base = os.environ.get("APP_BASE_URL", "/aws-inventory")
    redirect_uri = request.host_url.rstrip("/") + base + "/auth/callback"
    return oauth.okta.authorize_redirect(redirect_uri)


@okta_bp.route("/auth/callback")
def callback():
    token = oauth.okta.authorize_access_token()
    user  = token.get("userinfo")
    if user:
        session["user"] = {
            "email": user.get("email"),
            "name":  user.get("name"),
        }
    base = os.environ.get("APP_BASE_URL", "/aws-inventory")
    next_url = session.pop("next_url", base + "/")
    return redirect(next_url)


@okta_bp.route("/auth/logout")
def logout():
    session.clear()
    base = os.environ.get("APP_BASE_URL", "/aws-inventory")
    return redirect(base + "/")


#@okta_bp.route("/auth/logout")
#def logout():
#    session.clear()
#    domain = os.environ.get("OKTA_DOMAIN", "")
#    logout_url = (
#        f"https://{domain}/v1/logout"
#        f"?post_logout_redirect_uri={request.host_url}"
#    )
#    return redirect(logout_url)

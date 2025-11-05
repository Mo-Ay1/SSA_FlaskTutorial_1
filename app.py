"""
Secure Flask application factory with sensible defaults:
- Config from environment
- CSRF protection (if flask-wtf installed)
- Secure headers via Flask-Talisman (if installed) or fallback headers
- Rate limiting (if flask-limiter installed)
- Rotating file logging
- Safe defaults for cookies and sessions
"""

import os
import logging
import secrets
from datetime import timedelta

from flask import Flask, jsonify, request, abort

# Optional security libs (best-effort; app works without them)
try:
    from flask_wtf import CSRFProtect
except Exception:
    CSRFProtect = None

try:
    from flask_talisman import Talisman
except Exception:
    Talisman = None

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:
    Limiter = None
    get_remote_address = None


class Config:
    """Base configuration. Override via environment variables."""
    SECRET_KEY = os.environ.get("SECRET_KEY") or None  # filled later if None
    SESSION_COOKIE_SECURE = True  # require HTTPS for cookie transport
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(days=int(os.environ.get("SESSION_DAYS", "7")))
    WTF_CSRF_ENABLED = True  # used by flask-wtf if present
    # Recommended to set FLASK_ENV=production and not use debug in prod
    DEBUG = os.environ.get("FLASK_DEBUG", "0") in ("1", "true", "True")


def create_app(config_object=Config):
    """App factory to create a secure Flask app instance."""
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_object)

    # Ensure a SECRET_KEY exists; generate ephemeral for dev only
    if not app.config.get("SECRET_KEY"):
        if app.config["DEBUG"]:
            app.logger.warning("No SECRET_KEY set in environment; generating ephemeral key for debug session.")
            app.config["SECRET_KEY"] = secrets.token_hex(32)
        else:
            raise RuntimeError("SECRET_KEY must be set in environment for production.")

    # Logging: Rotating file handler for production; keep console output for debug
    if not app.debug:
        try:
            from logging.handlers import RotatingFileHandler
            log_dir = os.path.join(os.getcwd(), "logs")
            os.makedirs(log_dir, exist_ok=True)
            fh = RotatingFileHandler(os.path.join(log_dir, "app.log"), maxBytes=10 * 1024 * 1024, backupCount=5)
            formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]")
            fh.setFormatter(formatter)
            fh.setLevel(logging.INFO)
            app.logger.addHandler(fh)
            app.logger.setLevel(logging.INFO)
            app.logger.info("Application startup")
        except Exception:
            app.logger.exception("Failed to configure file logging; continuing with default logger.")

    # CSRF protection (optional)
    if CSRFProtect:
        csrf = CSRFProtect()
        csrf.init_app(app)
    else:
        app.logger.info("flask-wtf not installed; CSRF protection not enabled via flask-wtf.")

    # Security headers via Talisman (optional) or manual fallback
    csp = {
        "default-src": ["'self'"],
        # Further tighten CSP for your app's assets and scripts as needed
    }
    if Talisman:
        Talisman(
            app,
            content_security_policy=csp,
            strict_transport_security=True,
            strict_transport_security_max_age=31536000,
            strict_transport_security_include_subdomains=True,
            frame_options="DENY",
            session_cookie_secure=True,
            session_cookie_http_only=True,
            session_cookie_samesite="Lax",
        )
    else:
        app.logger.info("flask-talisman not installed; applying minimal security headers via fallback.")
        @app.after_request
        def set_security_headers(response):
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault("Referrer-Policy", "no-referrer-when-downgrade")
            # HSTS only when serving HTTPS
            if request.is_secure:
                response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            # Basic CSP fallback
            response.headers.setdefault("Content-Security-Policy", "default-src 'self'")
            return response

    # Rate limiting (optional)
    if Limiter and get_remote_address:
        limiter = Limiter(key_func=get_remote_address)
        limiter.init_app(app)
    else:
        app.logger.info("flask-limiter not installed; rate limiting not enabled.")

    # Example simple routes
    @app.route("/health", methods=["GET"])
    def health():
        return jsonify(status="ok"), 200

    @app.route("/", methods=["GET"])
    def index():
        return jsonify(message="Secure Flask app", env=("debug" if app.debug else "production")), 200

    # Example endpoint demonstrating safe file access (don't expose arbitrary paths)
    @app.route("/read-static/<path:filename>", methods=["GET"])
    def read_static(filename):
        # Only serve from a designated safe directory; avoid path traversal
        from werkzeug.utils import safe_join
        safe_dir = os.path.join(os.getcwd(), "static_files")
        try:
            path = safe_join(safe_dir, filename)
            if not path or not os.path.isfile(path):
                abort(404)
            with open(path, "rb") as f:
                data = f.read()
            return (data, 200, {"Content-Type": "application/octet-stream"})
        except Exception:
            app.logger.exception("Error serving static file.")
            abort(404)

    # Generic error handlers (avoid leaking internals)
    @app.errorhandler(404)
    def not_found(e):
        return jsonify(error="not_found"), 404

    @app.errorhandler(500)
    def internal_error(e):
        # Log details but return generic message
        app.logger.exception("Internal server error")
        return jsonify(error="internal_server_error"), 500

    return app


if __name__ == "__main__":
    app = create_app()
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = app.debug

    # Prefer a production WSGI server if available
    if not debug:
        try:
            from waitress import serve
            app.logger.info("Starting with waitress on %s:%d", host, port)
            serve(app, host=host, port=port)
        except Exception:
            app.logger.warning("waitress not available; falling back to Flask built-in server.")
            app.run(host=host, port=port, debug=debug)
    else:
        # In dev containers, you can open the host browser with: $BROWSER http://localhost:5000
        app.run(host=host, port=port, debug=debug)
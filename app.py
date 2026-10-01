"""TH2: Flask Blueprints, before_request middleware and signed JWT."""
import os
import secrets
from pathlib import Path

from flask import Flask, jsonify, render_template

from database import init_db
from routes import account, protected


def create_app(test_config=None):
    app = Flask(__name__)
    app.json.ensure_ascii = False
    instance = Path(app.instance_path)
    instance.mkdir(exist_ok=True)
    app.config.update(DATABASE=str(instance / 'users.db'), JWT_TTL=900,
                      MAX_CONTENT_LENGTH=16384)
    if test_config:
        app.config.update(test_config)
    if not app.config.get('JWT_SECRET'):
        secret = os.environ.get('JWT_SECRET')
        if not secret:
            secret_file = instance / '.jwt-secret'
            if not secret_file.exists():
                secret_file.write_text(secrets.token_hex(32), encoding='utf-8')
            secret = secret_file.read_text(encoding='utf-8').strip()
        app.config['JWT_SECRET'] = secret
    if len(app.config['JWT_SECRET'].encode()) < 32:
        raise ValueError('JWT_SECRET must contain at least 32 bytes')
    init_db(app)
    app.register_blueprint(account)
    app.register_blueprint(protected)

    @app.get('/')
    def home():
        return render_template('index.html')

    @app.get('/docs')
    def docs():
        return render_template('swagger.html')

    @app.get('/openapi.json')
    def spec():
        return app.send_static_file('openapi.json')

    @app.errorhandler(404)
    def not_found(error):
        return jsonify(error='NOT_FOUND'), 404

    @app.errorhandler(413)
    def body_too_large(error):
        return jsonify(error='BODY_TOO_LARGE'), 413

    @app.errorhandler(405)
    def wrong_method(error):
        response = jsonify(error='METHOD_NOT_ALLOWED')
        response.status_code = 405
        response.headers['Allow'] = ', '.join(error.valid_methods or [])
        return response

    @app.after_request
    def no_cache(response):
        if not app.config.get('TESTING'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    return app


if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=5001, debug=False)

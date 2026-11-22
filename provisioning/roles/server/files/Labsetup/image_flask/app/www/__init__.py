import os
from flask import Flask
from .config import Config


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    if test_config is None:
        app.config.from_object(Config)
    else:
        app.config.from_mapping(test_config)

    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    from . import lab
    app.register_blueprint(lab.bp)
    app.add_url_rule('/', endpoint='index')
    return app

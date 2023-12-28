import hashlib
import time

from flask import Blueprint, current_app


def generate_csrf():
    salt= current_app.config['SECRET_KEY']
    ha = hashlib.md5(salt.encode('utf-8'))
    time_span = time.time()
    ha.update(bytes(f'{salt}|{time_span}', encoding='utf-8'))
    encryption = ha.hexdigest()
    csrf_token = f'{encryption}|{time_span}'
    return csrf_token


def validate_csrf(csrf_token):
    if not csrf_token:
        raise Exception('csrf missing')
    sp = csrf_token.split('|')
    if len(sp) != 2:
        raise Exception('csrf format error')
    encrypt, timestamp = sp
    timestamp = float(timestamp)
    limit_timestamp = time.time() - 3600
    if limit_timestamp > timestamp:
        raise Exception('csrf timeout')
    salt = current_app.config['SECRET_KEY']
    ha = hashlib.md5(salt.encode('utf-8'))
    ha.update(bytes(f'{salt}|{timestamp}', encoding='utf-8'))
    result = ha.hexdigest()
    if encrypt != result:
        raise Exception('csrf checking failed')


class CSRFProtect:

    def __init__(self, app=None):
        self._exempt_views = set()
        self._exempt_blueprints = set()
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.extensions['csrf'] = self

        app.jinja_env.globals['csrf_token'] = generate_csrf
        app.context_processor(lambda: dict(csrf_token=generate_csrf))

        @app.before_request
        def csrf_protect():
            if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
                return
            if not request.endpoint:
                return
            if request.blueprint in self._exempt_blueprints:
                return
            view = app.view_functions.get(request.endpoint)
            dest = f'{view.__module__}.{view.__name__}'
            if dest in self._exempt_views:
                return
            self.protect()

    def _get_csrf_token(self):
        base_token = request.form.get('csrf_token')
        if base_token:
            return base_token
        for header_name in ('X-CSRFToken', 'X-CSRF-Token'):
            csrf_token = request.headers.get(header_name)
            if csrf_token:
                return csrf_token
        return None

    def protect(self):
        try:
            validate_csrf(self._get_csrf_token())
        except Exception as e:
            raise Exception(f'failed validate csrf_token:\n{e}')
        return

    def exempt(self, view):
        if isinstance(view, Blueprint):
            self._exempt_blueprints.add(view.name)
            return view
        if isinstance(view, (str,)):
            view_location = view
        else:
            view_location = '.'.join((view.__module__, view.__name__))
        self._exempt_views.add(view_location)
        return view

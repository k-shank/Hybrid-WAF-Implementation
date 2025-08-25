"""A very simple REST service used for testing the WAF.

This Flask application exposes a single endpoint ``/srs/api/hello/<name>``
accepting both GET and POST methods.  It simply returns a greeting.  Use
``simple_testing.py`` to send requests against this endpoint and observe
how the firewall reacts.
"""

from flask import Flask

app = Flask(__name__)


@app.route('/srs/api/hello/<string:name>', methods=['GET', 'POST'])
def hello(name: str) -> str:
    return 'Hello, ' + name + '!'


if __name__ == '__main__':
    app.run(debug=True)
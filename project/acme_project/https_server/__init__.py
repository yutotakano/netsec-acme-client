from flask import Flask

app = Flask(__name__)


@app.route("/")
def http_challenge() -> bytes:
    return b"Hello World!"

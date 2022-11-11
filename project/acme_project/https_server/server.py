from flask import Flask

app = Flask(__name__)


@app.route("/")
def http_challenge() -> bytes:
    app.logger.debug("http-01 challenge validation occured")
    return b"Hello World!"

from flask import Flask
from flask import request

app = Flask(__name__)


@app.route("/shutdown")
def shutdown() -> bytes:
    shutdown_func = request.environ.get("werkzeug.server.shutdown")
    if shutdown_func is None:
        return b"wekzeug.server.shutdown function could not be found. Can not shutdown server."

    shutdown_func()
    return b""

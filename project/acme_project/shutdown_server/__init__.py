import threading

from flask import Flask

app = Flask(__name__)
shutdown_requested = threading.Event()


@app.route("/shutdown")
def shutdown() -> bytes:
    shutdown_requested.set()
    return b"Shutdown requested!"

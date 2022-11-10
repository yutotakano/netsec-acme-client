import threading

from acme_project.shutdown_server import server


def start_thread():
    """Start the shutdown HTTP server that flags a semaphore when we receive a
    request to /shutdown.
    """
    shutdown_thread = threading.Thread(
        target=lambda: server.app.run(host="0.0.0.0", port=5003, debug=False),
        daemon=True,
    )
    shutdown_thread.start()

import threading

from acme_project.https_server import server


def start_thread(cert_pem_path: str, key_pem_path: str):
    """Start the main HTTPS server using the specified SSL certificate files.

    Parameters
    ----------
    cert_pem_path : str
        Path to the PEM encoded certificate chain.
    key_pem_path : str
        Path to the PEM encoded private key for the certificate.
    """
    main_server_thread = threading.Thread(
        target=lambda: server.app.run(
            host="0.0.0.0",
            port=5001,
            debug=False,
            ssl_context=(cert_pem_path, key_pem_path),
        ),
        daemon=True,
    )
    main_server_thread.start()

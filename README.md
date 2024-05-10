# ACME Client Implementation

This is a client implementation for the Automatic Certificate Management Environment scheme (ACME) specified in **RFC 8555** and partially in **RFC 7638**. The client is feature-complete and supports:
- fulfilling both `dns-01` and `http-01` challenges;
- issuing and revoking X.509 certificates;
- issuing multi-domain and wildcard certificates;
- communicating with the ACME server using an implementation of JWK built from cryptographic primitives.

This client is implemented in Python (tested with 3.10.7), and is built with code clarity and structure:
- typehints are liberally used to prevent runtime type mismatch errors and improve developer experience (drastically);
- object-oriented structure employed (e.g. ACME Client endpoints all inherit from `Endpoint` which implements `self.retrieve(URL)` to communicate with ACME server);
- project structure and clean imports are emphasised through using Poetry and a modular directory structure.

To set up the dependencies, we use Poetry.
```sh
$ git clone ...
$ cd netsec-acme-client/project
$ pip install poetry
$ poetry install
```

To run the ACME client (requires an ACME server):
```sh
$ cd netsec-acme-client/project
$ poetry run python3 -m acme_project --help
```

> [!NOTE]  
> This project was implemented for the ETH Zurich Network Security HS2022 course, and as such the repository is not maintained on an active basis.

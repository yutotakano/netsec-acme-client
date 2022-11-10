from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from acme_project.acme_client.endpoint import Endpoint


@dataclass
class RevokeCertEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url


@dataclass
class GetCertificateEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url


@dataclass
class Certificate:
    pem_chain: str
    key: str

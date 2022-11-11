from dataclasses import dataclass

from acme_project.acme_client.endpoint import Endpoint


@dataclass
class KeyChangeEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url

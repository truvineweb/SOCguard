from pypsrp.client import Client
from typing import Tuple

class WinRMClient:
    def __init__(self, host: str, username: str, password: str | None,
                 port: int = 5986, ssl: bool = True,
                 cert_validation: bool = True, ca_trust_path: str | None = None,
                 negotiate: bool = True):
        """
        By default we use HTTPS + cert validation. 'negotiate' will try NTLM on Linux.
        """
        self.client = Client(
            server=host,
            username=username,
            password=password,
            port=port,
            ssl=ssl,
            cert_validation=cert_validation,
            ca_trust_path=ca_trust_path,
            negotiate=negotiate,
        )

    def run_ps(self, script: str) -> Tuple[str, str, int]:
        stdout, stderr, rc = self.client.execute_ps(script)
        return stdout, stderr, rc

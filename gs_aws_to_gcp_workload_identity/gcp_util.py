import json
import requests

from google.auth import crypt
from google.auth import jwt


class GcpUtil:
    def __init__(self) -> None:
        pass

    def call_gcp_url(self, body: dict, url: str, auth_token=None) -> dict:

        headers = {
            "content-type": "application/json; charset=utf-8",
            "Accept": "application/json",
        }

        if auth_token is not None:
            headers["Authorization"] = f"Bearer {auth_token}"

        response = requests.post(
            url,
            json=body,
            headers=headers,
        )

        if response.status_code != 200:
            logger.fatal("Error getting Identity token")
            logger.error(response.text)
            response.raise_for_status()

        return response.json()


    def parse_gcp_jwt_expiration(self, token) -> str:

        return jwt.decode(token, certs=None, verify=False).get('exp')

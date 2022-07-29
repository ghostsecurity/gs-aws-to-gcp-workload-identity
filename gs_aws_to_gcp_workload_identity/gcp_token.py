import time
import json
import boto3
import logging
import requests
import urllib.parse

from typing import Tuple
from datetime import datetime
from google.auth import crypt
from google.auth import jwt
from botocore import exceptions
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import ReadOnlyCredentials

from gs_aws_to_gcp_workload_identity.gcp_util import GcpUtil

# import sys
# logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

logger = logging.getLogger(__name__)

class GcpToken:

    def __init__(self,
                 gcp_federated_token: str = None,
                 gcp_service_account_email: str = None,
                 gcp_token_lifetime: str = "3600s",
                 gcp_token_scopes: str = "https://www.googleapis.com/auth/cloud-platform"
                ) -> None:

        self.gcp_federated_token = gcp_federated_token
        self.gcp_service_account_email = gcp_service_account_email
        self.gcp_token_lifetime = gcp_token_lifetime
        self.gcp_token_scopes = gcp_token_scopes

    def get_gcp_oauth_token(self) -> Tuple[str, str]:

        body = {
            "scope": self.gcp_token_scopes.split(","),
            "lifetime": self.gcp_token_lifetime
        }

        url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{self.gcp_service_account_email}:generateAccessToken"

        response = GcpUtil().call_gcp_url(body, url, auth_token=self.gcp_federated_token)

        token = response.get('accessToken', None)
        expires_at = datetime.strptime(response['expireTime'], '%Y-%m-%dT%H:%M:%SZ').strftime('%s')

        return token, expires_at


    def get_gcp_identity_token(self, audience: str) -> Tuple[str, str]:

        body = {
            "audience": audience,
            "includeEmail": True
        }
        url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{self.gcp_service_account_email}:generateIdToken"

        response = GcpUtil().call_gcp_url(body, url, auth_token=self.gcp_federated_token)

        token = response.get('token', None)
        expires_at = GcpUtil().parse_gcp_jwt_expiration(token)

        return token, expires_at

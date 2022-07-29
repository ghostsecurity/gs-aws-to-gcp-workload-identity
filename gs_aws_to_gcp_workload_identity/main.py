import time
import json
import boto3
import logging
import requests
import urllib.parse

from gs_aws_to_gcp_workload_identity.gcp_util import GcpUtil
from gs_aws_to_gcp_workload_identity.gcp_token import GcpToken

from typing import Tuple
from datetime import datetime
from google.auth import crypt
from google.auth import jwt
from botocore import exceptions
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import ReadOnlyCredentials

# import sys
# logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

logger = logging.getLogger(__name__)

class AwsToGcpTokenService:

    def __init__(
        self,
        gcp_workload_provider_path: str,
        gcp_service_account_email: str,
        gcp_token_lifetime: str = "3600s",
        gcp_token_scopes: str = "https://www.googleapis.com/auth/cloud-platform",
        aws_assume_role_arn: str = None,
        aws_region: str = "us-east-1",
        ) -> None:

        # GCP
        self.gcp_workload_provider_path = gcp_workload_provider_path
        self.gcp_service_account_email = gcp_service_account_email
        self.gcp_token_lifetime = gcp_token_lifetime
        self.gcp_token_scopes = gcp_token_scopes

        # Instance vars
        self.gcp_federated_token = None
        self.gcp_sa_token = None
        self.authorization_header = None
        self.refresh_buffer_seconds = 300
        self.oauth_token = None
        self.oauth_token_expires_at = 0
        self.identity_token = None
        self.identity_token_expires_at = 0

        # AWS
        self.aws_region = aws_region
        self.aws_assume_role_arn = aws_assume_role_arn
        self.x_goog_cloud_target_resource = f"//iam.googleapis.com/{self.gcp_workload_provider_path}"
        self.sts_url = 'https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15'
        self.sts_client = boto3.client('sts')

        self.x_amz_date = None
        self._set_x_amz_date()


    def get_oauth_token(self) -> Tuple[str, str]:

        delta = 0
        current_time = int(time.time())
        delta = int(self.oauth_token_expires_at) - current_time

        if self.oauth_token is None or delta <= self.refresh_buffer_seconds:
            federated_access_token = self._get_gcp_federated_token()
            gcp_token = GcpToken(
               gcp_federated_token = federated_access_token,
               gcp_service_account_email = self.gcp_service_account_email,
               gcp_token_lifetime = self.gcp_token_lifetime,
               gcp_token_scopes = self.gcp_token_scopes
            )
            self.oauth_token, self.oauth_token_expires_at = gcp_token.get_gcp_oauth_token()

        return self.oauth_token, self.oauth_token_expires_at


    def get_identity_token(self, audience) -> Tuple[str, str]:

        delta = 0
        current_time = int(time.time())
        delta = int(self.identity_token_expires_at) - current_time

        if self.identity_token is None or delta <= self.refresh_buffer_seconds:
            federated_access_token = self._get_gcp_federated_token()
            gcp_token = GcpToken(
               gcp_federated_token = federated_access_token,
               gcp_service_account_email = self.gcp_service_account_email
            )
            self.identity_token, self.identity_token_expires_at = gcp_token.get_gcp_identity_token(audience)

        return self.identity_token, self.identity_token_expires_at


    def _get_gcp_federated_token(self) -> str:

        aws_key, aws_secret_key, aws_session_token = None, None, None
        credentials = None

        if self.aws_assume_role_arn is not None:
            aws_key, aws_secret_key, aws_session_token = self._aws_assume_role()
        else:
            temp_session = boto3.session.Session()
            aws_key = temp_session.get_credentials().access_key
            aws_secret_key = temp_session.get_credentials().secret_key
            aws_session_token = temp_session.get_credentials().token

        credentials = ReadOnlyCredentials(aws_key, aws_secret_key, aws_session_token)

        self._set_x_amz_date()

        caller_identity_token = self._generate_aws_caller_identity_token(
            self._generate_aws_auth_header(credentials),
            credentials
        )

        encoded_token: str = urllib.parse.quote(json.dumps(caller_identity_token))

        body = {
            "audience": self.x_goog_cloud_target_resource,
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "subjectTokenType": "urn:ietf:params:aws:token-type:aws4_request",
            "subjectToken": encoded_token
        }

        url = "https://sts.googleapis.com/v1/token"
        response = GcpUtil().call_gcp_url(body, url)

        federated_token = response.get('access_token', None)

        return federated_token


    def _aws_assume_role(self) -> Tuple[str, str, str]:

        try:
            logger.info("Assuming AWS IAM Role.")
            assumed_role_object: dict = self.sts_client.assume_role(
                RoleArn=self.aws_assume_role_arn,
                RoleSessionName=self.aws_assume_role_arn.split('/')[-1]
            )
        except exceptions.ClientError as err:
            raise err
        except exceptions.ParamValidationError as err:
            raise ValueError(f'The parameters you provided are incorrect: {err}')

        try:
            credentials: dict = assumed_role_object['Credentials']

            aws_key: str = credentials['AccessKeyId']
            aws_secret_key: str = credentials['SecretAccessKey']
            aws_session_token: str = credentials['SessionToken']

        except KeyError as err:
            logger.error("Something went wrong getting AssumeRole credentials")
            raise err

        return aws_key, aws_secret_key, aws_session_token


    def _set_x_amz_date(self) -> None:
        current_time = datetime.utcnow()
        self.x_amz_date = current_time.strftime('%Y%m%dT%H%M%SZ')


    def _sign_aws_request(
            self,
            data=None,
            params=None,
            headers=None,
            credentials=None
        ) -> str:

        request = AWSRequest(
            url=self.sts_url,
            data=data,
            params=params,
            headers=headers,
            method="POST",
        )
        SigV4Auth(credentials, "sts", self.aws_region).add_auth(request)
        auth_headers = request.headers['Authorization']

        return auth_headers


    def _generate_aws_auth_header(
            self,
            credentials
        ) -> str:

        headers = {
            'host': "sts.amazonaws.com",
            'x-amz-date': self.x_amz_date,
            'x-amz-security-token': credentials.token
        }

        signature = self._sign_aws_request(
            headers=headers,
            params=None,
            data=None,
            credentials=credentials
        )

        return signature


    def _generate_aws_caller_identity_token(
            self,
            authorization_header: str,
            credentials
        ) -> str:

        identity_token = {
            "url": "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
            "method": "POST",
            "headers": [
                {
                    "key": "Authorization",
                    "value" : authorization_header
                },
                {
                    "key": "host",
                    "value": "sts.amazonaws.com"
                },
                {
                    "key": "x-amz-date",
                    "value": self.x_amz_date
                },
                {
                    "key": "x-goog-cloud-target-resource",
                    "value": self.x_goog_cloud_target_resource
                },
                {
                    "key": "x-amz-security-token",
                    "value": credentials.token
                }
            ],
        }

        return identity_token

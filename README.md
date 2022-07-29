# AWS to GCP Workload Identity Federation

If you have workloads running in AWS and want to access GCP services without exporting static GCP service account credentials, this module can leverage workload identity federation to dynamically exchange credentials from an IAM Role in AWS for either an OAuth2 Access Token or Identity Token for a given GCP Service Account.

## Getting Started

### AWS Setup

Set some shell variables for AWS related items for easier setup:

```bash
export AWS_ACCOUNT_ID="123456789012"
export AWS_ROLE_NAME="demo-wif-iam-role"
# If you are running this on an EC2 instance or Lambda with a role attached, the ARN is just the role ARN
export AWS_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${AWS_ROLE_NAME}"
# If you are assuming a role via some other means, use this ARN format instead
# export AWS_ROLE_ARN="arn:aws:sts::${AWS_ACCOUNT_ID}:assumed-role/${AWS_ROLE_NAME}"
```

Note that the `AWS_ROLE_NAME` can be the name of an existing role (for example, attached to an EC2 instance or Lambda) or you can create a new one.  It needs no specific policies attached on the AWS side, but you can if that role needs to use AWS services as well.

Here's an example role that can be attached to EC2 or Lambda with no AWS related policies attached:

```bash
aws iam get-role --role-name demo-wif-iam-role
{
    "Role": {
        "Path": "/",
        "RoleName": "demo-wif-iam-role",
        "RoleId": "AROA3K4K4NKZMWMTAAMLD",
        "Arn": "arn:aws:iam::123456789012:role/demo-wif-iam-role",
        "CreateDate": "2022-07-08T15:38:50+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": [
                            "ec2.amazonaws.com",
                            "lambda.amazonaws.com"
                        ]
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "Description": "Allows EC2 instances to call AWS services on your behalf.",
        "MaxSessionDuration": 3600,
        "Tags": [
            {
                "Key": "env",
                "Value": "dev"
            }
        ],
        "RoleLastUsed": {
            "LastUsedDate": "2022-07-29T14:40:18+00:00",
            "Region": "us-east-1"
        }
    }
}
```

### GCP Setup

Set some shell variables for GCP related items:

```bash
export GCP_PROJECT_ID="my-project-id"
export GCP_WORKLOAD_POOL_ID="aws-to-gcp-pool"
export GCP_WORKLOAD_PROVIDER_ID="aws-to-gcp-provider"
export GCP_SA_NAME="my-wif-sa"
```

Authenticate with `gcloud` as an `roles/owner` on the target GCP project, and set the current project:

```bash
gcloud config set project "${GCP_PROJECT_ID}"
```

Obtain the GCP Project Number:

```bash
export GCP_PROJECT_NUMBER="$(gcloud projects describe ${GCP_PROJECT_ID} --format='value(projectNumber)')"
```

Enable the necessary services in the project:

```bash
gcloud services enable sts.googleapis.com iamcredentials.googleapis.com
```

Create the Workload Identity Pool:

```bash
gcloud iam workload-identity-pools create "${GCP_WORKLOAD_POOL_ID}" \
  --location="global" \
  --display-name="${GCP_WORKLOAD_POOL_ID}" \
  --description="${GCP_WORKLOAD_POOL_ID}"
```

Create an `aws` Provider in the Workload Identity Pool:

```bash
gcloud iam workload-identity-pools providers create-aws "${GCP_WORKLOAD_PROVIDER_ID}" \
  --account-id="${AWS_ACCOUNT_ID}" \
  --location="global" \
  --workload-identity-pool="${GCP_WORKLOAD_POOL_ID}"
```

Create a dedicated GCP service account that the AWS IAM Role will be connected to:

```bash
export GCP_SA_EMAIL="${GCP_SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
gcloud iam service-accounts create "${GCP_SA_NAME}" \
  --display-name="${GCP_SA_NAME}" \
  --description="WIF from AWS to ${GCP_SA_NAME}"
```

Or reference an existing GCP service account:

```bash
export GCP_SA_EMAIL="my-existing-sa@my-project-id.iam.gserviceaccount.com"
```

Grant permissions directly on the service account so the AWS Role ARN can exchange STS for its GCP token(s):

```bash
gcloud iam service-accounts add-iam-policy-binding "${GCP_SA_EMAIL}" \
  --member "principalSet://iam.googleapis.com/projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${GCP_WORKLOAD_POOL_ID}/attribute.aws_role/${AWS_ROLE_ARN}" \
  --role roles/iam.workloadIdentityUser
```

Grant permissions as usual for the GCP service account to access services in GCP.  Next, list the workload identity pools/providers to get the full `gcp_workload_provider_path` to use in the module:

```bash
for pool in "$(gcloud iam workload-identity-pools list --location global --format='value(name)')"; do
  gcloud iam workload-identity-pools providers list --location global --workload-identity-pool="${pool}" --format='value(name)';
done

projects/4556456456456/locations/global/workloadIdentityPools/aws-to-gcp-pool/providers/aws-to-gcp-provider
```

## Usage

```python
#!/usr/bin/env python3

from gs_aws_to_gcp_workload_identity.main import AwsToGcpTokenService

aws_to_gcp_token_service = AwsToGcpTokenService(
    gcp_workload_provider_path="<insert full workload identity path>",
    gcp_service_account_email="<insert GCP service account email>",
    aws_assume_role_arn=None # Insert a role ARN to explicitly assume first if needed
)

# Most GCP services take the OAuth2 access token as the Bearer Token
access_token, expiry_utc_epoch = aws_to_gcp_token_service.get_oauth_token()

# Certain services like GCP Functions require Identity Tokens for Authenticated
# invocations and need the function URL in the token's `audience` field
function_url="https://us-central1-my-project-id.cloudfunctions.net/hello_world"
id_token, expiry_utc_epoch = aws_to_gcp_token_service.get_identity_token(audience=function_url)

# Call GCP services here
```

## Samples

See [SAMPLES.md](./SAMPLES.md) for working examples.

## FAQ

- **What about performance and rate limits?** - Performing this token exchange requires several calls to AWS' STS APIs and GCP's STS/IAM APIs, so this module caches the credentials after the first exchange and refreshes them only if they are expired or under 300s from expiring.  This should help reduce the API quote/rate limit usage.  Running hundreds of Lambdas at once is likely to hit some of these, for example.


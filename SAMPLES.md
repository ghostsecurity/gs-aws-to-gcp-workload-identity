# Samples

Assuming this is running on an EC2 instance with a role named `arn:aws:iam::123456789012:role/demo-wif-iam-role` attached in the instance profile:

## Listing GCS bucket objects

```python
#!/usr/bin/env python3

import json
import requests

from gs_aws_to_gcp_workload_identity.main import AwsToGcpTokenService

aws_to_gcp_token_service = AwsToGcpTokenService(
    gcp_workload_provider_path="projects/4556456456456/locations/global/workloadIdentityPools/aws-to-gcp-pool/providers/aws-to-gcp-provider",
    gcp_service_account_email="demo-wif-role@my-project-id.iam.gserviceaccount.com",
)

try:

    oauth_token, expiry_utc_epoch = aws_to_gcp_token_service.get_oauth_token()

    bucket = "my-test-wif-bucket"
    url = f'https://storage.googleapis.com/storage/v1/b/{bucket}/o/?fields=items/name'
    objects = requests.get(
        url,
        params={'access_token': oauth_token}
    )

    print(json.dumps(objects.json()['items'], indent=2))

except Exception as error:
    print(error)
    raise
```

Running this prints: 

```json
[
  {
    "name": "my-file1.txt"
  },
  {
    "name": "my-file2.txt"
  },
  {
    "name": "my-file3.txt"
  }
]
```

## Invoking an authenticated GCP Function

```python
#!/usr/bin/env python3

import json
import requests

from gs_aws_to_gcp_workload_identity.main import AwsToGcpTokenService

aws_to_gcp_token_service = AwsToGcpTokenService(
    gcp_workload_provider_path="projects/4556456456456/locations/global/workloadIdentityPools/aws-to-gcp-pool/providers/aws-to-gcp-provider",
    gcp_service_account_email="demo-wif-role@my-project-id.iam.gserviceaccount.com",
)

try:

    function_url = "https://us-central1-my-project-id.cloudfunctions.net/hello_world"
    id_token, expiry_utc_epoch = aws_to_gcp_token_service.get_identity_token(audience=function_url)

    payload = {
        "name": "there"
    }

    message_data = json.loads(json.dumps(payload).encode('UTF-8'))

    headers = {
        "Accept": "application/json",
        "Content-type": "application/json",
        "Authorization": f"Bearer {id_token}",
    }

    res = requests.post(
        function_url,
        json=message_data,
        headers=headers)
    res.raise_for_status()

    print(json.loads(json.dumps(res.json()).encode('UTF-8')))

except Exception as error:
    print(error)
    raise
```

Running this returns:

```json
{
  "message": "Hello, there!"
}
```

# SPDX-License-Identifier: AGPL-v3
import boto3
import json
import cf
import os
import copy


def assert_env(secret_type):
    """Asserts that the appropriate environment variables are set for the secret type of the managed secret"""

    if secret_type == "apiToken":
        if not (
            len(os.environ.get("CF_API_KEY", "")) > 0
            and len(os.environ.get("CF_API_EMAIL", "")) > 0
        ):
            # for api tokens we only need a api token that can create other tokens
            assert len(os.environ.get("CF_API_TOKEN", "")) > 0
            # the python library combines api token and key, ugh, which is so confusing
            # so we munge it here
            api_token = os.environ["CF_API_TOKEN"]
            os.environ["CF_API_KEY"] = api_token
    elif secret_type == "tunnelServiceKey":
        # for tunnel service keys we need full email and api key
        assert len(os.environ.get("CF_API_KEY", "")) > 0
        assert len(os.environ.get("CF_API_EMAIL", "")) > 0
    elif secret_type == "argoTunnelToken":
        # for argo tunnel tokens we need the origin ca key
        assert len(os.environ.get("CF_API_CERTKEY", "")) > 0
    else:
        raise ValueError(f"Invalid secret token type {secret_type}")


def lambda_handler(event, context):
    """Secrets Manager Rotation for Cloudflare

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information


    The Secret SecretString is expected to be a JSON object with the following keys:

            - Type: The type of cloudflare secret stored (one of apiToken, tunnelServiceKey, argoTunnelToken)
            - Attributes: A JSON object containing the token attributes, which depend on the type of cloudflare secret, see below

        apiToken Attribute keys:
            - TokenId: the cloudflare token id
            - TokenValue: the secret token value
            - Name: the name of this api token
            - Policies: the policies associated with this api token
            - ValidDays: the number of days the token should be valid

            Rotating api tokens uses the model suggested by AWS by switching between two "users" (tokens in our case).
            Two tokens are created and swapped between every rotation. The tokens are recreated if deleted.
            https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-two-users.html

        tunnelServiceKey Attribute keys:
            - KeyValue: the secret tunnel service key value

            There is no way to revoke, delete tunnel service keys. It is also not possible to test that a service key works.

        argoTunnelToken keys:
            - Hostname: a string for the hostname to be included in the tunnel (e.g., "foo.example.com")
            - ValidityDays: integer. The number of days the tunnel token will be valid.
            - ZoneId: the id of the the tunnel exists in
            - TunnelServiceKeyArn: the arn of the aws secrets manager secret that contains the tunnel service key
            - TokenValue: string. the argo tunnel token

            Unfortunately it is not possible to test of an argo tunnel token works, as that would require doing a capnproto rpc connection
            to cloudflare mimicking the cloudflared client.


    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys

        CloudFlare.exceptions.CloudFlareAPIError: On cloudflare API errrors

    """
    print(json.dumps(event))
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    # Setup the client
    service_client = boto3.client("secretsmanager")

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    print("Metadata", metadata)
    if not metadata["RotationEnabled"]:
        print("Secret %s is not enabled for rotation." % arn)
        raise ValueError("Secret %s is not enabled for rotation." % arn)
    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        print(
            "Secret version %s has no stage for rotation of secret %s." % (token, arn)
        )
        raise ValueError(
            "Secret version %s has no stage for rotation of secret %s." % (token, arn)
        )
    if "AWSCURRENT" in versions[token]:
        print(
            "Secret version %s already set as AWSCURRENT for secret %s." % (token, arn)
        )
        return
    elif "AWSPENDING" not in versions[token]:
        print(
            "Secret version %s not set as AWSPENDING for rotation of secret %s."
            % (token, arn)
        )
        raise ValueError(
            "Secret version %s not set as AWSPENDING for rotation of secret %s."
            % (token, arn)
        )

    print("Executing step", step)
    if step == "createSecret":
        create_secret(service_client, arn, token, context)

    elif step == "setSecret":
        set_secret(service_client, arn, token, context)

    elif step == "testSecret":
        test_secret(service_client, arn, token, context)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token, context)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(service_client, arn, token, context):
    """Create the secret

    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version (this is the AWS token, not the CF token)
    """

    try:
        print("Retrieving current version")
        current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    except service_client.exceptions.ResourceNotFoundException:
        # AWSCURRENT doesn't exist, which means the secret hasn't been initialized yet
        # fetch our custom CFINIT staging label to initialize the secert
        try:
            current_dict = get_secret_dict(service_client, arn, "CFINIT")
        except service_client.exceptions.ResourceNotFoundException as e:
            print(
                "createSecret: CFINIT does not exist. the secret has not been initialized."
            )
            raise e
    try:
        service_client.get_secret_value(
            SecretId=arn, VersionId=token, VersionStage="AWSPENDING"
        )
        print("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        secret_type = current_dict["Type"]

        assert_env(secret_type)

        print("createSecret: creating secret of type %s for %s" % (secret_type, arn))

        if secret_type == "apiToken":
            payload = json.dumps(rotate_or_create_api_token(current_dict))

        elif secret_type == "tunnelServiceKey":
            # no initialization necessary, just create a new service key
            current_dict["Attributes"][
                "KeyValue"
            ] = cf.create_origintunnel_service_key()
            payload = json.dumps(current_dict)
            print("createSecret(tunnelServiceKey): created tunnel service key")

        elif secret_type == "argoTunnelToken":
            hostname = current_dict["Attributes"]["Hostname"]
            valid_days = current_dict["Attributes"]["ValidityDays"]
            zone_id = current_dict["Attributes"]["ZoneId"]
            # we fetch the service key from another AWS Secrets Manager Secret
            if "TunnelServiceKeyArn" in current_dict["Attributes"]:
                tunnel_service_key_arn = current_dict["Attributes"][
                    "TunnelServiceKeyArn"
                ]
                tunnel_service_key = get_secret_dict(
                    service_client, tunnel_service_key_arn, "AWSCURRENT"
                )["Attributes"]["KeyValue"]
            else:
                tunnel_service_key = os.environ["CF_TUNNEL_SERVICE_KEY"]

            current_dict["TokenValue"] = cf.create_argo_tunnel_token(
                zone_id, tunnel_service_key, hostname, valid_days
            )
            payload = json.dumps(current_dict)
            print("createSecret(argoTunnelToken): created tunnel token")
        else:
            raise ValueError("Invalid secret Type parameter")

        service_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=payload,
            VersionStages=["AWSPENDING"],
        )

        print(
            "createSecret: Successfully put secret type %s for ARN %s and version %s."
            % (secret_type, arn, token)
        )


def set_secret(service_client, arn, token, context):
    """Set the secret

    This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
    credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    pass


def test_secret(service_client, arn, token, context):
    """Test the secret

    This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
    is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
    all of the expected permissions against the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING")
    secret_type = pending_dict["Type"]

    assert_env(secret_type)

    print("testSecret: testing secret of type %s for %s" % (secret_type, arn))
    if secret_type == "apiToken":
        if not cf.is_token_valid(pending_dict["Attributes"]["TokenValue"]):
            token_id = pending_dict["Attributes"]["TokenId"]
            raise ValueError(f"testSecret: Testing api token {token_id} failed")

    elif secret_type == "tunnelServiceKey":
        # no way to test these yet
        pass
    elif secret_type == "argoTunnelToken":
        # no way to test these yet
        pass
    else:
        raise ValueError("Invalid secret Type parameter")
    print("testSecret: tested secret of type %s for %s" % (secret_type, arn))


def finish_secret(service_client, arn, token, context):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist

    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)

    new_version = token
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                print(
                    "finishSecret: Version %s already marked as AWSCURRENT for %s"
                    % (version, arn)
                )
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=new_version,
        RemoveFromVersionId=current_version,
    )
    print(
        "finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s."
        % (new_version, arn)
    )


def get_secret_dict(service_client, arn, stage, token=None):
    """Gets the secret dictionary corresponding for the secret arn, stage, and token

    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired

        stage (string): The stage identifying the secret version

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON

        KeyError: If the secret json does not contain the expected keys

    """

    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = service_client.get_secret_value(
            SecretId=arn, VersionId=token, VersionStage=stage
        )
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret["SecretString"]
    secret_dict = json.loads(plaintext)

    # Parse and return the secret JSON string
    return secret_dict


def create_api_token(secret_value):
    new_value = copy.deepcopy(secret_value)
    name = secret_value["Attributes"]["Name"]
    policies = secret_value["Attributes"]["Policies"]
    valid_days = secret_value["Attributes"]["ValidDays"]

    new_token = cf.create_api_token(name, policies, valid_days)

    new_value["Attributes"]["TokenValue"] = new_token["value"]
    new_value["Attributes"]["TokenId"] = new_token["id"]

    return new_value


def rotate_between_api_tokens(secret_value):
    cf_token_id = secret_value["Attributes"]["TokenId"]

    # assumption, cf_token_id exists

    new_value = copy.deepcopy(secret_value)
    if "OtherTokenId" in secret_value["Attributes"] and cf.token_exists(
        secret_value["Attributes"]["OtherTokenId"]
    ):
        cf_other_token_id = secret_value["Attributes"]["OtherTokenId"]
        # make other token active again
        value = cf.renew_api_token(cf_other_token_id)
        new_value["Attributes"]["OtherTokenId"] = cf_token_id
        new_value["Attributes"]["TokenValue"] = value
        new_value["Attributes"]["TokenId"] = cf_other_token_id
        print(
            "createSecret(apiToken): rotate between %s -> %s"
            % (cf_token_id, cf_other_token_id)
        )
    else:
        new_token = cf.clone_api_token(cf_token_id)
        new_value["Attributes"]["OtherTokenId"] = cf_token_id
        new_value["Attributes"]["TokenValue"] = new_token["value"]
        new_value["Attributes"]["TokenId"] = new_token["id"]
        print(
            "createSecret(apiToken): rotate between %s -> %s (new!)"
            % (cf_token_id, new_token["id"])
        )
    return new_value


def rotate_or_create_api_token(current_dict):
    new_dict = copy.deepcopy(current_dict)
    if "TokenId" not in new_dict["Attributes"]:
        # token hasn't been created yet
        r = create_api_token(new_dict)
        print(
            "createSecret(apiToken): created apiToken %s" % r["Attributes"]["TokenId"]
        )
        return r
    else:
        # token exists, check that it is valid
        cf_token_id = new_dict["Attributes"]["TokenId"]
        if not cf.token_exists(cf_token_id):
            # token was deleted, create it new
            r = create_api_token(new_dict)
            print(
                "createSecret(apiToken): token not found. created again (old id %s, new id %s)"
                % (cf_token_id, r["Attributes"]["TokenId"])
            )
            return r
        else:
            return rotate_between_api_tokens(new_dict)

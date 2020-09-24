import os
import base64
import textwrap
import requests
from datetime import datetime, timedelta

import CloudFlare
from dateutil.parser import isoparse
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# setup hidden non-public api endpoints
os.environ[
    "CF_API_EXTRAS"
] = "/client/v4/user/service_keys /client/v4/user/service_keys/origintunnel"


def date_fmt(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def roll_api_token(token_id):
    """
     Args:
         - token_id: the id of the api token to rotate
     Returns:
         - a string containing the new token value
     """
    cf = CloudFlare.CloudFlare()
    return cf.user.tokens.value.put(token_id)


def get_api_token(token_id):
    """
     Args:
         - token_id: the id of the api token to retrieve
     Returns:
         - a dict containing the new token's data
     """
    cf = CloudFlare.CloudFlare()
    return cf.user.tokens.get(token_id)


def create_api_token(name, policies, valid_days):
    """
    Creates a new token

     Args:
         - name: the name of the token
         - policies: the policies dict, see CF docs
         - valid_days: the number of days the policy should be valid
     Returns:
         - a dict containing the new token's data, the secret token is in the 'value' key
     """
    cf = CloudFlare.CloudFlare()
    now = datetime.utcnow()
    new_token = {"name": name, "not_before": date_fmt(now), "policies": policies}

    for policy in new_token["policies"]:
        if "id" in policy:
            del policy["id"]

    if valid_days > 0:
        new_token["expires_on"] = date_fmt(now + timedelta(days=valid_days))

    return cf.user.tokens.post(data=new_token)


def clone_api_token(token_id):
    """
    Clones an existing token, creating a new token with the same policies.

     Args:
         - token_id: the id of the api token to retrieve
     Returns:
         - a dict containing the new token's data, the secret token is in the 'value' key
     """
    cf = CloudFlare.CloudFlare()
    existing_token = cf.user.tokens.get(token_id)
    now = datetime.utcnow()
    new_token = {
        "name": existing_token["name"],
        "not_before": date_fmt(now),
        "policies": existing_token["policies"],
        "condition": existing_token.get("condition", {}),
    }

    for policy in new_token["policies"]:
        del policy["id"]

    if "expires_on" in existing_token:
        issued_date = isoparse(existing_token["issued_on"])
        expires_date = isoparse(existing_token["expires_on"])

    new_token["expires_on"] = date_fmt(now + (expires_date - issued_date))
    return cf.user.tokens.post(data=new_token)


def renew_api_token(token_id):
    """Renews an existing token. Rolls the secret value, resets validity period to now + expiry days and marks as active

     Args:
         - token_id: the id of the api token to retrieve
     Returns:
         - the new secret value
     """
    cf = CloudFlare.CloudFlare()
    now = datetime.utcnow()
    existing_token = cf.user.tokens.get(token_id)
    existing_token["not_before"] = date_fmt(now)
    existing_token["status"] = "active"

    if "expires_on" in existing_token:
        issued_date = isoparse(existing_token["issued_on"])
        expires_date = isoparse(existing_token["expires_on"])

    existing_token["expires_on"] = date_fmt(now + (expires_date - issued_date))
    cf.user.tokens.put(token_id, data=existing_token)
    return roll_api_token(token_id)


def get_token(token_id):
    """Fetch a token's  details
     Args:
         - token_id: the id of the api token to retrieve
     Returns:
         - the token's details
    """
    cf = CloudFlare.CloudFlare()
    return cf.user.tokens.get(token_id)


def token_exists(token_id):
    """Check if a token exists
     Args:
         - token_id: the id of the api token to check
     Returns:
         - True / False
    """
    cf = CloudFlare.CloudFlare()
    try:
        cf.user.tokens.get(token_id)
        return True
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        if int(e) == 1003:
            return False
        else:
            raise e


def is_token_valid(token_value):
    """Check if a token value works and is active
     Args:
         - token_value: the secret token value to test
     Returns:
         - True / False
    """
    url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
    response = requests.get(
        url, headers={"Authorization": f"Bearer {token_value}"}
    ).json()
    return response["success"] and response["result"]["status"] == "active"


def list_api_tokens():
    """
     Returns:
         - a list of token details
     """
    cf = CloudFlare.CloudFlare()
    return cf.user.tokens.get()


def create_origintunnel_service_key():
    """
     Returns:
         - a fresh origin tunnel service key
     """
    cf = CloudFlare.CloudFlare()
    return cf.user.service_keys.origintunnel.get()["service_key"]


def create_private_key():
    """Generates a p256R1 ECC private key
     Returns:
         - tuple of private_key (object) and private key pem encoded
     """
    private_key = ec.generate_private_key(ec.SECP256R1(), crypto_default_backend())
    private_pem = (
        private_key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        )
        .decode("utf-8")
        .strip()
    )
    return private_key, private_pem


def create_origin_certificate(private_key, hostname, valid_days):
    """Creates a cloudflare origin certificate for the given hostname
     Args:
         - private_key: the private key object
         - hostname: the hostname to issue the cert for
         - valid_days: the number of days the cert is valid
     Returns:
         - the PEM encoded certificate
     """
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "Cloudflare"),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(crypto_serialization.Encoding.PEM).decode("utf-8")
    cf = CloudFlare.CloudFlare()

    data = {
        "hostnames": [hostname],
        "requested_validity": valid_days,
        "request_type": "origin-ecc",
        "csr": csr_pem,
    }
    resp = cf.certificates.post(data=data)
    cert_pem = resp["certificate"].strip()
    return cert_pem


def format_argo_tunnel_token(zone_id, tunnel_service_key, private_pem, cert_pem):
    """Formats inputs into Argo tunnel token
     Args:
         - zone_id: the zone the tunnel will be in
         - tunnel_service_key:
         - private_pem: pem encoded private key
         - cert_pem: pem encoded origin certficate
     Returns:
         - string containing formatted argo tunnel token ready to be consumed by cloudflared
     """
    argo_token_contents = f"{zone_id}\n{tunnel_service_key}"
    encoded_argo_token = "\n".join(
        textwrap.wrap(
            base64.b64encode(argo_token_contents.encode("utf-8")).decode("ascii"),
            width=64,
        )
    ).strip()

    argo_token = f"""{private_pem}
{cert_pem}
-----BEGIN ARGO TUNNEL TOKEN-----
{encoded_argo_token}
-----END ARGO TUNNEL TOKEN-----"""
    return argo_token


def create_argo_tunnel_token(zone_id, tunnel_service_key, hostname, valid_days=30):
    """Creates an argo tunnel token for use with cloudflared
     Args:
         - zone_id: the zone the tunnel will be in
         - tunnel_service_key:
         - hostname: the hostname to issue the cert for
         - valid_days: the number of days the token will be valid
     Returns:
         - string containing formatted argo tunnel token ready to be consumed by cloudflared
     """
    private_key, private_pem = create_private_key()
    cert_pem = create_origin_certificate(private_key, hostname, valid_days)
    return format_argo_tunnel_token(zone_id, tunnel_service_key, private_pem, cert_pem)

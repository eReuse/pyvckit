import json
import zlib
import base64
import requests
import nacl.encoding
import nacl.signing
import multicodec
import multiformats
from typing import Tuple

from datetime import datetime, timezone

from jsonschema import Draft202012Validator, RefResolver, ValidationError
from datetime import datetime
from nacl.signing import VerifyKey
from pyroaring import BitMap

from pyvckit.sign import to_jws_payload
from pyvckit.did import resolve_did, get_public_key_bytes


def get_signing_input(payload):
    header = b'{"alg":"EdDSA","crit":["b64"],"b64":false}'
    header_b64 = nacl.encoding.URLSafeBase64Encoder.encode(header)
    signing_input = header_b64 + b"." + payload
    return header_b64, signing_input


def get_message(vc, verify=True):
    document = vc.copy()
    proof = document.pop("proof", {})
    jws = proof.pop("jws", None)
    proof['@context'] = 'https://w3id.org/security/v2'
    if not jws:
        return None, False

    return jws+"==", to_jws_payload(document, proof, verify=verify)


def get_pubkey_bytes_from_diddocument(did, did_document=None, verify=True):
    if not did_document:
        did_document = resolve_did(did, verify=verify)

    if not did_document:
        return

    for x in did_document.get("verificationMethod", []):
        pub_key = x.get("publicKeyJwk", {})
        if pub_key.get('crv', '').lower() == "ed25519":
            return get_public_key_bytes(pub_key.get("x", ""))


def get_verify_key(vc, did_document=None, verify=True):
    did = vc["proof"]["verificationMethod"].split("#")[0]
    if did[:7] == "did:web":
        public_key_bytes = get_pubkey_bytes_from_diddocument(
            did,
            did_document=did_document,
            verify=verify
        )
        if not public_key_bytes:
            return False
    else:
        pub = did.split(":")[-1]
        mc = multiformats.multibase.decode(pub)
        public_key_bytes = multicodec.remove_prefix(mc)
    return VerifyKey(public_key_bytes)


def jws_split(jws):
    header, sig_b64 = jws.split("..")
    signature = nacl.encoding.URLSafeBase64Encoder.decode(sig_b64.encode())
    return header.encode(), signature


def is_revoked(vc, did_document):
    # TODO enable this function
    return False

    if "credentialStatus" in vc:
        # NOTE: THIS FIELD SHOULD BE SERIALIZED AS AN INTEGER,
        # BUT IOTA DOCUMENTAITON SERIALIZES IT AS A STRING.
        # DEFENSIVE CAST ADDED JUST IN CASE.
        revocation_index = int(vc["credentialStatus"]["revocationBitmapIndex"])

        if did_document:  # Only DID:WEB can revoke
            issuer_revocation_list = did_document["service"][0]
            assert issuer_revocation_list["type"] == "RevocationBitmap2022"
            revocation_bitmap = BitMap.deserialize(
                zlib.decompress(
                    base64.b64decode(
                        issuer_revocation_list["serviceEndpoint"].rsplit(",")[1].encode('utf-8')
                    )
                )
            )
            if revocation_index in revocation_bitmap:
                # Credential has been revoked by the issuer
                return False


def _load_credential(data):
    # Helper function to allow verification of dict json
    if isinstance(data, dict):
        return data, None
    try:
        return json.loads(data), None
    except (TypeError, json.JSONDecodeError):
        return None, "Invalid input: Argument must be a valid JSON string or a dictionary"

def is_expired(vc):
    valid_from = vc.get("validFrom")
    valid_until = vc.get("validUntil")
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"

    if valid_from:
        dt_from = datetime.strptime(valid_from, fmt).replace(tzinfo=timezone.utc)
        if dt_from > now:
            return True

    if valid_until:
        dt_until = datetime.strptime(valid_until, fmt).replace(tzinfo=timezone.utc)
        if dt_until < now:
            return True

    return False


def verify_signature(credential, verify=True) -> Tuple[bool, str]:
    vc, error = _load_credential(credential)
    if error:
        return False, error

    header = {"alg": "EdDSA", "crit": ["b64"], "b64": False}
    jws, message = get_message(vc, verify=verify)

    if not message:
        return False, "Could not extract JWS or message from proof"

    did_issuer = vc.get("issuer", {}) or vc.get("holder", {})
    if isinstance(did_issuer, dict):
        did_issuer = did_issuer.get("id")

    try:
        did_issuer_method = vc["proof"]["verificationMethod"].split("#")[0]
    except (KeyError, IndexError, TypeError):
        return False, "Missing or malformed verificationMethod in proof"

    if did_issuer != did_issuer_method:
        return False, f"Issuer DID ({did_issuer}) does not match verification method controller ({did_issuer_method})"

    header_b64, signature = get_signing_input(message)
    header_jws, signature_jws = jws_split(jws)

    if header_jws != header_b64:
        return False, "JWS header does not match signed header input"

    try:
        header_jws_json = json.loads(
            nacl.encoding.URLSafeBase64Encoder.decode(header_jws)
        )
    except Exception:
         return False, "Could not decode JWS header"

    for k, v in header.items():
        if header_jws_json.get(k) != v:
            return False, f"Invalid JWS header parameter: {k}"

    did_document = {}
    if did_issuer[:7] == "did:web":
        did_document = resolve_did(did_issuer, verify=verify)

    verify_key = get_verify_key(vc, did_document=did_document, verify=verify)

    try:
        data_verified = verify_key.verify(signature_jws+signature)
    except nacl.exceptions.BadSignatureError:
        return False, "Cryptographic signature verification failed (Bad Signature)"

    if data_verified != signature:
        return False, "This credential is not cryptographically vallid"
    if is_revoked(vc, did_document):
        return False, "This credential is revoked"
    if is_expired(vc):
        return False, "This credential is expired"

    return True, "Success"

def verify_schema(credential, verify=True):
    vc, error = _load_credential(credential)
    if error:
        return False, error

    schema_url = vc.get('credentialSchema', {}).get('id')
    if not schema_url:
        return False, "Credential is missing 'credentialSchema' ID"

    try:
        schema_response = requests.get(schema_url, verify=verify)
        schema_response.raise_for_status()
        schema_doc = schema_response.json()
    except requests.exceptions.RequestException as e:
        return False, f"Failed to fetch schema from {schema_url}: {str(e)}"
    except json.JSONDecodeError:
        return False, "Fetched schema is not valid JSON"

    resolver = RefResolver(base_uri=schema_url, referrer=schema_doc)
    validator = Draft202012Validator(schema_doc, resolver=resolver)

    try:
        validator.validate(vc)
    except ValidationError as e:
        return False, f"Schema validation failed: {e.message} at path '{'/'.join(map(str, e.path))}'"
    except Exception as e:
        return False, f"Internal error during schema validation: {str(e)}"

    return True, "Schema is valid"


def verify_vp_signature(presentation) -> Tuple[bool, str]:
    vp = json.loads(presentation)

    is_vp_valid, vp_error = verify_signature(presentation)
    if not is_vp_valid:
        return False, f"Presentation Signature Invalid: {vp_error}"

    if 'verifiableCredential' in vp:
        for index, vc in enumerate(vp['verifiableCredential']):
            vc_str = json.dumps(vc)

            is_vc_valid, vc_error = verify_signature(vc_str)
            if not is_vc_valid:
                return False, f"Credential #{index} Invalid: {vc_error}"

    return True, "Presentation and all included Credentials are valid"

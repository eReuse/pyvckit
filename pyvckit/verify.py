import json
import nacl.encoding
import nacl.signing
import multicodec
import multiformats

from nacl.signing import VerifyKey

from pyvckit.sign import to_jws_payload


def get_signing_input(payload):
    header = b'{"alg":"EdDSA","crit":["b64"],"b64":false}'
    header_b64 = nacl.encoding.URLSafeBase64Encoder.encode(header)
    signing_input = header_b64 + b"." + payload
    return header_b64, signing_input


def get_message(vc):
    document = vc.copy()
    proof = document.pop("proof", {})
    jws = proof.pop("jws", None)
    proof['@context'] = 'https://w3id.org/security/v2'
    if not jws:
        return None, False

    return jws+"==", to_jws_payload(document, proof)


def get_verify_key(vc):
    did = vc["proof"]["verificationMethod"].split("#")[0]
    pub = did.split(":")[-1]
    mc = multiformats.multibase.decode(pub)
    public_key_bytes = multicodec.remove_prefix(mc)
    return VerifyKey(public_key_bytes)


def jws_split(jws):
    header, sig_b64 = jws.split("..")
    signature = nacl.encoding.URLSafeBase64Encoder.decode(sig_b64.encode())
    return header.encode(), signature

    
def verify_vc(credential):
    vc = json.loads(credential)
    header = {"alg": "EdDSA", "crit": ["b64"], "b64": False}
    jws, message = get_message(vc)
    if not message:
        return False

    header_b64, signature = get_signing_input(message)
    header_jws, signature_jws = jws_split(jws)
    
    if header_jws != header_b64:
        return False

    header_jws_json = json.loads(
        nacl.encoding.URLSafeBase64Encoder.decode(header_jws)
    )
    for k, v in header.items():
        if header_jws_json.get(k) != v:
            return False

    verify_key = get_verify_key(vc)
    try:
        data_verified = verify_key.verify(signature_jws+signature)
    except nacl.exceptions.BadSignatureError:
        return False
    return data_verified == signature


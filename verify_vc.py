import sys
import json
import hashlib
import multicodec
import multiformats
import nacl.signing
import nacl.encoding

from pyld import jsonld
from jwcrypto import jwk
from nacl.signing import SigningKey, VerifyKey
from collections import OrderedDict
from nacl.encoding import RawEncoder
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey



def key_to_did(public_key_bytes):
   """did-key-format := 
       did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))"""
   
   mc = multicodec.add_prefix('ed25519-pub', public_key_bytes)

   # Multibase encode the hashed bytes
   did = multiformats.multibase.encode(mc, 'base58btc')

   return f"did:key:{did}"


def get_signing_input(payload):
    header = b'{"alg":"EdDSA","crit":["b64"],"b64":false}'
    header_b64 = nacl.encoding.URLSafeBase64Encoder.encode(header)
    signing_input = header_b64 + b"." + payload
    return header_b64, signing_input


def urdna2015_normalize(document, proof):
    doc_dataset = jsonld.compact(document, "https://www.w3.org/2018/credentials/v1")
    sigopts_dataset = jsonld.compact(proof, "https://w3id.org/security/v2")
    doc_normalized = jsonld.normalize(
        doc_dataset,
        {'algorithm': 'URDNA2015', 'format': 'application/n-quads'}
    )
    sigopts_normalized = jsonld.normalize(
        sigopts_dataset,
        {'algorithm': 'URDNA2015', 'format': 'application/n-quads'}
    )
    return doc_normalized, sigopts_normalized


def sha256_normalized(doc_normalized, sigopts_normalized):
    doc_digest = hashlib.sha256(doc_normalized.encode('utf-8')).digest()
    sigopts_digest = hashlib.sha256(sigopts_normalized.encode('utf-8')).digest()
    message = sigopts_digest + doc_digest
    return message


def to_jws_payload(document, proof):
    doc_normalized, sigopts_normalized = urdna2015_normalize(document, proof)
    return sha256_normalized(doc_normalized, sigopts_normalized)


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

    
def verify_vc(vc):
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
    data_verified = verify_key.verify(signature_jws+signature)
    return data_verified == signature


def get_credential(path_credential):
    with open(path_credential, "r") as f:
        vc = f.read()
    return json.loads(vc)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        path_credential = sys.argv[1]
        credential = get_credential(path_credential)
        print(verify_vc(credential))
    else:
        print("You need pass a credential.")

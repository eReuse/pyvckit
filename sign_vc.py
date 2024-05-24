import json
import hashlib
import multicodec
import multiformats
import nacl.signing
import nacl.encoding

from pyld import jsonld
from jwcrypto import jwk
from nacl.public import PublicKey
from nacl.signing import SigningKey
from collections import OrderedDict
from nacl.encoding import RawEncoder
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# For signature
from pyld.jsonld import JsonLdProcessor


_debug = False


def now():
    timestamp = datetime.now(timezone.utc).replace(microsecond=0)
    formatted_timestamp = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    return formatted_timestamp


def key_to_did(public_key_bytes):
    """did-key-format := 
       did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))"""

    #public_key_bytes = public_key.encode()
    mc = multicodec.add_prefix('ed25519-pub', public_key_bytes)

    # Multibase encode the hashed bytes
    did = multiformats.multibase.encode(mc, 'base58btc')

    return f"did:key:{did}"


def key_save(key):
    # Save the private JWK to a file
    private_jwk = key.export()
    with open('keypairs.jwk', 'w') as f:
        f.write(private_jwk)


def key_read():
    # Save the private JWK to a file
    with open('keypairs.jwk', 'r') as f:
        private_jwk = f.read()

    return jwk.JWK.from_json(private_jwk)


# https://github.com/spruceid/ssi/blob/main/ssi-jws/src/lib.rs#L75
def sign_bytes(data, secret):
    # https://github.com/spruceid/ssi/blob/main/ssi-jws/src/lib.rs#L125
    return secret.sign(data)[:-len(data)]


# https://github.com/spruceid/ssi/blob/main/ssi-jws/src/lib.rs#L248
def sign_bytes_b64(data, key):
    signature = sign_bytes(data, key)
    sig_b64 = nacl.encoding.URLSafeBase64Encoder.encode(signature)
    return sig_b64


 # https://github.com/spruceid/ssi/blob/main/ssi-jws/src/lib.rs#L581
def detached_sign_unencoded_payload(payload, key):
    header = b'{"alg":"EdDSA","crit":["b64"],"b64":false}'
    header_b64 = nacl.encoding.URLSafeBase64Encoder.encode(header)
    signing_input = header_b64 + b"." + payload
    sig_b64 = sign_bytes_b64(signing_input, key)
    jws = header_b64 + b".." + sig_b64
    return jws


# https://github.com/spruceid/ssi/blob/main/ssi-ldp/src/lib.rs#L423
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


# https://github.com/spruceid/ssi/blob/main/ssi-ldp/src/lib.rs#L456
def sha256_normalized(doc_normalized, sigopts_normalized):
    doc_digest = hashlib.sha256(doc_normalized.encode('utf-8')).digest()
    sigopts_digest = hashlib.sha256(sigopts_normalized.encode('utf-8')).digest()
    message = sigopts_digest + doc_digest
    return message


# https://github.com/spruceid/ssi/blob/main/ssi-ldp/src/lib.rs#L413
def to_jws_payload(document, proof):
    doc_normalized, sigopts_normalized = urdna2015_normalize(document, proof)
    return sha256_normalized(doc_normalized, sigopts_normalized)


# https://github.com/spruceid/ssi/blob/main/ssi-ldp/src/lib.rs#L498
def sign_proof(document, proof, key):
    message = to_jws_payload(document, proof)
    jws = detached_sign_unencoded_payload(message, key)
    proof["jws"] = jws.decode('utf-8')[:-2]
    return proof

# source: https://github.com/mmlab-aueb/PyEd25519Signature2018/blob/master/signer.py

def sign(document, key, issuer_did):
    _did = issuer_did + "#" + issuer_did.split("did:key:")[1]
    proof = {
        '@context':'https://w3id.org/security/v2',
        'type': 'Ed25519Signature2018',
        'proofPurpose': 'assertionMethod',
        'verificationMethod': _did,
        'created': now()
    }
    sign_proof(document, proof, key)
    del proof['@context']
    document['proof'] = proof
    return document


if __name__ == "__main__":
    # Generate an Ed25519 key pair
    key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
    key['kid'] = 'Generated'
    # key = key_read()

    jwk_pr = key.export_private(True)
    private_key_material_str = jwk_pr['d']
    missing_padding = len(private_key_material_str) % 4
    if missing_padding:
      private_key_material_str += '=' * (4 - missing_padding)

    private_key_material = nacl.encoding.URLSafeBase64Encoder.decode(private_key_material_str)
    signing_key = SigningKey(private_key_material, encoder=RawEncoder)
    verify_key = signing_key.verify_key
    public_key_bytes = verify_key.encode()
    
    # Generate the DID
    did = key_to_did(public_key_bytes)
    # print(did)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": did,
        "issuanceDate": now()
    }

    # vc = generate_vc(credential, signing_key, did)
    vc = sign(credential, signing_key, did)

    print(json.dumps(vc, separators=(',', ':')))


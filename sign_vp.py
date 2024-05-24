import sys
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


def key_to_did(key):
    """did-key-format := 
       did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))"""

    verify_key = key.verify_key
    public_key_bytes = verify_key.encode()
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


def sign_bytes(data, secret):
    return secret.sign(data)[:-len(data)]


def sign_bytes_b64(data, key):
    signature = sign_bytes(data, key)
    sig_b64 = nacl.encoding.URLSafeBase64Encoder.encode(signature)
    return sig_b64


def detached_sign_unencoded_payload(payload, key):
    header = b'{"alg":"EdDSA","crit":["b64"],"b64":false}'
    header_b64 = nacl.encoding.URLSafeBase64Encoder.encode(header)
    signing_input = header_b64 + b"." + payload
    sig_b64 = sign_bytes_b64(signing_input, key)
    jws = header_b64 + b".." + sig_b64
    return jws


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


def sign_proof(document, proof, key):
    message = to_jws_payload(document, proof)
    jws = detached_sign_unencoded_payload(message, key)
    proof["jws"] = jws.decode('utf-8')[:-2]
    return proof


def get_presentation(vc):
    template = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "id": "http://example.org/presentations/3731",
      "type": ["VerifiablePresentation"],
      "holder": "",
      "verifiableCredential": []
      }

    template["verifiableCredential"].append(json.loads(vc))
    return template


def get_keys(path_file=None):
    if path_file:
        key = key_read(path_file)
    else:
        key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
        key['kid'] = 'Generated'

    jwk_pr = key.export_private(True)
    private_key_material_str = jwk_pr['d']
    missing_padding = len(private_key_material_str) % 4
    if missing_padding:
      private_key_material_str += '=' * (4 - missing_padding)

    private_key_material = nacl.encoding.URLSafeBase64Encoder.decode(private_key_material_str)
    signing_key = SigningKey(private_key_material, encoder=RawEncoder)
    return signing_key


def sign_vp(signing_key, holder_did, vc):
    presentation = get_presentation(vc)
    _did = holder_did + "#" + holder_did.split("did:key:")[1]
    presentation["holder"] = holder_did
    proof = {
        '@context':'https://w3id.org/security/v2',
        'type': 'Ed25519Signature2018',
        'proofPurpose': 'assertionMethod',
        'verificationMethod': _did,
        'created': now()
    }
    sign_proof(presentation, proof, signing_key)
    del proof['@context']
    presentation['proof'] = proof
    return presentation


def main():
    path_credential = None
    path_keys = None

    if len(sys.argv) > 1:
        path_credential = sys.argv[1]

    if not path_credential:
        print("You need pass a credential.")
        return

    if len(sys.argv) > 2:
        path_keys = sys.argv[2]

    with open(path_credential, "r") as f:
        vc = f.read()

    if not vc:
        print("You need pass a credential.")
        return

    signing_key = get_keys(path_keys)
    holder_did = key_to_did(signing_key)
    vp = sign_vp(signing_key, holder_did, vc)
    print(json.dumps(vp, separators=(',', ':')))


if __name__ == "__main__":
    main()

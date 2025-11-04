import json
import hashlib
import requests
import functools
import nacl.signing
import nacl.encoding
from pyld import jsonld
from pyvckit.utils import now
from pyvckit.did import get_signing_key
from pyvckit.templates import proof_tmpl
from pyvckit.document_loader import requests_document_loader


jsonld.set_document_loader(requests_document_loader())


def create_loader(url, options={}, verify=True):
    response = requests.get(
        url,
        headers={'Accept': 'application/ld+json, application/json'},
        verify=verify)

    response.raise_for_status()

    return {
        "contextUrl": None,
        "document": response.json(),
        "documentUrl": response.url
    }


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
def urdna2015_normalize(document, proof, verify=True):
    configured_loader = functools.partial(create_loader, verify=verify)
    options = {
    'documentLoader': configured_loader,
    }

    all_context = [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/ns/credentials/v2"
    ]

    context_url = all_context[0]
    for c in all_context:
        if c in document.get("@context", []):
            context_url = c
            break

    doc_dataset = jsonld.compact(
        document,
        context_url,
        options=options
    )
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
def to_jws_payload(document, proof, verify=True):
    doc_normalized, sigopts_normalized = urdna2015_normalize(document, proof, verify=verify)
    return sha256_normalized(doc_normalized, sigopts_normalized)


# https://github.com/spruceid/ssi/blob/main/ssi-ldp/src/lib.rs#L498
def sign_proof(document, proof, key, verify=True):
    message = to_jws_payload(document, proof, verify=verify)
    jws = detached_sign_unencoded_payload(message, key)
    proof["jws"] = jws.decode('utf-8')[:-2]
    return proof


def sign(credential, key, issuer_did, verify=True):
    signing_key = get_signing_key(key)
    document = json.loads(credential)
    _did = issuer_did + "#" + issuer_did.split(":")[-1]
    proof = json.loads(proof_tmpl)
    proof['verificationMethod'] = _did
    proof['created'] = now()

    sign_proof(document, proof, signing_key, verify=verify)
    del proof['@context']
    document['proof'] = proof
    return document

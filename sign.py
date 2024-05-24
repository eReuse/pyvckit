import hashlib
import nacl.signing
import nacl.encoding
from pyld import jsonld


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

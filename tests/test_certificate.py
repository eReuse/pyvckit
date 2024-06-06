import json
import multicodec
import multiformats
import nacl.encoding

from pyvckit.did import generate_keys, generate_did, gen_did_document
from pyvckit.sign import sign
from pyvckit.sign_vp import get_presentation
from pyvckit.verify import verify_vc
from pyvckit.verify import verify_vp
from pyvckit.utils import now


def test_generated_did_key():
    key = generate_keys()
    key_d = json.loads(key)
    did = generate_did(key)
    _did = did.split("#")[0]
    pub = _did.split(":")[-1]
    mc = multiformats.multibase.decode(pub)
    public_key_bytes = multicodec.remove_prefix(mc)
    x = nacl.encoding.URLSafeBase64Encoder.encode(public_key_bytes).decode('utf-8')
    k_x = key_d.get('x', '')
    missing_padding = len(k_x) % 4
    if missing_padding:
        k_x += '=' * (4 - missing_padding)

    assert key_d.get('kty') == 'OKP'
    assert key_d.get('crv') == 'Ed25519'
    assert key_d.get('kid') == 'Generated'
    assert k_x == x
    assert key_d.get('d') is not None
    assert did.split(":")[:-1] == ['did', 'key']

    
def test_generated_did_web():
    key = generate_keys()
    key_d = json.loads(key)
    url = "https://localhost/did-registry"
    did = generate_did(key, url)
    _did = did.split("#")[0]
    pub = _did.split(":")[-1]
    mc = multiformats.multibase.decode(pub)
    public_key_bytes = multicodec.remove_prefix(mc)
    x = nacl.encoding.URLSafeBase64Encoder.encode(public_key_bytes).decode('utf-8')
    k_x = key_d.get('x', '')
    missing_padding = len(k_x) % 4
    if missing_padding:
        k_x += '=' * (4 - missing_padding)

    assert key_d.get('kty') == 'OKP'
    assert key_d.get('crv') == 'Ed25519'
    assert key_d.get('kid') == 'Generated'
    assert k_x == x
    assert key_d.get('d') is not None
    assert did.split(":")[:-1] == ['did', 'web', 'localhost', 'did-registry']


def test_generated_did_document():
    key = generate_keys()
    key_d = json.loads(key)
    url = "https://localhost/did-registry"
    did = generate_did(key, url)
    definitive_url, document = gen_did_document(did, key_d)
    pubkey = did.split(":")[-1]
    doc_id = json.loads(document)["id"]
    assert doc_id == did
    assert definitive_url == f"{url}/{pubkey}/did.json"


def test_credential():
    key = generate_keys()
    did = generate_did(key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did,
            "name": ""
        },
        "issuanceDate": now()
    }

    cred = json.dumps(credential)

    vc = sign(cred, key, did)
    header = 'eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9'
    assert vc.get('proof', {}).get('jws') is not None
    assert header in vc.get('proof', {}).get('jws')
    assert did in vc.get('proof', {}).get('verificationMethod')


def test_presentation():
    key = generate_keys()
    did = generate_did(key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did,
            "name": ""
        },
        "issuanceDate": now()
    }

    cred = json.dumps(credential)

    vc = sign(cred, key, did)
    vc_json = json.dumps(vc)

    holder_key = generate_keys()
    holder_did = generate_did(holder_key)
    unsigned_vp = get_presentation(vc_json, holder_did)
    vp = sign(unsigned_vp, holder_key, holder_did)
    header = 'eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9'
    assert vp.get('proof', {}).get('jws') is not None
    assert header in vp.get('proof', {}).get('jws')
    assert holder_did in vp.get('proof', {}).get('verificationMethod')


def test_verifiable_credential():
    key = generate_keys()
    did = generate_did(key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did,
            "name": ""
        },
        "issuanceDate": now()
    }

    cred = json.dumps(credential)

    vc = sign(cred, key, did)
    verified = verify_vc(json.dumps(vc))
    assert verified


def test_verifiable_presentation():
    key = generate_keys()
    did = generate_did(key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3732",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did,
            "name": ""
        },
        "issuanceDate": now()
    }

    cred = json.dumps(credential)

    vc = sign(cred, key, did)
    vc_json = json.dumps(vc)
    assert verify_vc(json.dumps(vc))

    holder_key = generate_keys()
    holder_did = generate_did(holder_key)
    unsigned_vp = get_presentation(vc_json, holder_did)
    vp = sign(unsigned_vp, holder_key, holder_did)
    verified = verify_vp(json.dumps(vp))
    assert verified


def test_verifiable_credential_fail():
    key = generate_keys()
    did = generate_did(key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did,
            "name": ""
        },
        "issuanceDate": now()
    }

    cred = json.dumps(credential)

    vc = sign(cred, key, did)
    vc["id"] = "bar"
    verified = verify_vc(json.dumps(vc))
    assert not verified


def test_verifiable_presentation_fail1():
    key = generate_keys()
    did = generate_did(key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did,
            "name": ""
        },
        "issuanceDate": now()
    }

    cred = json.dumps(credential)

    vc = sign(cred, key, did)
    vc_json = json.dumps(vc)

    holder_key = generate_keys()
    holder_did = generate_did(holder_key)
    unsigned_vp = get_presentation(vc_json, holder_did)
    vp = sign(unsigned_vp, holder_key, holder_did)
    vp["verifiableCredential"][0]["id"] = "bar"
    verified = verify_vp(json.dumps(vp))
    assert not verified


def test_verifiable_presentation_fail2():
    key = generate_keys()
    did = generate_did(key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did,
            "name": ""
        },
        "issuanceDate": now()
    }

    cred = json.dumps(credential)

    vc = sign(cred, key, did)
    vc_json = json.dumps(vc)

    holder_key = generate_keys()
    holder_did = generate_did(holder_key)
    unsigned_vp = get_presentation(vc_json, holder_did)
    vp = sign(unsigned_vp, holder_key, holder_did)
    vp["id"] = "http://example.org/presentations/3732"
    verified = verify_vp(json.dumps(vp))
    assert not verified


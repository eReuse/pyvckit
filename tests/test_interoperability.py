import json
import asyncio
import didkit
# import multicodec
# import multiformats
# import nacl.encoding
from ast import literal_eval

# from pyvckit.sign_vc import sign
from pyvckit.sign import sign
from pyvckit.sign_vp import get_presentation
from pyvckit.verify import verify_vc
from pyvckit.verify import verify_vp
from pyvckit.utils import now
from pyvckit.did import generate_keys, generate_did


def verify_credential(vc):
    async def inner():
        try:
            return await didkit.verify_credential(vc, '{"proofFormat": "ldp"}')
        except Exception:
            return False

    return asyncio.run(inner())


def render_and_sign_credential(unsigned_vc, jwk_issuer):
    async def inner():
        signed_vc = await didkit.issue_credential(
            json.dumps(unsigned_vc),
            '{"proofFormat": "ldp"}',
            jwk_issuer
        )
        return signed_vc

    return asyncio.run(inner())


def verify_presentation(vp: str):
    async def inner():
        str_res = await didkit.verify_presentation(vp, '{"proofFormat": "ldp"}')
        res = literal_eval(str_res)
        ok = res["warnings"] == [] and res["errors"] == []
        return ok, str_res

    valid, reason = asyncio.run(inner())
    if not valid:
        return False

    vp = json.loads(vp)
    for credential in vp["verifiableCredential"]:
        valid = verify_credential(json.dumps(credential))
        if not valid:
            return False

    return True


def issue_verifiable_presentation(vc_list, jwk_holder, holder_did, presentation_id):
    async def inner(unsigned_vp):
        signed_vp = await didkit.issue_presentation(
            unsigned_vp,
            '{"proofFormat": "ldp"}',
            jwk_holder
        )
        return signed_vp

    unsigned_vp = json.dumps({
        "@context": [
            "https://www.w3.org/2018/credentials/v1"
        ],
        "id": presentation_id,
        "type": [
            "VerifiablePresentation"
        ],
        "holder": holder_did,
        "verifiableCredential": vc_list
    })

    return asyncio.run(inner(unsigned_vp))

def test_key_from_didkit():
    key = didkit.generate_ed25519_key()
    did_didkit = didkit.key_to_did("key", key)
    did_pyvckit = generate_did(key)
    assert did_didkit == did_pyvckit


def test_key_from_pyvckit():
    key = generate_keys()
    did_didkit = didkit.key_to_did("key", key)
    did_pyvckit = generate_did(key)
    assert did_didkit == did_pyvckit


def test_pyvckit_credential_validated_from_didkit():
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
            "id": did
        },
        "issuanceDate": now()
    }

    cred = json.dumps(credential)

    vc = sign(cred, key, did)
    result = verify_credential(json.dumps(vc))
    assert result == '{"checks":["proof"],"warnings":[],"errors":[]}'


def test_didkit_credential_validated_from_pyvckit():
    key = didkit.generate_ed25519_key()
    did = didkit.key_to_did("key", key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did
        },
        "issuanceDate": now()
    }

    cred_signed = render_and_sign_credential(credential, key)

    result = verify_vc(cred_signed)
    assert result


def test_pyvckit_presentation_validated_from_didkit():
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
            "id": did
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

    result = verify_presentation(json.dumps(vp))
    assert result


def test_fail_pyvckit_presentation_validated_from_didkit():
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
            "id": did
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
    vp_fail = json.dumps(vp)

    result = verify_vp(vp_fail)
    result2 = verify_presentation(vp_fail)

    assert result == result2
    assert not result


def test_didkit_presentation_validated_from_pyvckit():
    key = didkit.generate_ed25519_key()
    did = didkit.key_to_did("key", key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did
        },
        "issuanceDate": now()
    }
    cred_signed = render_and_sign_credential(credential, key)

    holder_key = didkit.generate_ed25519_key()
    holder_did = didkit.key_to_did("key", holder_key)

    vc_list = [json.loads(cred_signed)]
    vp_signed = issue_verifiable_presentation(vc_list, holder_key, holder_did, "1")

    result = verify_vp(vp_signed)
    assert result


def test_fail_didkit_presentation_validated_from_pyvckit():
    key = didkit.generate_ed25519_key()
    did = didkit.key_to_did("key", key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did
        },
        "issuanceDate": now()
    }
    cred_signed = render_and_sign_credential(credential, key)

    holder_key = didkit.generate_ed25519_key()
    holder_did = didkit.key_to_did("key", holder_key)

    vc_list = [json.loads(cred_signed)]
    vp_signed = issue_verifiable_presentation(vc_list, holder_key, holder_did, "1")
    vp = json.loads(vp_signed)
    vp["verifiableCredential"][0]["id"] = "bar"
    vp_fail = json.dumps(vp)

    result = verify_vp(vp_fail)
    assert not result


def test_fail2_didkit_presentation_validated_from_pyvckit():
    key = didkit.generate_ed25519_key()
    did = didkit.key_to_did("key", key)

    credential = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "http://example.org/credentials/3731",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
        },
        "issuer": {
            "id": did
        },
        "issuanceDate": now()
    }
    cred_signed = render_and_sign_credential(credential, key)

    holder_key = didkit.generate_ed25519_key()
    holder_did = didkit.key_to_did("key", holder_key)

    vc_list = [json.loads(cred_signed)]
    vp_signed = issue_verifiable_presentation(vc_list, holder_key, holder_did, "1")
    vp = json.loads(vp_signed)
    vp['proof']['created'] = now()
    vp_fail = json.dumps(vp)

    result = verify_vp(vp_fail)
    result2 = verify_presentation(vp_fail)
    assert result == result2
    assert not result


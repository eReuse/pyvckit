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
    proof = json.loads(vc).get("proof", {})
    verification_method = proof.get("verificationMethod", "")
    proof_purpose = proof.get("proofPurpose", "")
    options = {
        "proofPurpose": proof_purpose,
        "verificationMethod": verification_method,
    }
    return didkit.verifyCredential(vc, json.dumps(options))


def render_and_sign_credential(unsigned_vc, key):
    verification_method = didkit.keyToVerificationMethod("key", key)
    options = {
        "proofPurpose": "assertionMethod",
        "verificationMethod": verification_method,
    }
    try:
        return didkit.issueCredential(
                json.dumps(unsigned_vc),
                json.dumps(options),
                key
            )
    except didkit.DIDKitException:
        return False


def verify_presentation(vp: str):
    proof = json.loads(vp).get("proof", {})
    verification_method = proof.get("verificationMethod", "")
    proof_purpose = proof.get("proofPurpose", "")
    options = {
        "proofPurpose": proof_purpose,
        "verificationMethod": verification_method,
    }
    try:
        return didkit.verifyPresentation(vp, json.dumps(options))
    except didkit.DIDKitException:
        return False


def issue_verifiable_presentation(vc_list, key_holder, holder_did, presentation_id):
    verification_method = didkit.keyToVerificationMethod("key", key_holder)
    options = {
        "proofPurpose": "assertionMethod",
        "verificationMethod": verification_method,
    }

    unsigned_vp = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "http://example.org/credentials/{}".format(presentation_id),
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": vc_list
    }

    return didkit.issuePresentation(
        json.dumps(unsigned_vp),
        json.dumps(options),
        key_holder
    )


def test_key_from_didkit():
    key = didkit.generateEd25519Key()
    did_didkit = didkit.keyToDID("key", key)
    did_pyvckit = generate_did(key)
    assert did_didkit == did_pyvckit


def test_key_from_pyvckit():
    key = generate_keys()
    did_didkit = didkit.keyToDID("key", key)
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
    key = didkit.generateEd25519Key()
    did = didkit.keyToDID("key", key)

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
    assert not result2

def test_didkit_presentation_validated_from_pyvckit():
    key = didkit.generateEd25519Key()
    did = didkit.keyToDID("key", key)

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

    holder_key = didkit.generateEd25519Key()
    holder_did = didkit.keyToDID("key", holder_key)

    vc_list = [json.loads(cred_signed)]
    vp_signed = issue_verifiable_presentation(vc_list, holder_key, holder_did, "1")

    result = verify_vp(vp_signed)
    assert result


def test_fail_didkit_presentation_validated_from_pyvckit():
    key = didkit.generateEd25519Key()
    did = didkit.keyToDID("key", key)

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

    holder_key = didkit.generateEd25519Key()
    holder_did = didkit.keyToDID("key", holder_key)

    vc_list = [json.loads(cred_signed)]
    vp_signed = issue_verifiable_presentation(vc_list, holder_key, holder_did, "1")
    vp = json.loads(vp_signed)
    vp["verifiableCredential"][0]["id"] = "bar"
    vp_fail = json.dumps(vp)

    result = verify_vp(vp_fail)
    assert not result


def test_fail2_didkit_presentation_validated_from_pyvckit():
    key = didkit.generateEd25519Key()
    did = didkit.keyToDID("key", key)

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

    holder_key = didkit.generateEd25519Key()
    holder_did = didkit.keyToDID("key", holder_key)

    vc_list = [json.loads(cred_signed)]
    vp_signed = issue_verifiable_presentation(vc_list, holder_key, holder_did, "1")
    vp = json.loads(vp_signed)
    vp['proof']['created'] = now()
    vp_fail = json.dumps(vp)

    result = verify_vp(vp_fail)
    result2 = verify_presentation(vp_fail)
    assert not result
    assert result2 == '{"checks":[],"warnings":[],"errors":["Crypto error"]}'

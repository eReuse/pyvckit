import json
import argparse
from utils import now
from did import generate_did, get_signing_key, key_read
from templates import credential_tmpl, proof_tmpl
from sign import sign_proof


# source: https://github.com/mmlab-aueb/PyEd25519Signature2018/blob/master/signer.py

def sign(credential, key, issuer_did):
    document = json.loads(credential)
    _did = issuer_did + "#" + issuer_did.split("did:key:")[1]
    proof = proof_tmpl.copy()
    proof['verificationMethod'] = _did
    proof['created'] = now()

    sign_proof(document, proof, key)
    del proof['@context']
    document['proof'] = proof
    return document


def main():
    parser=argparse.ArgumentParser(description='Generates a new credential')
    parser.add_argument("-k", "--key-path", required=True)
    args=parser.parse_args()

    if args.key_path:
        key = key_read(args.key_path)
        did = generate_did(key)
        signing_key = get_signing_key(key)

        credential = credential_tmpl.copy()
        credential["issuer"] = did
        credential["issuanceDate"] = now()
        cred = json.dumps(credential)

        vc = sign(cred, signing_key, did)

        print(json.dumps(vc, separators=(',', ':')))

        return


if __name__ == "__main__":
    main()

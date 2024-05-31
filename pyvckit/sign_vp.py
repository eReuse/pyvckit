import json
import argparse

from utils import now
from templates import presentation_tmpl, proof_tmpl
from did import key_read, generate_did, get_signing_key
from sign import sign_proof


def sign_vp(signing_key, holder_did, vc):
    presentation = presentation_tmpl.copy()
    presentation["verifiableCredential"].append(json.loads(vc))
    presentation["holder"] = holder_did

    _did = holder_did + "#" + holder_did.split("did:key:")[1]
    proof = proof_tmpl.copy()
    proof['verificationMethod'] = _did
    proof['created'] = now()

    sign_proof(presentation, proof, signing_key)
    del proof['@context']
    presentation['proof'] = proof
    return presentation


def main():
    parser=argparse.ArgumentParser(description='Generates a new credential')
    parser.add_argument("-k", "--key-path", required=True)
    parser.add_argument("-c", "--credential-path", required=True)
    args=parser.parse_args()

    if args.key_path and args.credential_path:
        with open(args.credential_path, "r") as f:
            vc = f.read()

        if not vc:
            print("You need pass a credential.")
            return

        key = key_read(args.key_path)
        did = generate_did(key)
        signing_key = get_signing_key(key)
        vp = sign_vp(signing_key, did, vc)
        print(json.dumps(vp, separators=(',', ':')))

        return


if __name__ == "__main__":
    main()

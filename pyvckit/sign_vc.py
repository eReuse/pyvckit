import json
import argparse
from pyvckit.utils import now
from pyvckit.did import generate_did, key_read
from pyvckit.templates import credential_tmpl
from pyvckit.sign import sign


# source: https://github.com/mmlab-aueb/PyEd25519Signature2018/blob/master/signer.py


def main():
    parser=argparse.ArgumentParser(description='Generates a new credential')
    parser.add_argument("-k", "--key-path", required=True)
    args=parser.parse_args()

    if args.key_path:
        key = key_read(args.key_path)
        did = generate_did(key)

        credential = json.loads(credential_tmpl)
        credential["issuer"]["id"] = did
        credential["issuanceDate"] = now()
        cred = json.dumps(credential)

        vc = sign(cred, key, did)

        print(json.dumps(vc, separators=(',', ':')))

        return


if __name__ == "__main__":
    main()

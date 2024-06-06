import json
import argparse

from pyvckit.templates import presentation_tmpl
from pyvckit.did import key_read, generate_did
from pyvckit.sign import sign


def get_presentation(vc, holder_did):
    presentation = json.loads(presentation_tmpl)
    presentation["verifiableCredential"].append(json.loads(vc))
    presentation["holder"] = holder_did
    return json.dumps(presentation)


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
        unsigned_vp = get_presentation(vc, did)
        vp = sign(unsigned_vp, key, did)
        print(json.dumps(vp, separators=(',', ':')))

        return


if __name__ == "__main__":
    main()

import json
import argparse
import multicodec
import multiformats
import nacl.signing
import nacl.encoding

from jwcrypto import jwk
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder


def key_to_did(public_key_bytes, type_did):
    """did-key-format := 
       did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))"""

    mc = multicodec.add_prefix('ed25519-pub', public_key_bytes)

    # Multibase encode the hashed bytes
    did = multiformats.multibase.encode(mc, 'base58btc')

    if type_did == "web":
        return f"did:web:{did}"

    return f"did:key:{did}"


def key_read(path_keys):
  # Save the private JWK to a file
  with open(path_keys, 'r') as f:
      private_jwk = f.read()

  return jwk.JWK.from_json(private_jwk)


def get_signing_key(jwk_pr):
    private_key_material_str = jwk_pr['d']
    missing_padding = len(private_key_material_str) % 4
    if missing_padding:
      private_key_material_str += '=' * (4 - missing_padding)

    private_key_material = nacl.encoding.URLSafeBase64Encoder.decode(private_key_material_str)
    signing_key = SigningKey(private_key_material, encoder=RawEncoder)
    return signing_key


def generate_did(jwk_pr, type_did=None):
    signing_key = get_signing_key(jwk_pr)
    verify_key = signing_key.verify_key
    public_key_bytes = verify_key.encode()

    # Generate the DID
    did = key_to_did(public_key_bytes, type_did)
    return did

def generate_keys():
    # Generate an Ed25519 key pair
    key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
    key['kid'] = 'Generated'
    return key.export_private(True)


def main():
    parser=argparse.ArgumentParser(description='Generates a new did or key pair')
    parser.add_argument("-k", "--key-path", required=False)
    parser.add_argument("-n", "--new", choices=['keys', 'did'])
    args=parser.parse_args()

    if args.new == 'keys':
        keyspair = generate_keys()
        print(json.dumps(keyspair))
        return

    if not args.key_path and args.new == 'did':
        print("error: argument --key-path: expected one argument")
        return

    if args.new == 'did':
        key = key_read(args.key_path)
        did = generate_did(key)
        print(json.dumps(did))
        return
    

if __name__ == "__main__":
    main()

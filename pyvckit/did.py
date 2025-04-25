import json
import argparse
import requests
import multicodec
import multiformats
import nacl.signing
import nacl.encoding

from jwcrypto import jwk
from urllib.parse import urlparse
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from pyvckit.templates import did_document_tmpl


def key_to_did(public_key_bytes, url):
    """did-key-format :=
       did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))"""

    mc = multicodec.add_prefix('ed25519-pub', public_key_bytes)

    # Multibase encode the hashed bytes
    did = multiformats.multibase.encode(mc, 'base58btc')

    if url:
        u = urlparse(url)
        domain = u.netloc
        path = u.path.strip("/").replace("/", ":")
        if path:
            return f"did:web:{domain}:{path}:{did}"
        return f"did:web:{domain}:{did}"

    return f"did:key:{did}"


def key_read(path_keys):
  # Save the private JWK to a file
  with open(path_keys, 'r') as f:
      private_jwk = f.read()

  return private_jwk


def get_signing_key(jwk_pr):
    key = json.loads(jwk_pr)
    private_key_material_str = key['d']
    missing_padding = len(private_key_material_str) % 4
    if missing_padding:
      private_key_material_str += '=' * (4 - missing_padding)

    private_key_material = nacl.encoding.URLSafeBase64Encoder.decode(private_key_material_str)
    signing_key = SigningKey(private_key_material, encoder=RawEncoder)
    return signing_key


def get_public_key_bytes(pub_str):
    pub = pub_str
    missing_padding = len(pub_str) % 4
    if missing_padding:
      pub += '=' * (4 - missing_padding)

    public_key_bytes = nacl.encoding.URLSafeBase64Encoder.decode(pub)
    return public_key_bytes

def get_hash_public_key(public_key_bytes):
    mc = multicodec.add_prefix('ed25519-pub', public_key_bytes)

    # Multibase encode the hashed bytes
    did = multiformats.multibase.encode(mc, 'base58btc')
    return did


def generate_did(jwk_pr, url=None):
    signing_key = get_signing_key(jwk_pr)
    verify_key = signing_key.verify_key
    public_key_bytes = verify_key.encode()

    # Generate the DID
    did = key_to_did(public_key_bytes, url)
    return did

def generate_keys():
    # Generate an Ed25519 key pair
    key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
    key['kid'] = 'Generated'
    key_json = key.export_private(True)
    return json.dumps(key_json)


def gen_did_document(did, keys):
    if did[:8] != "did:web:":
        return "", ""
    document = json.loads(did_document_tmpl)
    webdid_owner = did+"#owner"
    webdid_revocation = did+"#revocation"
    document["id"] = did
    document["verificationMethod"][0]["id"] = webdid_owner
    document["verificationMethod"][0]["controller"] = did
    document["verificationMethod"][0]["publicKeyJwk"]["x"] = keys["x"]
    document["authentication"].append(webdid_owner)
    document["assertionMethod"].append(webdid_owner)
    document["service"][0]["id"] = webdid_revocation
    document_fixed_serialized = json.dumps(document)
    url = "https://" + "/".join(did.split(":")[2:]) + "/did.json"

    return url, document_fixed_serialized


def resolve_did(did):
    if did[:8] != "did:web:":
        return

    sdid = did[8:].split(":")
    try:
        if len(sdid) > 2:
            url = "https://{}/did.json".format("/".join(sdid))
        elif len(sdid) == 2:
            url = "https://{}/.well-known/{}/did.json".format(*sdid)
        response = requests.get(url)
    except Exception:
        if len(sdid) > 2:
            url = "http://{}/did.json".format("/".join(sdid))
        elif len(sdid) == 2:
            url = "http://{}/.well-known/{}/did.json".format(*sdid)
        response = requests.get(url)

    if 200 <= response.status_code < 300:
        return response.json()


def main():
    parser=argparse.ArgumentParser(description='Generates a new did or key pair')
    parser.add_argument("-k", "--key-path", required=False)
    parser.add_argument("-n", "--new", choices=['keys', 'did'])
    parser.add_argument("-u", "--url")
    parser.add_argument("-g", "--gen-doc")
    args=parser.parse_args()

    if args.new == 'keys':
        keyspair = generate_keys()
        print(keyspair)
        return

    if not args.key_path and args.new == 'did':
        print("error: argument --key-path: expected one argument")
        return

    if args.new == 'did' and args.url:
        key = key_read(args.key_path)
        did = generate_did(key, args.url)
        print(did)
        return

    if args.new == 'did':
        key = key_read(args.key_path)
        did = generate_did(key)
        print(did)
        return

    if args.gen_doc and not args.key_path:
        print("error: argument --key-path: expected one argument")
        return

    if args.gen_doc:
        keys = json.loads(key_read(args.key_path))
        if not keys.get("x"):
            print("error: argument --key-path: not is valid")
            return

        url, doc = gen_did_document(args.gen_doc, keys)
        # print(url)
        print(doc)
        return

if __name__ == "__main__":
    main()

# PyVckit
PyVckit is a library for:
- sign verifiable credentials
- verify verifiable credentials
- generate verifiable presentations
- verify verifiable submissions

This library is strongly inspired by [SpruceId didkit](https://github.com/spruceid/didkit) and aims to maintain compatibility with it.

For now the supported cryptography is only EdDSA with a signature Ed25519Signature2018.

# Install
For now the installation is from the repository:
```sh
    python -m venv env
    source env/bin/activate
    git clone https://farga.pangea.org/ereuse/pyvckit.git
    cd pyvckit
    pip install -r requirements.txt
    pip install -e .
```

# Cli
The mode of use under the command line would be the following:

## generate a key pair:
```sh
    python pyvckit/did.py -n keys > keypair.json
```

## generate a did identifier:

### did key
```sh
  python pyvckit/did.py -n did -k keypair.json
```

### did web
```sh
  python pyvckit/did.py -n did -k keypair.json -u https://localhost/user1/dids/
```

## generate an example signed credential:
An example of a credential is generated, which is the one that appears in the credential_tmpl template in the file [templates.py](templates.py)
```sh
    python pyvckit/sign_vc.py -k keypair.json > credential_signed.json
```

## verify a signed credential:
```sh
    python pyvckit/verify_vc.py credential_signed.json
```

## generate a verifiable presentation:
```sh
    python pyvckit/sign_vp.py -k keypair.json -c credential_signed.json > presentation_signed.json
```

## verify a verifiable presentation:
```sh
    python pyvckit/verify_vp.py presentation_signed.json
```

## creation of did document:
This command will create a json document and a url path where to place this document. The did must be a web did.
This document is an example and in production it must be adapted to contain the revoked verifiable credentials.
```sh
  python pyvckit/did.py -k keypair.json -g did:web:localhost:did-registry:z6MkiNc8xqJLcG7QR1wzD9HPs5oPQEaWNcVf92QsbppNiB7C
```

# Use as a library
In the tests you can find examples of use. Now I will explain the usual cases

## generate a key pair:
```python
    from pyvckit.did import generate_keys
    key = generate_keys()
```

## generate a did identifier:

### did key
```python
    from pyvckit.did import generate_keys, generate_did
    key = generate_keys()
    did = generate_did(key)
```

### did web
```python
    from pyvckit.did import generate_keys, generate_did
    key = generate_keys()
    url = "https://localhost/user1/dids/"
    did = generate_did(key, url)
```

## generate a signed credential:
Assuming **credential** is a valid credential.
**credential** is a string variable
```python
    from pyvckit.did import generate_keys, generate_did, get_signing_key
    from pyvckit.sign_vc import sign

    key = generate_keys()
    did = generate_did(key)
    signing_key = get_signing_key(key)
    vc = sign(credential, signing_key, did)
```

## verify a signed credential:
Assuming **vc** is a properly signed verifiable credential
```python
    import json
    from pyvckit.verify import verify_vc

    verified = verify_vc(json.dumps(vc))
```

## generate a verifiable presentation:
```python
    from pyvckit.did import generate_keys, generate_did, get_signing_key
    from pyvckit.sign_vp import sign_vp

    holder_key = generate_keys()
    holder_did = generate_did(holder_key)
    holder_signing_key = get_signing_key(holder_key)
    vp = sign_vp(holder_signing_key, holder_did, vc_string)
```

## verify a verifiable presentation:
```python
    from pyvckit.verify_vp import verify_vp
    verified = verify_vp(json.dumps(vp))
```

## creation of did document:
This command will create a json document and a url path where to place this document. The did must be a web did.
This document is an example and in production it must be adapted to contain the revoked verifiable credentials.
```python
    from pyvckit.did import generate_keys, generate_did, gen_did_document

    key = generate_keys()
    url = "https://localhost/did-registry"
    did = generate_did(key, url)
    definitive_url, document = gen_did_document(did, key)
```

# Differences with didkit from spruceId:
Although there is didkit support, there are some small differences in behavior.

## Namespaces:
In didkit it is necessary to define in the context every name, (key) used in the credential or else both the signature and the verification will fail.
In pyvckit if a name, (key) is used but is not defined in the context, then that signature or verification will filter out that part of the credential and ignore it as if it did not exist.
The signature will be made by deleting that undefined part.

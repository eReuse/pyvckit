import json
import didkit
import multicodec
import multiformats
import nacl.encoding

from did import generate_keys, generate_did


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



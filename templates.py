# templates


credential_tmpl = {
    "@context": "https://www.w3.org/2018/credentials/v1",
    "id": "http://example.org/credentials/3731",
    "type": ["VerifiableCredential"],
    "credentialSubject": {
        "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M",
    },
    "issuer": None,
    "issuanceDate": None
}

proof_tmpl = {
    '@context':'https://w3id.org/security/v2',
    'type': 'Ed25519Signature2018',
    'proofPurpose': 'assertionMethod',
    'verificationMethod': None,
    'created': None
}

presentation_tmpl = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "http://example.org/presentations/3731",
    "type": ["VerifiablePresentation"],
    "holder": "",
    "verifiableCredential": []
}

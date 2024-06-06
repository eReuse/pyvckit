# templates


credential_tmpl = """{
    "@context": "https://www.w3.org/2018/credentials/v1",
    "id": "http://example.org/credentials/3731",
    "type": [
        "VerifiableCredential"
    ],
    "credentialSubject": {
        "id": "did:key:z6MkgGXSJoacuuNdwU1rGfPpFH72GACnzykKTxzCCTZs6Z2M"
    },
    "issuer": {
      "id": ""
    },
    "issuanceDate": ""
}"""

proof_tmpl = """{
    "@context":"https://w3id.org/security/v2",
    "type": "Ed25519Signature2018",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "",
    "created": ""
}"""

presentation_tmpl = """{
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "http://example.org/presentations/3731",
    "type": ["VerifiablePresentation"],
    "holder": "",
    "verifiableCredential": []
}"""


did_document_tmpl = """{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    {
      "Ed25519VerificationKey2018": "https://w3id.org/security#Ed25519VerificationKey2018",
      "publicKeyJwk": {
        "@id": "https://w3id.org/security#publicKeyJwk",
        "@type": "@json"
      }
    }
  ],
  "id": "",
  "verificationMethod": [
    {
      "id": "",
      "type": "Ed25519VerificationKey2018",
      "controller": "",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": ""
      }
    }
  ],
  "authentication": [
  ],
  "assertionMethod": [
  ],
  "service": [
    {
      "id": "",
      "type": "RevocationBitmap2022",
      "serviceEndpoint": "data:application/octet-stream;base64,eJyzMmAAAwADKABr"
    }
  ]
}"""

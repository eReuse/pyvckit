#!/usr/bin/env python3

import argparse
from pyvckit.verify import verify_schema


def get_credential(path_credential):
    with open(path_credential, "r") as f:
        vc = f.read()
    return vc


def main():
    parser=argparse.ArgumentParser(description="Verify a credential's json schema ")
    parser.add_argument("credential_path")
    args=parser.parse_args()

    if args.credential_path:
        credential = get_credential(args.credential_path)
        print(verify_schema(credential))


if __name__ == "__main__":
    main()

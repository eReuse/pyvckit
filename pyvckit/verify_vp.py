import json
import argparse
from pyvckit.verify import verify_vc


def get_presentation(path_presentation):
    with open(path_presentation, "r") as f:
        vc = f.read()
    return vc


def verify_vp(presentation):
    vp = json.loads(presentation)

    if not verify_vc(presentation):
        return False

    for vc in vp['verifiableCredential']:
        vc_str = json.dumps(vc)
        if not verify_vc(vc_str):
            return False

    return True


def main():
    parser=argparse.ArgumentParser(description='Verify a presentation')
    parser.add_argument("presentation_path")
    args=parser.parse_args()

    if args.presentation_path:
        presentation = get_presentation(args.presentation_path)
        print(verify_vp(presentation))


if __name__ == "__main__":
    main()

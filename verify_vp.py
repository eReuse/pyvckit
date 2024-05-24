import json
import argparse
from verify import verify_vc


def get_presentation(path_presentation):
    with open(path_presentation, "r") as f:
        vc = f.read()
    return vc


def main():
    parser=argparse.ArgumentParser(description='Verify a presentation')
    parser.add_argument("presentation_path")
    args=parser.parse_args()

    if args.presentation_path:
        presentation = get_presentation(args.presentation_path)
        presentation_verified = verify_vc(presentation)
        if not presentation_verified:
            print(presentation_verified)
            return

        vp = json.loads(presentation)
        for vc in vp['verifiableCredential']:
            vc_str = json.dumps(vc)
            verified = verify_vc(vc_str)
            if not verified:
                print(verified)
                return

        print(True)
        return


if __name__ == "__main__":
    main()

import argparse

from pyvckit.verify import verify_vp_signature


def get_presentation(path_presentation):
    with open(path_presentation, "r") as f:
        vc = f.read()
    return vc


def main():
    parser=argparse.ArgumentParser(description="Verify a presentation's signature")
    parser.add_argument("presentation_path")
    args=parser.parse_args()

    if args.presentation_path:
        presentation = get_presentation(args.presentation_path)
        print(verify_vp_signature(presentation))


if __name__ == "__main__":
    main()

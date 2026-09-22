#!/bin/sh

set -e
set -u
# DEBUG
set -x

main() {
        if [ ! -f "$HOME/.pypirc" ]; then
                echo "Error: Missing $HOME/.pypirc"
                exit 1
        fi

        cd "$(dirname "$0")/.."

        if [ -n "$(git status --porcelain)" ]; then
                echo "You have uncommitted changes in git"
                exit 1
        fi

        CURRENT_VERSION=$(grep '^version *=' pyproject.toml | cut -d'"' -f2)

        set +x
        printf "Current version [%s]. Enter new version: " "$CURRENT_VERSION"
        read NEW_VERSION
        set -x

        NEW_VERSION="${NEW_VERSION:-$CURRENT_VERSION}"

        sed "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" pyproject.toml > pyproject.toml.tmp
        mv pyproject.toml.tmp pyproject.toml

        rm -rf dist/ build/ src/*.egg-info *.egg-info

        python3 -m build

        python3 -m twine upload --non-interactive dist/*

        git add pyproject.toml
        git commit -m "Bump version to ${NEW_VERSION}"
        git tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"
}

main "${@:-}"

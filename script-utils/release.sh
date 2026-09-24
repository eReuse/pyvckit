#!/bin/sh

set -e
set -u
# DEBUG
set -x

do_codeberg_release() {
        release_data='{
  "tag_name":"%s",
  "name":"%s",
  "body":"%s",
  "draft":false,
  "prerelease":false,
  "hide_archive_links":true
}'
        codeberg_post_url='https://codeberg.org/api/v1/repos'
        curl -s \
             -X POST "${codeberg_post_url}/${CODEBERG_USER}/${CODEBERG_REPO}/releases" \
             -H "Authorization: token ${CODEBERG_TOKEN}" \
             -H "Content-Type: application/json" \
             -d "$(printf "${release_data}" \
                          "${NEW_VERSION}" "${NEW_VERSION}" "${release_message}")"
}

main() {
        # TODO better integration with CHANGELOG generation

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

        # TODO make less interactive
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
        # prints last markdown header
        CHANGELOG_CONTENT="$(awk '/^# /{if(printing)exit; printing=1} printing' ../CHANGELOG.md)"
        git tag -a "v${NEW_VERSION}" --cleanup=verbatim -m "${CHANGELOG_CONTENT}"
        git push origin "${NEW_VERSION}"

        # TODO test forgejo (it's very easy with form anyway)
        # looks like I should wait some seconds, to ensure release works
        #sleep 5
        #
        #do_codeberg_release

        # TODO do github / pyinfra did it with python
        # not that easy to generate, needs copypaste from git tag
}

main "${@:-}"

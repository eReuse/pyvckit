#!/usr/bin/env bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== publish to Pypi ===${NC}\n"

# --- check for pypirc (pypi credentials) ---
PYPIRC_FILE="$HOME/.pypirc"
echo "Checking for PyPI credentials..."
if [ ! -f "$PYPIRC_FILE" ]; then
    echo -e "${RED}[!] Error: Missing $PYPIRC_FILE${NC}"
    echo -e "${YELLOW}To publish automatically, you must have a .pypirc file in your home directory.${NC}"
    echo -e "Please create the file with the following structure:\n"
    echo -e "  [pypi]"
    echo -e "  username = __token__"
    echo -e "  password = pypi-your-token-here\n"
    exit 1
fi
echo -e "${GREEN}[*] Found ~/.pypirc${NC}\n"

# check for root folder if script run somewhere else
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TOML_FILE="$PROJECT_ROOT/pyproject.toml"

cd "$PROJECT_ROOT"

#detec python alias
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo -e "${RED}[!] Neither 'python3' nor 'python' command was found in your PATH.${NC}"
    exit 1
fi

# check git for dangling files
echo "Checking git status..."
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}[!] You have uncommitted changes in git. It is recommended to commit before publishing.${NC}"
    read -p "Do you want to continue anyway? (y/N): " resp
    if [[ ! "$resp" =~ ^[yY]$ ]]; then
        echo "Aborting."
        exit 1
    fi
fi

# update version
if [ ! -f "$TOML_FILE" ]; then
    echo -e "${RED}[!] File $TOML_FILE not found${NC}"
    exit 1
fi
CURRENT_VERSION=$(grep -E '^version\s*=' "$TOML_FILE" | cut -d'"' -f2)
if [ -z "$CURRENT_VERSION" ]; then
    echo -e "${RED}[!] Could not find the version in pyproject.toml${NC}"
    exit 1
fi

echo -e "Current version: ${YELLOW}$CURRENT_VERSION${NC}"

# suggest the next version
IFS='.' read -ra VER_PARTS <<< "$CURRENT_VERSION"
LAST_INDEX=$((${#VER_PARTS[@]} - 1))
PATCH=${VER_PARTS[$LAST_INDEX]}
let PATCH+=1
VER_PARTS[$LAST_INDEX]=$PATCH
SUGGESTED_VERSION=$(IFS=. ; echo "${VER_PARTS[*]}")

read -p "Enter the new version number [$SUGGESTED_VERSION]: " NEW_VERSION
NEW_VERSION=${NEW_VERSION:-$SUGGESTED_VERSION}

# replace the version in the file
sed "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" "$TOML_FILE" > "${TOML_FILE}.tmp"
mv "${TOML_FILE}.tmp" "$TOML_FILE"

echo -e "${GREEN}[*] Version updated to $NEW_VERSION in pyproject.toml${NC}\n"

# remove old build folder if any
echo "Cleaning up old build directories..."
rm -rf dist/ build/ src/*.egg-info *.egg-info
echo " - Deleted: dist/, build/, and *.egg-info"

# 5. Build the package
echo -e "\n> Running: $PYTHON_CMD -m build"
$PYTHON_CMD -m build

#upload to pypi with Twine
echo -e "\n> Starting PyPI upload..."
set +e
$PYTHON_CMD -m twine upload --non-interactive dist/*
TWINE_EXIT_CODE=$?
set -e
if [ $TWINE_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}[!] Error uploading to PyPI. Please check that your token in ~/.pypirc is valid and has not expired.${NC}"
    sed "s/^version = \"$NEW_VERSION\"/version = \"$CURRENT_VERSION\"/" "$TOML_FILE" > "${TOML_FILE}.tmp"
    mv "${TOML_FILE}.tmp" "$TOML_FILE"
    echo -e "${YELLOW}[*] Reverted pyproject.toml back to version $CURRENT_VERSION due to upload failure.${NC}"
    exit 1
fi

# create a Git tag
echo ""
read -p "Do you want to create a git tag for version v$NEW_VERSION? (Y/n): " tag_resp
tag_resp=${tag_resp:-Y}

if [[ "$tag_resp" =~ ^[yY]$ ]]; then
    git add "$TOML_FILE"
    git commit -m "Bump version to $NEW_VERSION" || true
    git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION"
    echo -e "${GREEN}[*] Tag v$NEW_VERSION created. Remember to run 'git push --tags' when you are ready.${NC}"
fi

echo -e "\n${GREEN}=== completed ===${NC}"

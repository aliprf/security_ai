#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <absolute-or-tilde-path-to-env>"
  exit 1
fi

# Expand ~ to $HOME if present
TARGET_PATH="${1/#\~/$HOME}"

# Convert to absolute path
TARGET_PATH="$(realpath -m "$TARGET_PATH")"

echo "Target Pixi env path: $TARGET_PATH"

# Create target directory if it doesn't exist
mkdir -p "$TARGET_PATH"

# Check if .pixi directory exists in current folder
if [ -d ".pixi" ]; then
  echo "Moving existing .pixi to $TARGET_PATH"
  # Move the entire .pixi directory content to target
  # If target is empty, move whole folder; otherwise move contents to avoid nesting
  if [ "$(ls -A "$TARGET_PATH")" ]; then
    # Target not empty: move contents individually
    mv .pixi/* "$TARGET_PATH"/
    rmdir .pixi
  else
    # Target empty: move whole directory
    mv .pixi "$TARGET_PATH"
  fi
else
  echo "No existing .pixi directory found in current folder."
fi

# Remove existing .pixi symlink or directory if any (to avoid conflicts)
if [ -L ".pixi" ] || [ -d ".pixi" ]; then
  rm -rf .pixi
fi

# Create symlink
ln -s "$TARGET_PATH" .pixi
echo "Created symlink: .pixi -> $TARGET_PATH"

echo "Done. Pixi environment location is now set to $TARGET_PATH"

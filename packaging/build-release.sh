#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$project_dir/manifest.json")
output_dir="${1:-$project_dir/dist}"
archive="$output_dir/omarchy-cyber-scout-widget-$version.tar.gz"

mkdir -p "$output_dir"
git -C "$project_dir" diff --quiet
git -C "$project_dir" diff --cached --quiet
git -C "$project_dir" archive --format=tar.gz --prefix="omarchy-cyber-scout-widget-$version/" -o "$archive" HEAD
sha256sum "$archive" > "$archive.sha256"
echo "$archive"

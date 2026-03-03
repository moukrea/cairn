#!/usr/bin/env bash
# bump-packages.sh — Detect changed components and bump their versions.
# Outputs BUMPED_PACKAGES to GITHUB_OUTPUT (e.g. "cairn-p2p-rs:0.2.0 cairn-p2p-ts:0.1.1").
set -euo pipefail

# Component definitions: name:directory:version_file:tag_prefix
# Empty version_file means version comes from tags only (Go, PHP).
COMPONENTS=(
  "cairn-p2p-rs:packages/rs/cairn-p2p:packages/rs/cairn-p2p/Cargo.toml:cairn-p2p-rs-"
  "cairn-p2p-ts:packages/ts/cairn-p2p:packages/ts/cairn-p2p/package.json:cairn-p2p-ts-"
  "cairn-p2p-go:packages/go/cairn-p2p::packages/go/cairn-p2p/v"
  "cairn-p2p-py:packages/py/cairn-p2p:packages/py/cairn-p2p/pyproject.toml:cairn-p2p-py-"
  "cairn-p2p-php:packages/php/cairn-p2p::cairn-p2p-php-"
  "cairn-relay:services/relay:services/relay/Cargo.toml:cairn-relay-"
  "cairn-signal:services/signaling:services/signaling/Cargo.toml:cairn-signal-"
)

BUMPED=()

# Get files changed in the last commit
if git rev-parse HEAD~1 &>/dev/null; then
  changed_files=$(git diff --name-only HEAD~1 HEAD)
else
  # First commit — treat all tracked files as changed
  changed_files=$(git ls-tree -r --name-only HEAD)
fi

# Parse a semver string into components
parse_version() {
  local ver="$1"
  ver="${ver#v}"  # strip leading v
  IFS='.' read -r major minor patch <<< "$ver"
  echo "${major:-0} ${minor:-0} ${patch:-0}"
}

# Read current version from manifest file
read_version_from_file() {
  local name="$1"
  local version_file="$2"

  case "$version_file" in
    *.toml)
      grep '^version' "$version_file" | head -1 | sed 's/.*"\(.*\)".*/\1/'
      ;;
    *.json)
      grep '"version"' "$version_file" | head -1 | sed 's/.*: *"\(.*\)".*/\1/'
      ;;
    *)
      echo "0.0.0"
      ;;
  esac
}

# Read current version from the latest git tag
read_version_from_tag() {
  local tag_prefix="$1"
  local latest_tag

  if [[ "$tag_prefix" == packages/go/cairn-p2p/v ]]; then
    latest_tag=$(git tag -l "packages/go/cairn-p2p/v*" --sort=-v:refname | head -1)
  else
    latest_tag=$(git tag -l "${tag_prefix}*" --sort=-v:refname | head -1)
  fi

  if [ -z "$latest_tag" ]; then
    echo "0.0.0"
    return
  fi

  # Strip the prefix to get the version
  local ver="${latest_tag#"$tag_prefix"}"
  ver="${ver#v}"
  echo "$ver"
}

# Determine bump type from conventional commits
determine_bump() {
  local dir="$1"
  local since_ref="$2"
  local bump="none"

  local root_commit
  root_commit=$(git rev-list --max-parents=0 HEAD | head -1)

  local commits
  if [ "$since_ref" = "$root_commit" ]; then
    # Include the root commit itself (no parent to diff against)
    commits=$(git log --oneline HEAD -- "$dir" 2>/dev/null || true)
  else
    commits=$(git log --oneline "$since_ref"..HEAD -- "$dir" 2>/dev/null || true)
  fi

  if [ -z "$commits" ]; then
    echo "none"
    return
  fi

  while IFS= read -r line; do
    local msg="${line#* }"

    # Check for breaking changes
    if echo "$msg" | grep -qE '^[a-z]+(\(.*\))?!:'; then
      echo "major"
      return
    fi

    # Check for features
    if echo "$msg" | grep -qE '^feat(\(|:)'; then
      bump="minor"
    fi

    # Check for fixes/other (only upgrade to patch if still none)
    if [ "$bump" = "none" ] && echo "$msg" | grep -qE '^(fix|perf|refactor|build)(\(|:)'; then
      bump="patch"
    fi
  done <<< "$commits"

  echo "$bump"
}

# Apply semver bump
bump_version() {
  local version="$1"
  local bump_type="$2"

  read -r major minor patch <<< "$(parse_version "$version")"

  case "$bump_type" in
    major) echo "$((major + 1)).0.0" ;;
    minor) echo "${major}.$((minor + 1)).0" ;;
    patch) echo "${major}.${minor}.$((patch + 1))" ;;
    *)     echo "$version" ;;
  esac
}

# Write new version to manifest file
write_version() {
  local version_file="$1"
  local new_version="$2"

  case "$version_file" in
    *.toml)
      sed -i "s/^version = \".*\"/version = \"${new_version}\"/" "$version_file"
      ;;
    *.json)
      if command -v npm &>/dev/null && [[ "$version_file" == *package.json ]]; then
        local dir
        dir=$(dirname "$version_file")
        (cd "$dir" && npm version "$new_version" --no-git-tag-version --allow-same-version)
      else
        sed -i "s/\"version\": \".*\"/\"version\": \"${new_version}\"/" "$version_file"
      fi
      ;;
  esac
}

# Create the appropriate tag for a component
make_tag() {
  local name="$1"
  local tag_prefix="$2"
  local new_version="$3"

  echo "${tag_prefix}${new_version}"
}

echo "=== Checking for component changes ==="

for component in "${COMPONENTS[@]}"; do
  IFS=':' read -r name dir version_file tag_prefix <<< "$component"

  # Check if this component's directory has changes
  if ! echo "$changed_files" | grep -q "^${dir}/"; then
    echo "[$name] No changes detected in $dir — skipping"
    continue
  fi

  echo "[$name] Changes detected in $dir"

  # Find the reference point (latest tag for this component)
  local_latest_tag=""
  if [[ "$tag_prefix" == "packages/go/cairn-p2p/v" ]]; then
    local_latest_tag=$(git tag -l "packages/go/cairn-p2p/v*" --sort=-v:refname | head -1)
  else
    local_latest_tag=$(git tag -l "${tag_prefix}*" --sort=-v:refname | head -1)
  fi

  if [ -z "$local_latest_tag" ]; then
    since_ref=$(git rev-list --max-parents=0 HEAD | head -1)
    echo "  No previous tag found — using initial commit as reference"
  else
    since_ref="$local_latest_tag"
    echo "  Latest tag: $local_latest_tag"
  fi

  # Determine bump type from commits
  bump_type=$(determine_bump "$dir" "$since_ref")

  if [ "$bump_type" = "none" ]; then
    echo "  No conventional commits warrant a bump — skipping"
    continue
  fi

  echo "  Bump type: $bump_type"

  # Read current version
  if [ -n "$version_file" ]; then
    current_version=$(read_version_from_file "$name" "$version_file")
  else
    current_version=$(read_version_from_tag "$tag_prefix")
  fi

  echo "  Current version: $current_version"

  # Compute new version
  new_version=$(bump_version "$current_version" "$bump_type")
  echo "  New version: $new_version"

  # Update version file if applicable
  if [ -n "$version_file" ]; then
    write_version "$version_file" "$new_version"
    echo "  Updated $version_file"
  fi

  # Record the bump
  tag=$(make_tag "$name" "$tag_prefix" "$new_version")
  BUMPED+=("${name}:${new_version}:${tag}")
  echo "  Tag: $tag"
done

# Update Cargo.lock if any Rust component changed
rust_changed=false
for b in "${BUMPED[@]+"${BUMPED[@]}"}"; do
  case "$b" in
    cairn-p2p-rs:*|cairn-relay:*|cairn-signal:*)
      rust_changed=true
      break
      ;;
  esac
done

if [ "$rust_changed" = true ] && command -v cargo &>/dev/null; then
  echo ""
  echo "=== Updating Cargo.lock ==="
  cargo generate-lockfile 2>/dev/null || echo "Warning: cargo generate-lockfile failed"
fi

echo ""
echo "=== Summary ==="

if [ ${#BUMPED[@]} -eq 0 ]; then
  echo "No packages to bump."
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "bumped=" >> "$GITHUB_OUTPUT"
    echo "has_bumps=false" >> "$GITHUB_OUTPUT"
  fi
  exit 0
fi

# Build output strings
bump_summary=""
tags=()
for b in "${BUMPED[@]}"; do
  IFS=':' read -r name version tag <<< "$b"
  bump_summary="${bump_summary}${bump_summary:+, }${name} to ${version}"
  tags+=("$tag")
  echo "  $name → $version ($tag)"
done

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "has_bumps=true" >> "$GITHUB_OUTPUT"
  echo "commit_message=chore(release): bump ${bump_summary}" >> "$GITHUB_OUTPUT"

  # Output bumped entries as newline-separated (name:version:tag per line)
  printf -v bumped_str '%s\n' "${BUMPED[@]}"
  {
    echo "bumped<<EOF"
    echo "$bumped_str"
    echo "EOF"
  } >> "$GITHUB_OUTPUT"

  # Output tags as newline-separated for easier iteration
  printf -v tags_str '%s\n' "${tags[@]}"
  {
    echo "tags<<EOF"
    echo "$tags_str"
    echo "EOF"
  } >> "$GITHUB_OUTPUT"
fi

echo ""
echo "Commit message: chore(release): bump ${bump_summary}"

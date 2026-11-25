#!/bin/sh
# Pull-based deployment of the Foretaster site, for a web host that accepts no
# inbound connections. Run it from cron on the host:
#
#     */15 * * * * /bin/sh /home/USER/foretaster-pull.sh /home/USER/DOCUMENT_ROOT
#
# It asks GitHub which build is current and, when that differs from the one
# installed, downloads the built site, checks it and copies it into the given
# directory. It needs no key, token or password: the repository is public, and
# nothing on GitHub can reach the host.
#
# What it will and will not do:
#   - It installs only plain files with the extensions listed in ALLOWED, so a
#     compromised build cannot place a server-side script on the host.
#   - It installs .htaccess only when the directory has none. A later build
#     that ships a different .htaccess is reported in the log and left alone,
#     because that file can change how the server treats every other file.
#     Deleting the installed .htaccess accepts the new one on the next run.
#   - It removes only files that an earlier run of this script installed.
#   - It refuses a directory that already holds another site.
#
# State and a log live in ~/.foretaster-site.
set -eu
umask 022
LC_ALL=C
export LC_ALL

REPOSITORY=${FORETASTER_REPOSITORY:-timofeevilia/foretaster}
BRANCH=${FORETASTER_BRANCH:-site-dist}
VERSION_URL=${FORETASTER_VERSION_URL:-https://raw.githubusercontent.com/$REPOSITORY/$BRANCH/VERSION}
ARCHIVE_URL=${FORETASTER_ARCHIVE_URL:-https://codeload.github.com/$REPOSITORY/tar.gz/refs/heads/$BRANCH}
STATE=${FORETASTER_STATE:-$HOME/.foretaster-site}
ALLOWED='html|css|js|mjs|wasm|json|zip|whl|svg|png|ico|txt|xml'
NAME='[A-Za-z0-9_-][A-Za-z0-9._-]*'
MAX_DOWNLOAD_BYTES=100000000
MAX_UNPACKED_KB=300000

LOCK=$STATE/lock
WORK=$LOCK/work
LOCKED=

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$STATE/log"
}

fail() {
  log "error: $*"
  echo "foretaster-pull: $*" >&2
  exit 1
}

cleanup() {
  if [ -n "$LOCKED" ]; then rm -rf "$LOCK"; fi
}

fetch() {
  # fetch URL FILE
  case $1 in
    https://*) ;;
    http://127.0.0.1:*) [ "${FORETASTER_TEST_ALLOW_HTTP:-}" = 1 ] || fail "refusing a URL that is not HTTPS: $1" ;;
    *) fail "refusing a URL that is not HTTPS: $1" ;;
  esac
  if command -v curl > /dev/null 2>&1; then
    curl --fail --silent --show-error --location --max-time 600 \
      --max-filesize "$MAX_DOWNLOAD_BYTES" --output "$2" "$1" 2> "$WORK/fetch-error" \
      || fail "download failed: $1: $(tr '\n' ' ' < "$WORK/fetch-error")"
  elif command -v wget > /dev/null 2>&1; then
    wget --quiet --timeout=600 --output-document="$2" "$1" || fail "download failed: $1"
  else
    fail "neither curl nor wget is available"
  fi
}

is_commit() {
  case $1 in
    *[!0-9a-f]* | '') return 1 ;;
  esac
  [ ${#1} -eq 40 ]
}

[ $# -eq 1 ] || { echo "usage: pull.sh DOCUMENT_ROOT" >&2; exit 2; }
TARGET=${1%/}
case $TARGET in
  /*) ;;
  *) echo "foretaster-pull: the directory must be given as an absolute path" >&2; exit 2 ;;
esac
[ -d "$TARGET" ] || { echo "foretaster-pull: $TARGET is not a directory" >&2; exit 2; }

mkdir -p "$STATE"
for tool in tar sha256sum find sed grep sort comm cmp; do
  command -v "$tool" > /dev/null 2>&1 || fail "the host has no '$tool' command"
done

# One run at a time. A lock older than an hour is left over from a killed run.
if ! mkdir "$LOCK" 2> /dev/null; then
  [ -n "$(find "$LOCK" -maxdepth 0 -mmin +60 2> /dev/null)" ] || exit 0
  rm -rf "$LOCK"
  mkdir "$LOCK" 2> /dev/null || exit 0
fi
LOCKED=1
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir "$WORK"

if [ -f "$STATE/target" ]; then
  [ "$(cat "$STATE/target")" = "$TARGET" ] \
    || fail "$STATE belongs to $(cat "$STATE/target"); remove it to deploy to another directory"
else
  # First run for this directory: make sure it is not somebody else's site.
  [ ! -e "$TARGET/index.php" ] || fail "$TARGET already holds index.php; refusing to deploy there"
  if [ -e "$TARGET/index.html" ] && ! grep -q Foretaster "$TARGET/index.html"; then
    fail "$TARGET already holds another site; refusing to deploy there"
  fi
fi

# Is there anything new?
fetch "$VERSION_URL" "$WORK/wanted"
wanted=$(head -c 100 "$WORK/wanted" | tr -d '\r\n')
is_commit "$wanted" || fail "the version marker at $VERSION_URL is not a commit id"
current=$(cat "$STATE/version" 2> /dev/null || true)
if [ "$wanted" = "$current" ] && [ -f "$TARGET/index.html" ] && [ -e "$TARGET/.htaccess" ]; then
  exit 0
fi

# Download and unpack.
fetch "$ARCHIVE_URL" "$WORK/site.tar.gz"
TREE=$WORK/tree
mkdir "$TREE"
tar -xzf "$WORK/site.tar.gz" -C "$TREE" --strip-components=1 2> /dev/null \
  || fail "the archive could not be unpacked"
[ "$(du -sk "$TREE" | cut -f1)" -le "$MAX_UNPACKED_KB" ] || fail "the archive is larger than expected"

# Check it before anything touches the site.
[ -z "$(find "$TREE" ! -type f ! -type d | head -n 1)" ] \
  || fail "the archive holds something that is not a plain file or a directory"
[ -f "$TREE/VERSION" ] && [ -f "$TREE/SHA256SUMS" ] && [ -d "$TREE/site" ] \
  || fail "the archive does not have the expected layout"
version=$(head -c 100 "$TREE/VERSION" | tr -d '\r\n')
is_commit "$version" || fail "the archive's version marker is not a commit id"

[ -s "$TREE/SHA256SUMS" ] || fail "the checksum list is empty"
if grep -Evq '^[0-9a-f]{64}  \./[A-Za-z0-9._/-]+$' "$TREE/SHA256SUMS"; then
  fail "the checksum list has an unexpected line"
fi
sed 's/^[0-9a-f]*  \.\///' "$TREE/SHA256SUMS" | sort > "$WORK/paths"
[ -z "$(uniq -d "$WORK/paths")" ] || fail "the checksum list names a file twice"
bad=$(grep -Evx "\.htaccess|($NAME/)*$NAME\.($ALLOWED)" "$WORK/paths" | head -n 1 || true)
[ -z "$bad" ] || fail "the archive holds a file this script does not install: $bad"
grep -qx 'index\.html' "$WORK/paths" || fail "the archive holds no index.html"
(cd "$TREE/site" && find . -type f | sed 's/^\.\///' | sort) > "$WORK/actual"
cmp -s "$WORK/paths" "$WORK/actual" || fail "the files in the archive do not match its checksum list"
(cd "$TREE/site" && sha256sum -c "$TREE/SHA256SUMS" > /dev/null 2>&1) \
  || fail "a file in the archive does not match its checksum"

# Install. Each file is copied beside its destination and renamed into place,
# so a visitor never receives half a file.
printf '%s\n' "$TARGET" > "$STATE/target"
copied=0
while IFS= read -r line; do
  sum=${line%% *}
  path=${line#*  ./}
  [ "$path" != .htaccess ] || continue
  if [ -f "$TARGET/$path" ] && [ "$(sha256sum < "$TARGET/$path" | cut -c1-64)" = "$sum" ]; then
    continue
  fi
  mkdir -p "$(dirname "$TARGET/$path")"
  cp "$TREE/site/$path" "$TARGET/$path.new.$$"
  chmod 644 "$TARGET/$path.new.$$"
  mv -f "$TARGET/$path.new.$$" "$TARGET/$path"
  copied=$((copied + 1))
done < "$TREE/SHA256SUMS"

if [ -f "$TREE/site/.htaccess" ]; then
  if [ ! -e "$TARGET/.htaccess" ]; then
    cp "$TREE/site/.htaccess" "$TARGET/.htaccess.new.$$"
    chmod 644 "$TARGET/.htaccess.new.$$"
    mv -f "$TARGET/.htaccess.new.$$" "$TARGET/.htaccess"
    log "installed .htaccess"
  elif ! cmp -s "$TREE/site/.htaccess" "$TARGET/.htaccess"; then
    log "notice: build $version ships a different .htaccess; the installed one was kept." \
      "Delete it to accept the new one on the next run."
  fi
fi

# Remove what an earlier build installed and this one no longer has.
removed=0
if [ -f "$STATE/paths" ]; then
  comm -23 "$STATE/paths" "$WORK/paths" > "$WORK/stale"
  while IFS= read -r path; do
    [ "$path" != .htaccess ] || continue
    printf '%s\n' "$path" | grep -Eqx "($NAME/)*$NAME\.($ALLOWED)" || continue
    rm -f "$TARGET/$path"
    removed=$((removed + 1))
    directory=$(dirname "$path")
    while [ "$directory" != . ] && rmdir "$TARGET/$directory" 2> /dev/null; do
      directory=$(dirname "$directory")
    done
  done < "$WORK/stale"
fi

cp "$WORK/paths" "$STATE/paths"
printf '%s\n' "$version" > "$STATE/version"
log "deployed $version: $copied file(s) copied, $removed removed"
tail -n 200 "$STATE/log" > "$STATE/log.new" && mv -f "$STATE/log.new" "$STATE/log"

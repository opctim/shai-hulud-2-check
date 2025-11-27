#!/usr/bin/env bash
set -euo pipefail

# Author: @opctim https://github.com/opctim/shai-hulud-2-check
# More info:
# https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains
# https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack

# THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SCRIPT OR THE USE OR OTHER DEALINGS IN THE SCRIPT.

CSV_URL="https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"

[ $# -eq 1 ] || { echo "Usage: $0 DIRECTORY" >&2; exit 2; }
DIR="$1"
[ -d "$DIR" ] || { echo "Error: not a directory: $DIR" >&2; exit 2; }

for cmd in jq curl find awk yq; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd is required." >&2; exit 2; }
done

# Temp files
TMP_CSV="$(mktemp)"
TMP_VULN="$(mktemp)"
trap 'rm -f "$TMP_CSV" "$TMP_VULN"' EXIT

# Decide CSV source: env var or download
if [ -n "${SHAI_HULUD_CSV:-}" ]; then
  if [ ! -f "$SHAI_HULUD_CSV" ]; then
    echo "Error: SHAI_HULUD_CSV is set, but file does not exist: $SHAI_HULUD_CSV" >&2
    exit 2
  fi
  CSV_SOURCE="$SHAI_HULUD_CSV"
  printf "\nUsing vulnerability CSV from SHAI_HULUD_CSV: %s\n\n" "$CSV_SOURCE" >&2
else
  CSV_SOURCE="$TMP_CSV"
  printf "\nDownloading vulnerability CSV from Github... (%s)\n\n" "$CSV_URL" >&2
  curl -fsSL "$CSV_URL" -o "$CSV_SOURCE"
fi

# Normalize CSV -> lines: "package<TAB>version"
# Handles cases like: "@scope/pkg","= 1.2.3 || = 1.2.4"
awk -F, 'NR>1 {
  gsub(/"/,"");          # drop quotes
  pkg=$1; vers=$2;
  n=split(vers, parts, /\|\|/);
  for (i=1; i<=n; i++) {
    gsub(/^ *= */,"", parts[i]); # strip leading " = "
    gsub(/ *$/,"",  parts[i]);   # trim trailing spaces
    if (parts[i] != "") {
      print pkg "\t" parts[i];
    }
  }
}' "$CSV_SOURCE" > "$TMP_VULN"

# jq program reused for each npm package-lock.json
read -r -d '' JQ_PROG <<'EOF' || true
  if .packages then
    .packages
    | to_entries[]
    | select(.key | startswith("node_modules/"))
    | "\(.key | sub("^node_modules/";"")) \(.value.version)"
  else
    def walk_deps:
      to_entries[]
      | .key as $name
      | .value as $v
      | ($v.version // empty) as $ver
      | if $ver != "" then "\($name) \($ver)" else empty end,
        ( $v.dependencies // {} | walk_deps );
    .dependencies // {} | walk_deps
  end
EOF

FOUND_ANY=0

# Find and scan all package-lock.json files recursively
while IFS= read -r LOCKFILE; do
  echo "Scanning npm lockfile: $LOCKFILE" >&2

  INSTALLED_PACKAGES="$(jq -r "$JQ_PROG" "$LOCKFILE" 2>/dev/null || true)"

  while read -r NAME VER; do
    [ -z "$NAME" ] || [ -z "$VER" ] && continue

    if awk -v n="$NAME" -v v="$VER" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$TMP_VULN"; then
      FOUND_ANY=1
      echo "VULNERABLE: $NAME@$VER (in $LOCKFILE)"
    fi
  done <<< "$INSTALLED_PACKAGES"

done < <(find "$DIR" -type f -name "package-lock.json")

# Find and scan all pnpm-lock.yaml files recursively
while IFS= read -r PLOCK; do
  echo "Scanning pnpm lockfile: $PLOCK" >&2

  # Extract "name version" pairs from pnpm-lock.yaml
  # .packages keys look like:
  #   "/left-pad@1.3.0"
  #   "/@scope/name@2.0.0"
  #   "/foo@1.0.0(bar@2.0.0)"  (peer suffix)
  INSTALLED_PACKAGES="$(
    yq -r '.packages // {} | to_entries[].key' "$PLOCK" 2>/dev/null \
    | awk '
      {
        key = $0
        gsub(/^\/+/, "", key)        # remove leading "/"
        sub(/\([^)]*\)$/, "", key)   # drop "(...)" peer suffix if present

        # Split at last "@": before -> name, after -> version
        i = match(key, /@[^@]*$/)
        if (i > 0) {
          name = substr(key, 1, i-1)
          ver  = substr(key, i+1)
          if (name != "" && ver != "") {
            print name " " ver
          }
        }
      }
    '
  )"

  while read -r NAME VER; do
    [ -z "$NAME" ] || [ -z "$VER" ] && continue

    if awk -v n="$NAME" -v v="$VER" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$TMP_VULN"; then
      FOUND_ANY=1
      echo "VULNERABLE: $NAME@$VER (in $PLOCK)"
    fi
  done <<< "$INSTALLED_PACKAGES"

done < <(find "$DIR" -type f -name "pnpm-lock.yaml")

# Find and scan all yarn.lock files recursively
while IFS= read -r YLOCK; do
  echo "Scanning yarn lockfile: $YLOCK" >&2

    # Detect yarn.lock format
    if grep -q '^__metadata:' "$YLOCK"; then
    YARN_LOCK_FORMAT="v2"
    else
    YARN_LOCK_FORMAT="v1"
    fi

    echo "Detected Yarn lockfile format: $YARN_LOCK_FORMAT" >&2

    # YARN v1 (classic)
    if [ "$YARN_LOCK_FORMAT" = "v1" ]; then

    INSTALLED_PACKAGES="$(
        awk '
        /^[^[:space:]].*:$/ {
            # remove trailing colon + quotes
            line = $0
            gsub(/"/, "", line)
            sub(/:$/, "", line)

            # extract name before the last "@"
            i = match(line, /@[^@]*$/)
            if (i > 0) {
            name = substr(line, 1, i-1)
            } else {
            next
            }
            next
        }

        /version / {
            gsub(/"/, "", $0)
            ver = $2

            if (name != "" && ver != "")
            print name, ver
        }
        ' "$YLOCK"
    )"

    # YARN v2+ (Berry)
    else

    # Only the version from "version" is taken,

    INSTALLED_PACKAGES="$(
        awk '
        /^[^[:space:]].*:$/ {

            header = $0
            gsub(/"/, "", header)
            sub(/:$/, "", header)

            delete pkgs
            pkg_count = 0

            n = split(header, parts, /, +/)

            for (i = 1; i <= n; i++) {
            p = parts[i]

            gsub(/@npm:/, "@", p)
            gsub(/@patch:/, "@", p)
            gsub(/@workspace:/, "@", p)
            gsub(/@link:/, "@", p)
            gsub(/@portal:/, "@", p)
            gsub(/@file:/, "@", p)
            gsub(/@virtual:/, "@", p)

            idx = match(p, /@[^@]*$/)
            if (idx > 0) {
                name = substr(p, 1, idx-1)

                pkgs[++pkg_count] = name
            }
            }

            next
        }

        /^[[:space:]]+version:/ {

            ver = $2
            gsub(/"/, "", ver)

            if (ver != "" && pkg_count > 0) {
            for (i = 1; i <= pkg_count; i++) {
                print pkgs[i], ver
            }
            }
        }

        ' "$YLOCK"
    )"

    fi


  if [ -z "$INSTALLED_PACKAGES" ]; then
    echo "Warning! Could not find any packages in $YLOCK - NOT Tested!"
  fi

  while read -r NAME VER; do
    [ -z "$NAME" ] || [ -z "$VER" ] && continue

    if awk -v n="$NAME" -v v="$VER" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$TMP_VULN"; then
      FOUND_ANY=1
      echo "VULNERABLE: $NAME@$VER (in $YLOCK)"
    fi

    # Warn about using another version of vulnerable package 
    if ! awk -v n="$NAME" -v v="$VER" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
    ' "$TMP_VULN" && \
    awk -v n="$NAME" '
        $1 == n { print "  ↳ known vulnerable version:", $2; found=1 }
        END { exit found ? 0 : 1 }
    ' "$TMP_VULN"; then

    echo "INFO: $NAME@$VER is used, but vulnerable versions exist (see above)"
    fi

  done <<< "$INSTALLED_PACKAGES"

done < <(find "$DIR" -type f -name "yarn.lock")

if (( FOUND_ANY )); then
  printf "\n[EMERGENCY] Vulnerable packages found.\n" >&2
  exit 1
else
  printf "\n[OK] No vulnerable packages detected.\n" >&2
  exit 0
fi

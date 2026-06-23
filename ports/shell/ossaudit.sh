#!/bin/sh
# ossaudit (POSIX shell port) — OSS license-compliance auditor.
#
# Mirrors the reference Python CLI's `audit` command using only POSIX sh + awk:
# normalise each SPDX-ish license id, classify copyleft strength, and decide
# whether each dependency is permitted under a distribution-policy preset.
# No network. Exit code 2 on policy violations (matches the Python tool).
#
#   sh ossaudit.sh audit deps.json --policy proprietary
#   sh ossaudit.sh --version
#
# The manifest parser is intentionally simple: it extracts the {name, version,
# license} triples from the JSON via awk (one dependency object per record).
# Defensive / authorized-use only.
set -eu

TOOL_NAME="ossaudit"
TOOL_VERSION="0.3.0-sh"

usage() {
    echo "usage: ossaudit audit <manifest.json> [--policy P]" >&2
    exit 1
}

# normalize_license <raw>  -> canonical SPDX id on stdout
normalize_license() {
    raw=$(printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -z "$raw" ] && { echo "NOASSERTION"; return; }
    # SPDX OR: pick the least-severe operand; AND: pick the most-severe.
    case " $(printf '%s' "$raw" | tr 'a-z' 'A-Z') " in
        *" OR "*)
            best="NOASSERTION"; best_sev=99
            old_ifs=$IFS; IFS='|'
            for part in $(printf '%s' "$raw" | sed 's/ [Oo][Rr] /|/g'); do
                c=$(normalize_license "$part"); s=$(severity_of "$(classify "$c")")
                [ "$s" -lt "$best_sev" ] && { best=$c; best_sev=$s; }
            done
            IFS=$old_ifs; echo "$best"; return ;;
        *" AND "*)
            worst="NOASSERTION"; worst_sev=-1
            old_ifs=$IFS; IFS='|'
            for part in $(printf '%s' "$raw" | sed 's/ [Aa][Nn][Dd] /|/g'); do
                c=$(normalize_license "$part"); s=$(severity_of "$(classify "$c")")
                [ "$s" -gt "$worst_sev" ] && { worst=$c; worst_sev=$s; }
            done
            IFS=$old_ifs; echo "$worst"; return ;;
    esac
    # strip a single fully-enclosing paren pair
    raw=$(printf '%s' "$raw" | sed 's/^(\(.*\))$/\1/; s/^[[:space:]]*//; s/[[:space:]]*$//')
    key=$(printf '%s' "$raw" | tr 'a-z' 'A-Z' | tr -cd 'A-Z0-9.+' | sed 's/\.*$//')
    # direct canonical (case-insensitive) match
    for canon in MIT BSD-2-Clause BSD-3-Clause Apache-2.0 ISC Zlib BSL-1.0 CC-BY-4.0 \
        Unlicense CC0-1.0 0BSD LGPL-2.1-only LGPL-3.0-only MPL-2.0 EPL-2.0 CC-BY-SA-4.0 \
        GPL-2.0-only GPL-2.0-or-later GPL-3.0-only GPL-3.0-or-later \
        AGPL-3.0-only AGPL-3.0-or-later SSPL-1.0 BUSL-1.1 Elastic-2.0 Commercial Proprietary; do
        if [ "$(printf '%s' "$raw" | tr 'a-z' 'A-Z')" = "$(printf '%s' "$canon" | tr 'a-z' 'A-Z')" ]; then
            echo "$canon"; return
        fi
    done
    case "$key" in
        APACHE|APACHE2|APACHE2.0) echo "Apache-2.0" ;;
        BSD|BSD3|NEWBSD) echo "BSD-3-Clause" ;;
        BSD2) echo "BSD-2-Clause" ;;
        MITLICENSE|THEMITLICENSE|EXPAT) echo "MIT" ;;
        GPL) echo "GPL-3.0-or-later" ;;
        GPL3|GPLV3) echo "GPL-3.0-only" ;;
        GPL2|GPLV2) echo "GPL-2.0-only" ;;
        LGPL|LGPLV3) echo "LGPL-3.0-only" ;;
        LGPL2) echo "LGPL-2.1-only" ;;
        AGPL) echo "AGPL-3.0-or-later" ;;
        AGPL3|AGPLV3) echo "AGPL-3.0-only" ;;
        MPL|MOZILLA) echo "MPL-2.0" ;;
        CC0) echo "CC0-1.0" ;;
        *) echo "NOASSERTION" ;;
    esac
}

# classify <canonical> -> category
classify() {
    case "$1" in
        MIT|BSD-2-Clause|BSD-3-Clause|Apache-2.0|ISC|Zlib|BSL-1.0|CC-BY-4.0) echo permissive ;;
        Unlicense|CC0-1.0|0BSD) echo public-domain ;;
        LGPL-2.1-only|LGPL-3.0-only|MPL-2.0|EPL-2.0|CC-BY-SA-4.0) echo weak-copyleft ;;
        GPL-2.0-only|GPL-2.0-or-later|GPL-3.0-only|GPL-3.0-or-later) echo strong-copyleft ;;
        AGPL-3.0-only|AGPL-3.0-or-later|SSPL-1.0) echo network-copyleft ;;
        BUSL-1.1|Elastic-2.0|Commercial|Proprietary) echo proprietary ;;
        *) echo unknown ;;
    esac
}

severity_of() {
    case "$1" in
        network-copyleft) echo 5 ;;
        strong-copyleft|proprietary) echo 4 ;;
        unknown) echo 3 ;;
        weak-copyleft) echo 2 ;;
        permissive) echo 1 ;;
        public-domain) echo 0 ;;
        *) echo 3 ;;
    esac
}

# allowed <policy> <category> -> exit 0 if permitted
allowed() {
    _pol=$1; _cat=$2
    case "$_pol" in
        permissive-only) set -- permissive public-domain ;;
        gpl-project) set -- permissive public-domain weak-copyleft strong-copyleft ;;
        permissive-audit) set -- permissive public-domain weak-copyleft strong-copyleft network-copyleft proprietary unknown ;;
        *) set -- permissive public-domain weak-copyleft ;;  # proprietary/distribute-binary/default
    esac
    for a in "$@"; do [ "$a" = "$_cat" ] && return 0; done
    return 1
}

main() {
    [ "${1:-}" = "--version" ] && { echo "$TOOL_NAME $TOOL_VERSION"; return 0; }
    [ $# -lt 2 ] || [ "$1" != "audit" ] && usage
    manifest=$2; shift 2
    policy=proprietary
    while [ $# -gt 0 ]; do
        case "$1" in
            --policy) policy=$2; shift 2 ;;
            --format) shift 2 ;;   # only table output in the shell port
            *) shift ;;
        esac
    done
    [ -f "$manifest" ] || { echo "$TOOL_NAME: error: file not found: $manifest" >&2; return 1; }

    # Extract one "name|version|license" record per dependency object via awk.
    records=$(awk '
        BEGIN { RS="{"; FS="\n" }
        /"name"/ {
            name=""; ver="0.0.0"; lic=""
            if (match($0, /"name"[ \t]*:[ \t]*"[^"]*"/))    { s=substr($0,RSTART,RLENGTH); gsub(/.*:[ \t]*"/,"",s); gsub(/"$/,"",s); name=s }
            if (match($0, /"version"[ \t]*:[ \t]*"[^"]*"/)) { s=substr($0,RSTART,RLENGTH); gsub(/.*:[ \t]*"/,"",s); gsub(/"$/,"",s); ver=s }
            if (match($0, /"license"[ \t]*:[ \t]*"[^"]*"/)) { s=substr($0,RSTART,RLENGTH); gsub(/.*:[ \t]*"/,"",s); gsub(/"$/,"",s); lic=s }
            if (name != "") printf "%s\037%s\037%s\n", name, ver, lic
        }
    ' "$manifest")

    total=0; violations=0
    out=""
    OLD_IFS=$IFS
    IFS='
'
    for rec in $records; do
        name=$(printf '%s' "$rec" | cut -d"$(printf '\037')" -f1)
        ver=$(printf '%s' "$rec" | cut -d"$(printf '\037')" -f2)
        lic=$(printf '%s' "$rec" | cut -d"$(printf '\037')" -f3)
        total=$((total + 1))
        spdx=$(normalize_license "$lic")
        cat=$(classify "$spdx")
        sev=$(severity_of "$cat")
        if allowed "$policy" "$cat"; then status="ok"; else status="VIOLATION"; violations=$((violations + 1)); fi
        out="$out$sev|$status|$name|$ver|$spdx
"
    done
    IFS=$OLD_IFS

    echo "Policy: $policy   Deps: $total   Violations: $violations"
    echo "----------------------------------------------------------------------"
    printf '%s' "$out" | sort -t'|' -k1,1nr -k3,3 | while IFS='|' read -r sev status name ver spdx; do
        [ -z "$name" ] && continue
        printf '%-10s %-2s %-24s %-12s %s\n' "$status" "$sev" "$name" "$ver" "$spdx"
    done
    echo "----------------------------------------------------------------------"
    if [ "$violations" -eq 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
    [ "$violations" -eq 0 ] || return 2
}

main "$@"

#!/usr/bin/env bash
# php2shell-check.sh — local PHP version check for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619).
#
# Runs entirely OFFLINE: it only reads the version string of the PHP binaries
# installed on this host and compares them to the patched releases. It does NOT
# exploit anything and sends nothing over the network. Please review this script
# before running it.  Source: https://php2shell.ai
#
# Usage:   bash php2shell-check.sh
# Exit:    0 = all checked installs fixed · 1 = none found / review needed · 2 = vulnerable
set -u

# Fixed (patched) patch-level per supported branch. Safe at this level or higher.
fixed_patch() {
  case "$1" in
    8.5) echo 12 ;;
    8.4) echo 27 ;;
    8.3) echo 36 ;;
    8.2) echo 35 ;;
    *)   echo "" ;;
  esac
}

# Colours only when stdout is a terminal.
if [ -t 1 ]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else
  R=''; G=''; Y=''; B=''; N=''
fi

printf '%sPHP2Shell — local version check%s\n' "$B" "$N"
printf 'CVE-2026-109618 / CVE-2026-109619 · fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35\n'
printf 'Offline check — nothing is sent anywhere. Review this script before trusting it.\n\n'

tmp="$(mktemp 2>/dev/null || printf '/tmp/.p2s.%s' "$$")"
trap 'rm -f "$tmp"' EXIT

# Candidate PHP binaries: ones on PATH (plain + versioned names) and the common
# multi-PHP locations used by cPanel/EasyApache, Plesk, Remi and source builds.
{
  for name in php php-fpm php-cgi \
              php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 \
              php7.4 php7.3 php7.2 php7.1 php7.0 php5.6; do
    command -v "$name" 2>/dev/null
  done
  for g in /opt/cpanel/ea-php*/root/usr/bin/php \
           /opt/plesk/php/*/bin/php \
           /usr/local/php*/bin/php \
           /opt/remi/php*/root/usr/bin/php; do
    [ -x "$g" ] && printf '%s\n' "$g"
  done
} | while IFS= read -r b; do
      readlink -f "$b" 2>/dev/null || printf '%s\n' "$b"
    done | awk 'NF && !seen[$0]++' > "$tmp"

vuln=0; unknown=0; checked=0
while IFS= read -r bin; do
  [ -n "$bin" ] || continue
  ver="$("$bin" -v 2>/dev/null | sed -n 's/^PHP \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -1)"
  [ -n "$ver" ] || continue
  checked=$((checked + 1))
  maj="${ver%%.*}"; rest="${ver#*.}"; min="${rest%%.*}"; pat="${rest#*.}"; pat="${pat%%[!0-9]*}"
  branch="$maj.$min"
  fix="$(fixed_patch "$branch")"
  if [ -n "$fix" ]; then
    if [ "$pat" -lt "$fix" ]; then
      printf '  %sVULNERABLE%s  %-42s PHP %s  (upgrade to %s.%s+)\n' "$R" "$N" "$bin" "$ver" "$branch" "$fix"
      vuln=$((vuln + 1))
    else
      printf '  %sOK%s          %-42s PHP %s\n' "$G" "$N" "$bin" "$ver"
    fi
  elif [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -lt 2 ]; }; then
    printf '  %sEOL%s         %-42s PHP %s  (end-of-life — move to 8.2+)\n' "$Y" "$N" "$bin" "$ver"
    vuln=$((vuln + 1))
  else
    printf '  %s?%s           %-42s PHP %s  (branch not listed — verify at php.net)\n' "$Y" "$N" "$bin" "$ver"
    unknown=$((unknown + 1))
  fi
done < "$tmp"

printf '\n'
if [ "$checked" -eq 0 ]; then
  printf '%sNo PHP binary found.%s If PHP runs elsewhere (container, remote FPM), run this there.\n' "$Y" "$N"
  exit 1
fi
if [ "$vuln" -gt 0 ]; then
  printf '%s%sResult: VULNERABLE%s — %d PHP install(s) need updating. Upgrade and restart php-fpm / the web server.\n' "$R" "$B" "$N" "$vuln"
  printf 'Interim mitigation (CVE-2026-109619): set session.upload_progress.enabled=0 and restart workers.\n'
  exit 2
fi
if [ "$unknown" -gt 0 ]; then
  printf '%sResult: review needed%s — verify the unlisted branch(es) against the official php.net advisory.\n' "$Y" "$N"
  exit 1
fi
printf '%s%sResult: all checked PHP installs are on a fixed version.%s Keep CLI, cron and FPM in sync.\n' "$G" "$B" "$N"
exit 0

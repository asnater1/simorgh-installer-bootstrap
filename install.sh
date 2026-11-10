#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/bin LC_ALL=C DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
[ "$EUID" = 0 ] && [ -t 0 ] && [ "$(uname -m)" = x86_64 ] && . /etc/os-release && [ "$ID:$VERSION_ID" = ubuntu:24.04 ] || { echo 'Use interactive root on Ubuntu 24.04 amd64.' >&2; exit 2; }
umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

install_packages() {
    local plan
    plan=$(apt-get -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false -s --no-remove --no-install-recommends install "$@")
    if grep -Eq '^(Remv |Purg |Inst [^ ]+ \[)' <<<"$plan"; then
        echo 'Bootstrap packages would remove or upgrade installed packages.' >&2
        return 2
    fi
    apt-get -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false -y --no-remove --no-install-recommends install "$@"
}

apt-get -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false -o APT::Update::Error-Mode=any update
install_packages curl gh python3.12 nftables fail2ban
stage_tool() {
    local url=$1 hash=$2 member=$3 path=$4 binary_hash=$5
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -f "$path" && ! -L "$path" ]] || return 2
        printf '%s  %s\n' "$binary_hash" "$path" | sha256sum -c --status
        return
    fi
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 120 --max-filesize 67108864 "$url" -o "$work/tool.tar.gz"
    printf '%s  %s\n' "$hash" "$work/tool.tar.gz" | sha256sum -c --status
    tar -xOf "$work/tool.tar.gz" "$member" > "$work/tool"
    printf '%s  %s\n' "$binary_hash" "$work/tool" | sha256sum -c --status
    install -D -m 0755 "$work/tool" "$path"
}
stage_tool https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-linux.tar.gz \
  9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73 \
  minisign-linux/x86_64/minisign /usr/bin/minisign \
  2c74dffcc1c9a5ee55957c60971998ace2b89f22585631594ec2152c588af8db
stage_tool https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz \
  699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968 \
  sing-box-1.14.4-linux-amd64/sing-box /usr/local/libexec/simorgh-sing-box \
  1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a
unset GH_TOKEN GITHUB_TOKEN
export GH_CONFIG_DIR="$work/gh"
export GH_PROMPT_DISABLED=1
GH_TOKEN=$(/usr/bin/python3.12 -I -B - Iv23liELy89DlQgZGL4W <<'SIMORGH_DEVICE_FLOW'
"""Acquire an expiring GitHub App user token for the launcher."""

import json
import re
import sys
from time import monotonic, sleep
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def post(path, fields):
    request = Request("https://github.com/login/" + path, data=urlencode(fields).encode(),
                      headers={"Accept": "application/json"})
    with build_opener(NoRedirect()).open(request, timeout=15) as response:
        return json.loads(response.read(16384))


def authorize(client_id):
    device = post("device/code", {"client_id": client_id})
    user_code = device["user_code"]
    if not re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4}", user_code):
        raise ValueError("Unexpected device code")
    interval = max(1, int(device["interval"]))
    deadline = monotonic() + min(1800, int(device["expires_in"]))
    print(f"Authorize Simorgh Installer at https://github.com/login/device with code {user_code}",
          file=sys.stderr, flush=True)
    fields = {"client_id": client_id, "device_code": device["device_code"],
              "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}
    while monotonic() + interval < deadline:
        sleep(interval)
        result = post("oauth/access_token", fields)
        token = result.get("access_token")
        if token and re.fullmatch(r"ghu_[A-Za-z0-9]+", token) and int(result["expires_in"]) > 0:
            return token
        error = result.get("error")
        if error == "slow_down":
            interval = max(interval + 5, int(result.get("interval", 0)))
        elif error != "authorization_pending":
            raise ValueError("Authorization was denied or refused")
    raise ValueError("Authorization expired")


if __name__ == "__main__":
    try:
        print(authorize(sys.argv[1]))
    except (OSError, ValueError, KeyError, TypeError):
        print("GitHub authorization did not complete. Verify access and retry the installer.", file=sys.stderr)
        raise SystemExit(2)
SIMORGH_DEVICE_FLOW
)
export GH_TOKEN
gh release download v0.0.913 -R asnater1/Simorgh -p github_bootstrap.py -D "$work"
printf '%s  %s\n' 7ed9ed274ca05d543540fc775794dbbb9d5490c7a9934974f09c1b8ce6d82f8f "$work/github_bootstrap.py" | sha256sum -c --status
/usr/bin/python3.12 -I -B "$work/github_bootstrap.py" --tag v0.0.913 --source 2a5e985bfc6649d92822bc2d2b3bd99c328ef16e --operator-sha aeca5944de599d9015081e42a0a6a2b49ba7a406d75b5fffd755723739aef54e --key-sha eecb7936d5e92425d0a7afb5f41c0ddf467eecd1e3dc7ac25f63d02f76ebae20 --manifest-sha 8b839e64cfab1acbd40db971ac5049bd9c405868755ad9f20cffcbec8c9f450a

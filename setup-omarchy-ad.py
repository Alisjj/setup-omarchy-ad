#!/usr/bin/env python3
"""Join an Omarchy laptop to AD. Read-only unless --apply is specified.

Run on the OTHER laptop, in a local administrator's terminal:
    python3 setup-omarchy-ad.py
    sudo python3 setup-omarchy-ad.py --apply

Passwords are requested by adcli itself, never accepted as script arguments.
No AD user is created, no sudo rights are granted, and autologin is untouched.
An AD user's separate home still needs its own Omarchy desktop configuration.
"""

import argparse
import configparser
import ctypes
import datetime
import grp
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass


DEFAULT_DOMAIN = "vega.local"
DEFAULT_DNS = "10.0.10.1,10.0.10.2,10.1.10.1,10.1.10.2"
PACKAGES = ("realmd", "sssd", "adcli", "krb5", "samba", "bind")
MARKER = "# setup-omarchy-ad.py: managed SSSD integration"
PAM_FILE = Path("/etc/pam.d/system-auth")
NSS_FILE = Path("/etc/nsswitch.conf")
SSSD_FILE = Path("/etc/sssd/sssd.conf")
DNS_PROPERTIES = (
    "ipv4.dns", "ipv4.dns-search", "ipv4.ignore-auto-dns",
    "ipv6.dns", "ipv6.ignore-auto-dns",
)
PAM_RULE = re.compile(
    r"^\s*(-?(?:auth|account|password|session))\s+"
    r"(\[[^\]]+\]|\S+)\s+(\S+)(?:\s+(.*?))?\s*$"
)


class SetupError(Exception):
    pass


class Runner:
    def __init__(self):
        self.env = os.environ.copy()
        self.env.update({
            "LC_ALL": "C",
            "PATH": "/usr/share/omarchy/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin",
            "OMARCHY_PATH": "/usr/share/omarchy",
            "KRB5CCNAME": "MEMORY:omarchy-ad-setup",
        })
        for key in ("KRB5_CONFIG", "KRB5_KTNAME", "KRB5_CLIENT_KTNAME", "KRB5_TRACE"):
            self.env.pop(key, None)

    def has(self, command):
        return shutil.which(command, path=self.env["PATH"]) is not None

    def run(self, *args, check=True, interactive=False, timeout=30):
        try:
            result = subprocess.run(
                list(args), env=self.env, text=True,
                capture_output=not interactive, timeout=timeout,
            )
        except FileNotFoundError as error:
            raise SetupError(f"Required command not found: {args[0]}") from error
        except subprocess.TimeoutExpired as error:
            raise SetupError(f"Command timed out: {args[0]}") from error
        if check and result.returncode:
            detail = "" if interactive else (result.stderr or result.stdout).strip()
            raise SetupError(f"{args[0]} failed (exit {result.returncode}). {detail}")
        return result

    def text(self, *args, **kwargs):
        return self.run(*args, **kwargs).stdout.strip()


@dataclass(frozen=True)
class Connection:
    uuid: str
    name: str
    device: str


def active_connections(runner):
    output = runner.text(
        "nmcli", "--terse", "--escape", "no", "--fields", "UUID,TYPE,DEVICE",
        "connection", "show", "--active",
    )
    connections = []
    for line in output.splitlines():
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        uuid, kind, device = fields
        if kind not in {"802-11-wireless", "802-3-ethernet"} or device in {"", "--"}:
            continue
        name = runner.text("nmcli", "--escape", "no", "-g", "connection.id", "connection", "show", "uuid", uuid)
        connections.append(Connection(uuid, name, device))
    return connections


def choose_connection(connections, requested=None, routes=()):
    if requested:
        matches = [c for c in connections if requested in {c.uuid, c.name, c.device}]
    elif len(connections) == 1:
        matches = connections
    else:
        ranked = [(int(r.get("metric", 0)), r.get("dev")) for r in routes
                  if any(c.device == r.get("dev") for c in connections)]
        best = min((metric for metric, _ in ranked), default=None)
        devices = {device for metric, device in ranked if metric == best}
        matches = [c for c in connections if c.device in devices]
    if len(matches) != 1:
        choices = "\n".join(f"  {c.name}: {c.device} ({c.uuid})" for c in connections)
        raise SetupError(
            "Cannot unambiguously select an active Wi-Fi/Ethernet connection. "
            "Connect to the office network, or pass --connection UUID.\n" + choices
        )
    return matches[0]


def discover_connection(runner, requested):
    routes = []
    if runner.has("ip"):
        for family in ("-4", "-6"):
            result = runner.run("ip", "-j", family, "route", "show", "default", check=False)
            if result.returncode == 0:
                routes = json.loads(result.stdout or "[]")
                if routes:
                    break
    return choose_connection(active_connections(runner), requested, routes)


def validate_domain(value):
    value = value.rstrip(".").lower()
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels
    ):
        raise SetupError("Use a DNS domain such as vega.local.")
    return value


def validate_hostname(value):
    value = value.lower()
    if (not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?", value)
            or value in {"localhost", "localhostlocal"} or value.isdigit()):
        raise SetupError("Use a unique 1–15 character hostname: letters, digits, hyphens; no dots.")
    return value


def parse_dns(value):
    try:
        servers = list(dict.fromkeys(str(ipaddress.IPv4Address(x.strip())) for x in value.split(",")))
    except ipaddress.AddressValueError as error:
        raise SetupError("--dns must be a comma-separated list of AD IPv4 DNS servers.") from error
    return servers


def pam_rules(text):
    rules = []
    for index, line in enumerate(text.splitlines()):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = PAM_RULE.fullmatch(line)
        if not match:
            raise SetupError("Unrecognized system-auth syntax; refusing automatic PAM edits.")
        facility, control, module, options = match.groups()
        rules.append((index, facility.lstrip("-"), " ".join(control.split()), module, options or ""))
    return rules


def build_pam(text, legacy_helper=None):
    """Preserve stock Arch controls/options and reject unfamiliar auth stacks."""
    lines = text.splitlines()
    managed = MARKER in lines
    if managed:
        if lines.count(MARKER) != 1:
            raise SetupError("Duplicate PAM management markers; refusing automatic edits.")
        lines = [line for line in lines if line != MARKER]
        base_counts = {"auth": (3, 2), "account": (3, 1), "password": (2, 1)}
        expected_managed = {
            ("auth", "[success=2 default=ignore]", "pam_sss.so", "forward_pass"),
            ("account", "[success=1 default=ignore]", "pam_localuser.so", ""),
            ("account", "[success=1 default=bad]", "pam_sss.so", ""),
            ("password", "[success=1 default=ignore]", "pam_sss.so", ""),
            ("session", "optional", "pam_sss.so", ""),
        }
        found_managed = []
        cleaned = []
        for line in lines:
            match = PAM_RULE.fullmatch(line)
            if match:
                facility, control, module, options = match.groups()
                kind = facility.lstrip("-")
                if module == "pam_sss.so" or (kind == "account" and module == "pam_localuser.so"):
                    rule = (kind, " ".join(control.split()), module, options or "")
                    if rule not in expected_managed or rule in found_managed:
                        raise SetupError("Managed SSSD PAM rules were customized; refusing to overwrite them.")
                    found_managed.append(rule)
                    continue
                if module == "pam_systemd_home.so" and kind in base_counts:
                    old, new = base_counts[kind]
                    if " ".join(control.split()) != f"[success={old} default=ignore]":
                        raise SetupError("Managed PAM jump controls were modified; refusing to overwrite them.")
                    line = line.replace(control, f"[success={new} default=ignore]", 1)
            cleaned.append(line)
        if set(found_managed) != expected_managed:
            raise SetupError("Managed SSSD PAM rules are incomplete; have the file reviewed first.")
        lines = cleaned
    if any(re.search(r"\binclude\s+sssd-arch\s*$", line) for line in lines):
        expected = [
            ("auth", "sufficient", "pam_sss.so", "forward_pass"),
            ("password", "sufficient", "pam_sss.so", "use_authtok"),
            ("session", "required", "pam_mkhomedir.so", "skel=/etc/skel/ umask=0077"),
            ("session", "optional", "pam_sss.so", ""),
        ]
        actual = [r[1:] for r in pam_rules(legacy_helper or "")]
        if actual != expected:
            raise SetupError("Customized sssd-arch PAM helper found; refusing to replace it.")
        lines = [line for line in lines if not re.fullmatch(
            r"\s*(auth|password|session)\s+include\s+sssd-arch\s*", line
        )]
    rules = pam_rules("\n".join(lines))
    expected = {
        "auth": [("required", "pam_faillock.so"),
                 ("[success=2 default=ignore]", "pam_systemd_home.so"),
                 ("[success=1 default=bad]", "pam_unix.so"),
                 ("[default=die]", "pam_faillock.so"),
                 ("optional", "pam_permit.so"), ("required", "pam_env.so"),
                 ("required", "pam_faillock.so")],
        "account": [("[success=1 default=ignore]", "pam_systemd_home.so"),
                    ("required", "pam_unix.so"), ("optional", "pam_permit.so"),
                    ("required", "pam_time.so")],
        "password": [("[success=1 default=ignore]", "pam_systemd_home.so"),
                     ("required", "pam_unix.so"), ("optional", "pam_permit.so")],
        "session": [("optional", "pam_systemd_home.so"), ("required", "pam_limits.so"),
                    ("required", "pam_unix.so"), ("optional", "pam_permit.so")],
    }
    for kind, wanted in expected.items():
        actual = [(control, module) for _, facility, control, module, _ in rules
                  if facility == kind and module != "pam_mkhomedir.so"]
        if actual != wanted:
            raise SetupError(
                f"Unfamiliar {kind} stack in system-auth. No automatic PAM rewrite is safe; "
                "have it reviewed instead."
            )
    home_rules = [r for r in rules if r[3] == "pam_mkhomedir.so"]
    if len(home_rules) > 1 or any(r[1] != "session" for r in home_rules):
        raise SetupError("Unexpected pam_mkhomedir rules; refusing automatic PAM edits.")
    additions = {
        "auth": (3, ["auth       [success=2 default=ignore]  pam_sss.so forward_pass"]),
        "account": (3, ["account    [success=1 default=ignore]  pam_localuser.so",
                        "account    [success=1 default=bad]     pam_sss.so"]),
        "password": (2, ["password   [success=1 default=ignore]  pam_sss.so"]),
    }
    output = []
    for line in lines:
        match = PAM_RULE.fullmatch(line)
        if match and match.group(3) == "pam_systemd_home.so":
            facility = match.group(1).lstrip("-")
            if facility in additions:
                count, extra = additions[facility]
                line = line.replace(match.group(2), f"[success={count} default=ignore]", 1)
                output.extend([line, *extra])
                continue
        output.append(line)
    output.insert(1 if output and output[0].startswith("#%PAM") else 0, MARKER)
    if not home_rules:
        output.append("session    required                    pam_mkhomedir.so skel=/etc/skel/ umask=0077")
    output.append("session    optional                    pam_sss.so")
    return "\n".join(output) + "\n"


def build_nss(text):
    seen = set()
    output = []
    for line in text.splitlines():
        body, separator, comment = line.partition("#")
        match = re.match(r"^\s*(passwd|group)\s*:\s*(.*)$", body)
        if match:
            key, providers = match.groups()
            if key in seen:
                raise SetupError(f"Duplicate {key} entries in nsswitch.conf.")
            seen.add(key)
            if {"ldap", "winbind"}.intersection(providers.split()):
                raise SetupError("Another NSS directory provider is configured; refusing to mix providers.")
            if "sss" not in providers.split():
                body = body.rstrip() + " sss" + (" " if separator else "")
            line = body + separator + comment
        output.append(line)
    if seen != {"passwd", "group"}:
        raise SetupError("Missing passwd/group entries in nsswitch.conf.")
    return "\n".join(output) + "\n"


def build_sssd(existing, domain, hostname):
    if existing:
        config = configparser.ConfigParser(interpolation=None, strict=True)
        try:
            config.read_string(existing)
            domains = [x.strip().lower() for x in config.get("sssd", "domains").split(",")]
            section = next(s for s in config.sections() if s.lower() == "domain/" + domain)
            if (domains != [domain] or config.get(section, "id_provider") != "ad"
                    or config.get(section, "access_provider", fallback="") != "ad"
                    or config.get(section, "ad_gpo_access_control", fallback="enforcing").lower() != "enforcing"):
                raise ValueError
        except (configparser.Error, StopIteration, ValueError) as error:
            raise SetupError("Existing SSSD configuration is not a single-domain, policy-enforcing AD setup; refusing to replace it.") from error
        section = ""
        output = []
        for line in existing.splitlines():
            match = re.match(r"\s*\[([^]]+)\]", line)
            if match:
                section = match.group(1).lower()
            if section == "sssd" and re.match(r"\s*config_file_version\s*=", line):
                continue
            output.append(line)
        return "\n".join(output) + "\n"
    return f"""# Created by setup-omarchy-ad.py
[sssd]
domains = {domain}
services = nss, pam

[domain/{domain}]
id_provider = ad
access_provider = ad
ad_domain = {domain}
ad_hostname = {hostname}.{domain}
krb5_realm = {domain.upper()}
realmd_tags = manages-system joined-with-adcli
cache_credentials = true
krb5_store_password_if_offline = true
use_fully_qualified_names = true
ldap_id_mapping = true
fallback_homedir = /home/%u@%d
default_shell = /bin/bash
ad_gpo_access_control = enforcing
"""


def atomic_write(path, text, owner=None, mode=None):
    path = Path(path)
    if path.is_symlink():
        raise SetupError(f"Refusing to replace a symlink: {path}")
    previous = path.stat() if path.exists() else None
    descriptor, temporary = tempfile.mkstemp(prefix=".omarchy-ad-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), mode if mode is not None else
                      stat.S_IMODE(previous.st_mode) if previous else 0o600)
            if owner is not None or previous is not None:
                os.fchown(handle.fileno(), *(owner if owner else (previous.st_uid, previous.st_gid)))
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def pam_account_status(user, service="system-auth"):
    """Check account authorization only; never authenticate or open a session."""
    callback_type = ctypes.CFUNCTYPE(
        ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    )

    class Conversation(ctypes.Structure):
        _fields_ = [("conv", callback_type), ("appdata_ptr", ctypes.c_void_p)]

    @callback_type
    def refuse_conversation(_count, _messages, _responses, _data):
        return 19  # PAM_CONV_ERR; account-only checks must not ask for a password.

    library = ctypes.CDLL("libpam.so.0")
    library.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.POINTER(Conversation), ctypes.POINTER(ctypes.c_void_p)]
    library.pam_start.restype = ctypes.c_int
    library.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.pam_acct_mgmt.restype = ctypes.c_int
    library.pam_strerror.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.pam_strerror.restype = ctypes.c_char_p
    library.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.pam_end.restype = ctypes.c_int
    conversation = Conversation(refuse_conversation, None)
    handle = ctypes.c_void_p()
    status = library.pam_start(service.encode(), user.encode(), ctypes.byref(conversation), ctypes.byref(handle))
    if status:
        raise SetupError(f"Cannot start PAM account check for {user} (code {status}).")
    try:
        status = library.pam_acct_mgmt(handle, 0)
        message = library.pam_strerror(handle, status).decode(errors="replace")
        return status, message
    finally:
        library.pam_end(handle, status)


def responsive_dns(runner, servers, domain):
    working = []
    for server in servers:
        result = runner.run(
            "dig", "@" + server, "+time=2", "+tries=1", "+noall", "+answer",
            "_ldap._tcp." + domain, "SRV", check=False, timeout=5,
        )
        if result.returncode == 0 and re.search(r"\sIN\s+SRV\s", result.stdout):
            working.append(server)
    return working


def network_values(runner, connection):
    return {prop: runner.text("nmcli", "--escape", "no", "-g", prop, "connection", "show", "uuid", connection.uuid)
            for prop in DNS_PROPERTIES}


def backup_settings(runner, connection, local_admin):
    base = Path("/var/backups")
    base.mkdir(mode=0o755, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-")
    backup = Path(tempfile.mkdtemp(prefix="omarchy-ad-" + stamp, dir=base))
    manifest = {
        "connection_uuid": connection.uuid, "connection_name": connection.name,
        "interface": connection.device, "dns_before": network_values(runner, connection),
        "hostname_before": runner.text("hostnamectl", "--static"), "local_admin": local_admin,
        "ntp_before": runner.text("timedatectl", "show", "-p", "NTP", "--value"),
        "files": {},
    }
    paths = [PAM_FILE, NSS_FILE, SSSD_FILE, Path("/etc/krb5.conf"),
             Path("/etc/krb5.keytab"), Path("/etc/hostname"), Path("/etc/realmd.conf")]
    for directory in ("/etc/NetworkManager/system-connections", "/run/NetworkManager/system-connections"):
        folder = Path(directory)
        if not folder.exists():
            continue
        for profile in folder.iterdir():
            if not profile.is_file() or profile.is_symlink():
                continue
            config = configparser.ConfigParser(interpolation=None, strict=False)
            try:
                config.read(profile)
                if config.get("connection", "uuid", fallback="") == connection.uuid:
                    paths.append(profile)
            except configparser.Error:
                continue
    for path in paths:
        if path.is_symlink():
            raise SetupError(f"Refusing automatic setup with symlinked configuration: {path}")
        if not path.exists():
            manifest["files"][str(path)] = {"existed": False}
            continue
        target = backup / path.relative_to("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        info = path.stat()
        os.chown(target, info.st_uid, info.st_gid)
        manifest["files"][str(path)] = {"existed": True, "uid": info.st_uid,
                                       "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
    (backup / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    restore = backup / "restore-local-auth.sh"
    restore.write_text('''#!/usr/bin/env bash
set -euo pipefail
(( EUID == 0 )) || { echo "Run with sudo." >&2; exit 1; }
backup=$(cd -- "$(dirname -- "$0")" && pwd)
cp -a -- "$backup/etc/pam.d/system-auth" /etc/pam.d/system-auth
cp -a -- "$backup/etc/nsswitch.conf" /etc/nsswitch.conf
echo "Original PAM/NSS restored. DNS and AD membership were not changed."
''')
    restore.chmod(0o700)
    print(f"Backup: {backup}", flush=True)
    return backup


def restore_local_auth(backup, expected):
    for path in (PAM_FILE, NSS_FILE):
        source = backup / path.relative_to("/")
        original = source.read_text()
        if path.is_symlink() or path.read_text() not in {original, expected[path]}:
            raise SetupError(f"{path} was changed by another process; will not overwrite it during recovery.")
        info = source.stat()
        atomic_write(path, original, owner=(info.st_uid, info.st_gid),
                     mode=stat.S_IMODE(info.st_mode))


def install_packages(runner):
    missing = [p for p in PACKAGES if runner.run("pacman", "-Q", p, check=False).returncode]
    if not missing:
        return
    print("Installing missing packages: " + ", ".join(missing), flush=True)
    if not runner.has("omarchy"):
        raise SetupError("The Omarchy CLI is missing. Update Omarchy before running setup.")
    runner.run("omarchy", "pkg", "add", *missing, interactive=True, timeout=None)
    if any(runner.run("pacman", "-Q", p, check=False).returncode for p in PACKAGES):
        raise SetupError("Some packages could not be installed. Run omarchy update, then retry.")


def ensure_time(runner):
    if runner.text("timedatectl", "show", "-p", "NTPSynchronized", "--value") == "yes":
        return
    runner.run("timedatectl", "set-ntp", "true")
    print("Waiting up to 30 seconds for clock synchronization...", flush=True)
    for _ in range(15):
        if runner.text("timedatectl", "show", "-p", "NTPSynchronized", "--value") == "yes":
            return
        time.sleep(2)
    raise SetupError("Clock is not synchronized. Fix NTP before joining; Kerberos requires accurate time.")


def configure_dns(runner, connection, servers, domain):
    active_uuid = runner.text("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", connection.device)
    if active_uuid != connection.uuid:
        raise SetupError("The active network connection changed; stopping before changing DNS.")
    before = network_values(runner, connection)
    command = ["nmcli", "connection", "modify", "uuid", connection.uuid,
               "ipv4.dns", ",".join(servers), "ipv4.ignore-auto-dns", "yes",
               "ipv6.dns", "", "ipv6.ignore-auto-dns", "yes"]
    if "~" + domain not in re.split(r"[,\s]+", before["ipv4.dns-search"]):
        command.extend(["+ipv4.dns-search", "~" + domain])
    try:
        runner.run(*command)
        runner.run("nmcli", "device", "reapply", connection.device)
        runner.run("resolvectl", "query", "--type=SRV", "_ldap._tcp." + domain)
    except (SetupError, KeyboardInterrupt):
        print("DNS setup failed; restoring this connection's previous DNS settings.", file=sys.stderr)
        restore = ["nmcli", "connection", "modify", "uuid", connection.uuid]
        for key, value in before.items():
            restore.extend([key, value])
        runner.run(*restore)
        runner.run("nmcli", "device", "reapply", connection.device)
        raise


def local_administrator():
    name = os.environ.get("SUDO_USER", "")
    for line in Path("/etc/passwd").read_text().splitlines():
        fields = line.split(":")
        if len(fields) == 7 and fields[0] == name and int(fields[2]) >= 1000:
            return name
    raise SetupError("Run --apply with sudo from your existing LOCAL admin account, not an AD or root login.")


def check_mode(runner, connection, domain, servers, args):
    print(f"Domain:     {domain}\nConnection: {connection.name}\nUUID:       {connection.uuid}")
    print(f"IFACE:      {connection.device}\nHostname:   {socket.gethostname()}")
    print("Current DNS:\n" + runner.text("nmcli", "-g", "IP4.DNS,IP6.DNS", "device", "show", connection.device))
    if runner.has("dig"):
        working = responsive_dns(runner, servers, domain)
        print("Reachable AD DNS: " + (", ".join(working) or "none; check the office network/VPN"))
    else:
        print("Direct AD DNS checks need bind/dig; --apply installs it.")
    if runner.has("realm"):
        print("Configured domains: " + (runner.text("realm", "list", "--name-only") or "none"))
    print("\nREAD-ONLY: no settings changed. To configure this laptop, run:")
    command = ["sudo", "python3", str(Path(__file__).resolve()), "--apply", "--domain", domain,
               "--dns", ",".join(servers), "--connection", connection.uuid]
    for name in ("hostname", "join_user", "login_user", "computer_ou"):
        if getattr(args, name) is not None:
            command.extend(["--" + name.replace("_", "-"), getattr(args, name)])
    print("  " + shlex.join(command))


def apply_setup(args, runner, connection, domain, servers):
    if os.geteuid() != 0:
        raise SetupError("Use sudo python3 setup-omarchy-ad.py --apply in the other laptop's terminal.")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SetupError("--apply requires an interactive terminal. Do not pipe this script into sudo.")
    local_admin = local_administrator()
    for path in (PAM_FILE, NSS_FILE, SSSD_FILE, SSSD_FILE.parent):
        if path.is_symlink():
            raise SetupError(f"Symlinked configuration requires manual review: {path}")
    snippets = Path("/etc/sssd/conf.d")
    if snippets.exists() and any(snippets.glob("*.conf")):
        raise SetupError("SSSD config snippets exist; have the existing configuration reviewed first.")
    original_pam = PAM_FILE.read_text()
    original_nss = NSS_FILE.read_text()
    helper = Path("/etc/pam.d/sssd-arch")
    planned_pam = build_pam(original_pam, helper.read_text() if helper.exists() else None)
    planned_nss = build_nss(original_nss)
    existing_sssd = SSSD_FILE.read_text() if SSSD_FILE.exists() else ""
    if existing_sssd:
        build_sssd(existing_sssd, domain, "unused")  # Validate without overwriting policy.
    current_hostname = runner.text("hostnamectl", "--static")
    has_keytab = Path("/etc/krb5.keytab").exists()
    default_hostname = current_hostname if has_keytab else "omarchy-" + Path("/etc/machine-id").read_text().strip()[-6:]
    hostname = validate_hostname(args.hostname or input(f"Unique hostname for THIS laptop [{default_hostname}]: ").strip() or default_hostname)
    if has_keytab and hostname != current_hostname.lower():
        raise SetupError("An existing keytab was found. Renaming an enrolled computer requires manual handling.")
    join_user = args.join_user or ("" if has_keytab else input("AD account permitted to join computers: ").strip())
    if not has_keytab and (not join_user or any(ord(c) < 32 for c in join_user)):
        raise SetupError("A valid AD join username is required. Do not include its password.")
    login_user = args.login_user
    if login_user is None:
        login_user = input("Normal AD user to verify (optional, NOT a new account): ").strip()
    if any(ord(c) < 32 for c in login_user):
        raise SetupError("Invalid login username.")
    if login_user and "@" not in login_user:
        login_user += "@" + domain
    print(f"\nWill configure {hostname}.{domain} on {connection.name} ({connection.device}).")
    print("AD DNS candidates: " + ", ".join(servers))
    print("Only this connection's DNS changes; its IPv6 connectivity is retained.")
    print("Installs missing AD packages, joins AD, and enables SSSD/NSS/PAM.")
    print("Keeps local admin access and AD policy enforcement. No autologin or sudo changes.")
    print("Ensure this hostname is UNIQUE. No keytabs or profiles from another computer are needed.")
    if input("Type SETUP to continue: ").strip() != "SETUP":
        print("Cancelled; no changes made.")
        return
    backup = None
    auth_started = False
    join_started = False
    try:
        install_packages(runner)
        for command in ("sssctl", "adcli", "dig", "systemctl", "resolvectl"):
            if not runner.has(command):
                raise SetupError("Missing command after package installation: " + command)
        runner.run("systemctl", "is-active", "--quiet", "systemd-resolved.service")
        configured = runner.text("realm", "list", "--name-only").splitlines()
        if any(name.lower() != domain for name in configured):
            raise SetupError("Already configured for another domain; will not leave or overwrite it.")
        working_dns = responsive_dns(runner, servers, domain)
        if not working_dns:
            raise SetupError("None of the AD DNS servers responds with domain SRV records. Connect to the office network/VPN.")
        if PAM_FILE.read_text() != original_pam or NSS_FILE.read_text() != original_nss:
            raise SetupError("PAM/NSS changed during preflight; stopping rather than overwriting changes.")
        backup = backup_settings(runner, connection, local_admin)
        configure_dns(runner, connection, working_dns, domain)
        ensure_time(runner)
        if Path("/etc/krb5.keytab").exists() != has_keytab:
            raise SetupError("The machine keytab changed during setup; stopping rather than overwriting it.")
        if has_keytab:
            runner.run("adcli", "testjoin", "--domain=" + domain)
            print("Existing domain trust is valid; skipping the join.")
        else:
            runner.run("hostnamectl", "set-hostname", hostname)
            print("Enter the AD join account password at adcli's prompt (not the local sudo password).", flush=True)
            join_started = True
            command = ["adcli", "join", "--domain=" + domain, "--host-fqdn=" + hostname + "." + domain,
                       "--computer-name=" + hostname.upper(), "--login-user=" + join_user,
                       "--login-type=user", "--prompt-password", "--host-keytab=/etc/krb5.keytab"]
            if args.computer_ou:
                command.append("--domain-ou=" + args.computer_ou)
            runner.run(*command, interactive=True, timeout=300)
        text = build_sssd(existing_sssd, domain, hostname)
        service_user = runner.text("systemctl", "show", "sssd.service", "-p", "User", "--value")
        if service_user not in {"", "root", "sssd"}:
            raise SetupError("Custom SSSD service user; refusing to guess configuration ownership.")
        gid = grp.getgrnam("sssd").gr_gid if service_user == "sssd" else 0
        mode = 0o640 if service_user == "sssd" else 0o600
        staged = backup / "validated-sssd.conf"
        atomic_write(staged, text, owner=(0, gid), mode=mode)
        runner.run("sssctl", "config-check", "--config=" + str(staged), "--snippet=/etc/sssd/conf.d")
        if not SSSD_FILE.parent.exists():
            SSSD_FILE.parent.mkdir(mode=0o750)
            os.chown(SSSD_FILE.parent, 0, gid)
        current_sssd = SSSD_FILE.read_text() if SSSD_FILE.exists() else ""
        if current_sssd != existing_sssd:
            raise SetupError("SSSD configuration changed during enrollment; refusing to overwrite it.")
        atomic_write(SSSD_FILE, text, owner=(0, gid), mode=mode)
        runner.run("systemctl", "enable", "sssd.service")
        runner.run("systemctl", "restart", "sssd.service")
        runner.run("adcli", "testjoin", "--domain=" + domain)
        status = ""
        for _ in range(10):
            status = runner.text("sssctl", "domain-status", domain)
            if "Online status: Online" in status:
                break
            time.sleep(3)
        else:
            raise SetupError("SSSD stayed offline. Local PAM/NSS have not been changed.\n" + status)
        if PAM_FILE.read_text() != original_pam or NSS_FILE.read_text() != original_nss:
            raise SetupError("PAM/NSS changed during enrollment; stopping rather than overwriting changes.")
        auth_started = True
        atomic_write(NSS_FILE, planned_nss)
        atomic_write(PAM_FILE, planned_pam)
        for user in (local_admin, "root"):
            code, message = pam_account_status(user)
            if code:
                raise SetupError(f"Local account policy check failed for {user}: {message}")
        print("\nDomain trust: valid. SSSD: online. Local account-policy checks: passed.")
        if login_user:
            runner.run("id", "--", login_user)
            code, message = pam_account_status(login_user, "login")
            print(f"AD login account-policy check: {message} (code {code})")
            if code:
                print("WARNING: this AD user is not cleared for login. Ask IT about account/GPO access; do not disable policy enforcement.")
        else:
            print(f"AD user not tested. Check one with: id 'YOUR_AD_USER@{domain}'")
        print(f"\nBackups/recovery: {backup}")
        print("Keep the current local admin session open. Test a local login and an AD login in another terminal/TTY.")
        print("No password-based login was tested by this script. No AD user or admin rights were created.")
        print("AD desktop users need their own Omarchy configuration; autologin and existing homes were not modified.")
    except (Exception, KeyboardInterrupt):
        if backup:
            if auth_started:
                try:
                    restore_local_auth(backup, {PAM_FILE: planned_pam, NSS_FILE: planned_nss})
                    print("Original PAM/NSS restored to protect local login.", file=sys.stderr)
                except (SetupError, OSError) as recovery_error:
                    print(f"Manual recovery needed: {recovery_error}", file=sys.stderr)
            print(f"Backup/recovery directory: {backup}", file=sys.stderr)
            print("Completed package/DNS/hostname/NTP/SSSD changes are retained; inspect the error before rerunning.", file=sys.stderr)
            if join_started:
                print("An AD computer account/keytab may have been created. No automatic domain leave or keytab deletion was attempted.", file=sys.stderr)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="configure this laptop; requires sudo, a terminal, and confirmation")
    mode.add_argument("--check", action="store_true", help="read-only discovery (the default)")
    parser.add_argument("--domain", default=DEFAULT_DOMAIN)
    parser.add_argument("--dns", default=DEFAULT_DNS, help="comma-separated corporate IPv4 DNS servers")
    parser.add_argument("--connection", help="active office connection UUID, name, or interface; otherwise detected")
    parser.add_argument("--hostname", help="unique computer hostname, at most 15 characters; otherwise prompted")
    parser.add_argument("--join-user", help="AD account with computer-join rights; password is prompted separately")
    parser.add_argument("--login-user", help="existing normal AD user to verify; empty string skips this check")
    parser.add_argument("--computer-ou", help="optional AD computer OU distinguished name supplied by IT")
    args = parser.parse_args(argv)
    try:
        domain = validate_domain(args.domain)
        servers = parse_dns(args.dns)
        release = Path("/etc/os-release").read_text()
        if not re.search(r'^ID=["\']?omarchy["\']?$', release, re.MULTILINE):
            raise SetupError("This script is intended for Omarchy, not other Linux distributions.")
        runner = Runner()
        connection = discover_connection(runner, args.connection)
        if args.apply:
            apply_setup(args, runner, connection, domain, servers)
        else:
            check_mode(runner, connection, domain, servers, args)
        return 0
    except (SetupError, OSError, ValueError, configparser.Error) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

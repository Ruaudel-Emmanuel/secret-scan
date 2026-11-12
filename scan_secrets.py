#!/usr/bin/env python3
"""
scan_secrets.py — Scan hebdomadaire gitleaks de l'HISTORIQUE complet des dépôts actifs.

Pour chaque dépôt non archivé visible par le PAT :
  - clone --mirror (ou `git remote update`) dans /var/cache/secret-scan/<repo>.git
    (le PAT passe via -c http.extraHeader=... en ligne de commande -> JAMAIS persisté dans .git/config)
  - gitleaks detect --source <mirror> --report-format json --redact
    (--redact masque les secrets dans le rapport : aucun secret en clair nulle part)

Sortie : stdout + /var/log/secret-scan-last.txt + .json (umask 077, root only) + Telegram.
Exit 1 si au moins un finding.

Usage :
  python3 scan_secrets.py                # tous les dépôts actifs
  python3 scan_secrets.py --repo NOM     # un seul dépôt (test)
  python3 scan_secrets.py --max-repos 3  # limite (test)

Prérequis : gitleaks >= 8.x dans /usr/local/bin/gitleaks, git, PAT (Contents: read) dans /home/ubuntu/.env.
"""
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

API = "https://api.github.com"
ENV_PAT = "/home/ubuntu/.env"
ENV_TG = "/etc/vps-watchdog-telegram.env"
CACHE = "/var/cache/secret-scan"
LOG_TXT = "/var/log/secret-scan-last.txt"
LOG_JSON = "/var/log/secret-scan-last.json"
GITLEAKS = os.environ.get("GITLEAKS", "/usr/local/bin/gitleaks")
CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".gitleaks.toml")


def get_pat():
    with open(ENV_PAT) as f:
        for line in f:
            if line.startswith("GITHUB_PAT="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit(f"GITHUB_PAT introuvable dans {ENV_PAT}")


def api(url, pat):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {pat}",
                                                "Accept": "application/vnd.github+json",
                                                "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def git_base(pat):
    # credential helper INLINE (-c en CLI) : le PAT n'est jamais persisté dans .git/config
    helper = "!f() { echo username=x-access-token; echo password=%s; }; f" % pat
    return ["git", "-c", f"credential.helper={helper}"]


def ensure_mirror(full, pat):
    name = full.replace("/", "_")
    mirror = os.path.join(CACHE, name + ".git")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    if os.path.isdir(mirror):
        r = subprocess.run(git_base(pat) + ["-C", mirror, "remote", "update", "--prune"],
                           capture_output=True, text=True, timeout=600, env=env)
        if r.returncode != 0:
            print(f"  (remote update KO pour {full}, on rescanne le cache: {r.stderr[:120]})", file=sys.stderr)
    else:
        os.makedirs(CACHE, exist_ok=True)
        r = subprocess.run(git_base(pat) + ["clone", "--mirror", "-q",
                                            f"https://github.com/{full}.git", mirror],
                           capture_output=True, text=True, timeout=1200, env=env)
        if r.returncode != 0:
            print(f"  clone KO: {full}: {r.stderr[:200]}", file=sys.stderr)
            return None
    return mirror


def run_gitleaks(mirror, full):
    name = full.replace("/", "_")
    rep = f"/var/log/secret-scan-{name}.json"
    cmd = [GITLEAKS, "detect", "--source", mirror, "--report-format", "json",
           "--report-path", rep, "--no-banner", "--redact"]
    if os.path.exists(CONFIG):
        cmd += ["--config", CONFIG]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    # gitleaks exit 1 = findings (OK pour nous), 2+ = erreur réelle
    if r.returncode not in (0, 1):
        print(f"  gitleaks ERREUR sur {full}: {r.stderr[:200]}", file=sys.stderr)
        return []
    try:
        with open(rep) as f:
            findings = json.load(f)
    except Exception:
        return []
    os.chmod(rep, 0o600)
    for fd in findings:
        fd["_repo"] = full
    return findings


def send_telegram(text):
    try:
        with open(ENV_TG) as f:
            env = dict(l.strip().split("=", 1) for l in f if "=" in l)
        token, chat = env["TG_BOT_TOKEN"].strip('"'), env["TG_CHAT_ID"].strip('"')
        body = json.dumps({"chat_id": chat, "text": text[:4000]}).encode()
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage",
                                     data=body, method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status == 200
    except Exception as e:
        print(f"(telegram non envoyé: {e})", file=sys.stderr)
        return False


def main():
    os.umask(0o077)
    pat = get_pat()
    if not os.path.exists(GITLEAKS):
        raise SystemExit(f"gitleaks introuvable: {GITLEAKS} (installer depuis github.com/gitleaks/gitleaks/releases)")
    only_repo = sys.argv[sys.argv.index("--repo") + 1] if "--repo" in sys.argv else None
    max_repos = int(sys.argv[sys.argv.index("--max-repos") + 1]) if "--max-repos" in sys.argv else 1000

    repos = [r["full_name"] for r in api(f"{API}/user/repos?per_page=100&type=all", pat) if not r.get("archived")]
    if only_repo:
        repos = [r for r in repos if r.endswith("/" + only_repo)]
    repos = repos[:max_repos]

    all_findings = []
    scanned = 0
    for full in repos:
        print(f"🔎 {full} …", flush=True)
        mirror = ensure_mirror(full, pat)
        if not mirror:
            continue
        scanned += 1
        findings = run_gitleaks(mirror, full)
        if findings:
            print(f"  ⚠️  {full}: {len(findings)} finding(s)")
        all_findings.extend(findings)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = (f"🔐 Secret scan (gitleaks, historique complet) — {now}\n"
              f"{scanned} dépôts scannés · {len(all_findings)} finding(s)")
    lines = []
    for fd in all_findings:
        lines.append(f"  ⚠️ {fd['_repo']} — règle « {fd.get('RuleID','?')} » "
                     f"dans {fd.get('File','?')}:{fd.get('Line',0)} (commit {str(fd.get('Commit','?'))[:8]})")
    report = header + "\n" + ("\n".join(lines[:60]) if lines else "Aucun secret détecté 🎉")
    report += "\n(secrets masqués — détail local root-only dans /var/log/secret-scan-last.json)"
    print(report)

    with open(LOG_TXT, "w") as f:
        f.write(report + "\n")
    with open(LOG_JSON, "w") as f:
        json.dump({"date": now, "scanned": scanned, "findings": all_findings}, f, ensure_ascii=False, indent=1)
    os.chmod(LOG_TXT, 0o600)
    os.chmod(LOG_JSON, 0o600)

    if all_findings:
        send_telegram(report)
        sys.exit(1)
    send_telegram(report)
    sys.exit(0)


if __name__ == "__main__":
    main()

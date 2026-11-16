# secret-scan

Scan **hebdomadaire** de l'**historique complet** (tous les commits, y compris les fichiers
supprimés depuis) de tous les dépôts actifs, avec [gitleaks](https://github.com/gitleaks/gitleaks).

## 🧭 Principe

1. Liste les dépôts non archivés via l'API GitHub (PAT).
2. Clone `--mirror` de chacun dans `/var/cache/secret-scan/` (le PAT passe en
   `http.extraHeader` en CLI → **jamais persisté dans `.git/config`**). Les clones existants
   sont juste mis à jour (`git remote update --prune`).
3. `gitleaks detect --source <mirror> --report-format json --redact` → les secrets sont
   **masqués** dans les rapports (aucun secret en clair, même en local).
4. Rapport : Telegram + `/var/log/secret-scan-last.txt` / `.json` (chmod 600, root only).

## 🔒 Sécurité

- Aucun secret commité dans ce repo ; le PAT reste dans `/home/ubuntu/.env` sur le VPS.
- `--redact` : le champ `Secret` des rapports gitleaks est masqué. Le détail brut reste
  uniquement dans `/var/log/secret-scan-*.json` (root, 600).
- Si un vrai secret est trouvé : le révoquer immédiatement (GitHub/settings/tokens, Mistral, etc.),
  purger l'historique (`git filter-repo`), puis le noter dans une issue privée de ce repo.

Prérequis VPS : `gitleaks` ≥ 8.x dans `/usr/local/bin/gitleaks`, `git`, PAT (Contents: Read).

## ⏰ Cron (VPS)

- `secret-scan.timer` : **mardi 03h00 Europe/Paris**, `Persistent=true`
- `secret-scan.service` : oneshot, exécute `scan_secrets.py`

Vérification : `systemctl list-timers secret-scan.timer` · `journalctl -u secret-scan.service` · `cat /var/log/secret-scan-last.txt`

Exit code 1 si au moins un finding (visible dans `systemctl status`).

## ⚙️ Faux positifs

Ajuster `.gitleaks.toml` (allowlist regexes/paths) au fil des runs — ne jamais allowlister
un vrai pattern de secret.

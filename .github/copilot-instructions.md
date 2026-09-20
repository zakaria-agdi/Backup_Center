# BackupCenter

- Projet PowerShell pour Windows, compatible Windows PowerShell 5.1 et PowerShell 7.
- Garder les modules dans Modules et les scripts operateurs dans Scripts.
- Conserver DPAPI CurrentUser et les SecureString pour les secrets reversibles.
- Ne jamais journaliser les mots de passe, cles API, cles TOTP ou codes TOTP.
- Ne pas versionner Config/config.json, les fichiers temporaires ou les logs.
- Verifier les modifications avec Scripts/Test-Security.ps1, sans identifiants reels.
- Preserver les vecteurs de reference RFC 6238 et les tests de permissions Windows.
- La WebUI n'est pas implementee ; ne pas presenter la primitive TOTP comme une authentification complete.
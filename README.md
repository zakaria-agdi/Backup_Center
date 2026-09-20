# BackupCenter

Centre de sauvegarde Windows modulaire : secrets DPAPI, primitives TOTP, moteur de sauvegarde, adaptateurs hyperviseurs et maintenance. Le tableau de bord local affiche la file du moteur, le statut Proxmox et permet un test vzdump snapshot explicite en arriere-plan. Apres son succes, une continuation configuree execute le [Pull SFTP, chiffrement et upload](PROXMOX_PULL.md), sans relancer vzdump ni la pipeline complete. Il ne constitue pas une authentification web complete. Voir le [guide de l'interface](WebUI/README.md).

## Prerequis

- Windows, PowerShell 5.1 ou PowerShell 7, sans elevation requise pour les fichiers du projet. Le module Security n'a pas de dependance externe ; le serveur web utilise Pode 2.14.1.
- Un dossier local NTFS et un compte Windows disposant de son profil utilisateur. Executer les taches planifiees sous le meme compte que celui utilise pour chiffrer les secrets.
- Une horloge Windows synchronisee : TOTP depend de l'heure UTC.
- Respecter la politique d'execution de l'organisation ; signer les scripts si necessaire. Aucun contournement de cette politique n'est requis par le projet.

## Structure

```text
BackupCenter/
    Modules/   Security, BackupEngine, Hypervisors, Maintenance, WebBackend
    Config/    exemples publics, configurations locales et secrets chiffres
    Logs/      journaux de securite JSON Lines
    Scripts/   serveur local, operations et tests autonomes
    WebUI/     tableau de bord HTML/Tailwind raccorde a l'API locale
    Temp/      fichiers temporaires non versionnes
```

## Demarrage

Pour lancer le backend et le frontend ensemble, dans le runtime PowerShell choisi :

```powershell
Install-Module Pode -RequiredVersion 2.14.1 -Scope CurrentUser -Repository PSGallery -Force
.\Scripts\Start-BackupCenter.ps1
```

Ouvrir l'URL affichee, normalement `http://127.0.0.1:8080/`. La tache VS Code
`Backup Center: serveur local` lance le meme serveur. Le port suivant est utilise
si necessaire. Ne pas ouvrir le HTML directement : les donnees viennent du backend.

La cible de test est `https://192.168.1.45:8006/`, noeud `pve`, VM `9001`
(`srv-app-01`). Saisir le token uniquement dans le formulaire local, puis cliquer
sur **Tester la connexion**. Le certificat Proxmox doit etre approuve par Windows
et correspondre a l'adresse configuree ; aucune desactivation TLS n'est proposee.
Aucune sauvegarde n'est declenchee par cette interface. Le service est reserve a
un poste local de confiance, sans exposition reseau ni authentification multiutilisateur.

Pour initialiser les autres secrets du moteur :

Depuis la racine du projet :

```powershell
.\Scripts\Initialize-BackupCenter.ps1
.\Scripts\Set-BackupCenterSecret.ps1 -Name 'Smtp.Password'
.\Scripts\Set-BackupCenterSecret.ps1 -Name 'Cloud.ApiKey'
.\Scripts\Test-Security.ps1
```

L'initialisation est idempotente : elle conserve les secrets existants et refuse une configuration invalide. Le script de saisie utilise `Read-Host -AsSecureString` ; ne passer aucun secret litteral sur la ligne de commande.

## Secrets DPAPI

`Protect-BackupSecret` chiffre un `SecureString` ; `Unprotect-BackupSecret` restitue un `SecureString`. `Set-BackupSecret` et `Get-BackupSecret` raccordent ces operations a `Config/config.json`.

```powershell
Import-Module .\Modules\Security.psd1 -Force
$password = $null
try {
    $password = Get-BackupSecret -Name 'Smtp.Password'
    $credential = [pscredential]::new('backup-service', $password)
    # Transmettre $credential au composant de sauvegarde concerne.
}
catch {
    throw 'Impossible de charger les identifiants de sauvegarde.'
}
finally {
    if ($null -ne $password) { $password.Dispose() }
}
```

- DPAPI utilise exclusivement `CurrentUser`, avec une valeur d'entropie applicative fixe servant de separation de contexte, pas de cle secrete embarquee.
- Les valeurs du dictionnaire `Secrets` sont des enveloppes `dpapi:v1:<Base64>`. Ne jamais ajouter de mot de passe ou de cle en clair au JSON.
- Les noms de secrets acceptent lettres ASCII, chiffres, points, tirets, deux-points et underscores, sur 128 caracteres maximum, avec une lettre ou un chiffre initial.
- Les ACL des fichiers de configuration sont limitees au compte courant et a SYSTEM. Le dossier parent doit aussi etre administre et non modifiable par des utilisateurs non fiables.
- Un verrou exclusif couvre lecture, modification et remplacement atomique. Un conflit echoue immediatement : le demandeur peut reessayer. Le fichier `.lock` vide reste volontairement present et ne doit pas etre supprime en cours d'utilisation.
- Les fichiers temporaires sont nettoyes normalement ; apres un arret brutal, un fichier `.tmp` chiffre peut subsister. Taille maximale du JSON : 1 Mio.
- Les commandes acceptent `-ConfigPath` et `-LogDirectory` pour isoler les environnements. Les tests utilisent uniquement un dossier temporaire.

DPAPI protege les donnees au repos, pas contre un processus compromis executant le meme compte, ni contre un administrateur local. Un simple transfert de `config.json` ne suffit pas pour migrer les secrets : conserver une procedure de recuperation des cles/profils DPAPI ou rechiffrer sous le nouveau compte. Les ACL seules ne garantissent pas la recuperation des donnees.

## TOTP RFC 6238

`New-TotpSecret` genere une cle aleatoire cryptographique en Base32 sans remplissage et la retourne en `SecureString`. `Get-TotpCode` produit un code ; `Test-TotpCode` le valide. Les cles Base32 minuscules sont egalement acceptees, mais les espaces et le remplissage `=` sont refuses.

| Parametre | Defaut | Valeurs |
| --- | --- | --- |
| Algorithm | SHA1 | SHA1, SHA256, SHA512 |
| Digits | 6 | 6 ou 8 |
| Period | 30 secondes | 1 a 300 secondes |
| Window | 1 | 0 a 2 pas de temps de chaque cote |
| UnixTime | UTC actuel | Secondes depuis le 01/01/1970, pour tests deterministes |
| LastAcceptedTimeStep | -1 | Dernier compteur consomme, a fournir par le serveur |

Les cles generees contiennent respectivement 20, 32 et 64 octets pour SHA1, SHA256 et SHA512. Choisir les memes parametres dans l'application et l'authenticator. Le code reste une chaine afin de conserver les zeros initiaux. La comparaison parcourt tous les caracteres et toute la fenetre, sans retour anticipe en cas de correspondance ; PowerShell ne garantit toutefois pas un temps constant strict.

Generation et stockage d'une cle, une seule fois par enrollement :

```powershell
$totpSecret = $null
try {
    $totpSecret = New-TotpSecret
    Set-BackupSecret -Name 'Totp.Operator' -Secret $totpSecret
}
catch {
    throw 'Creation de la cle TOTP impossible.'
}
finally {
    if ($null -ne $totpSecret) { $totpSecret.Dispose() }
}
```

Cet exemple ne provisionne pas l'application authenticator. L'enrollement et son QR code restent a implementer cote serveur ; ne pas afficher la cle dans une console journalisee. Executer de nouveau cet exemple remplace la cle existante.

`Test-TotpCode` retourne un booleen, ou `{ IsValid, TimeStep }` avec `-PassThru`. Une saisie invalide retourne `false` ; un defaut de configuration ou de journalisation leve une exception et doit refuser l'acces. Le serveur doit lire le dernier compteur accepte, le passer via `-LastAcceptedTimeStep`, puis persister atomiquement le compteur retourne avant d'ouvrir une session. Sans cela, un code reste reutilisable pendant sa fenetre de validite. Voir `WebUI/README.md` pour le contrat complet.

Les fonctions de generation de code et de lecture des secrets ne doivent jamais etre exposees comme des endpoints publics. La limitation des tentatives, le premier facteur, le stockage anti-rejeu et les sessions ne sont pas encore implementes. Les mots de passe de connexion des utilisateurs doivent etre haches, contrairement aux identifiants de services que DPAPI doit pouvoir restituer.

## Erreurs Et Journaux

Les operations utilisent `Set-StrictMode`, des erreurs bloquantes, `try/catch/finally` et liberent les ressources cryptographiques. Les tampons sensibles sont effaces lorsque possible ; les appelants doivent liberer leurs `SecureString`.

Les fichiers `Logs/security-YYYY-MM-DD.jsonl` contiennent une ligne JSON par evenement : `TimestampUtc`, `Component`, `Operation`, `Outcome`, `ProcessId` et `EventId`. Les succes, refus et erreurs sont traces, notamment preparation et validation des ecritures. Les noms et valeurs des secrets, codes TOTP, contenus JSON et messages bruts des exceptions ne sont jamais journalises. Les erreurs renvoyees sont volontairement generiques.

Si le journal est inaccessible, l'operation echoue. Une ecriture possede un evenement de preparation et un evenement de succes : une panne entre la validation du fichier et le dernier evenement peut laisser une modification valide malgre une exception. Verifier l'etat avant une nouvelle tentative. Les logs sont locaux, non inviolables, avec rotation quotidienne mais sans purge automatique ; prevoir des ACL de deploiement, une retention et une collecte centrale.

Les validations de parametres du moteur PowerShell ont lieu avant l'execution du corps des fonctions ; elles sont bloquantes mais ne produisent pas d'evenement du module.

### Contrat Try/Catch/Finally

- `try` englobe l'operation et son audit. Les cmdlets sont executees avec des erreurs bloquantes ; un succes n'est retourne qu'apres journalisation.
- Un code TOTP incorrect, expire ou rejoue est un refus attendu : `false`, ou `{ IsValid = false; TimeStep = null }` avec `-PassThru`. Une panne de configuration, de cryptographie ou d'audit leve une exception : l'appelant doit refuser l'acces, jamais poursuivre avec une valeur par defaut.
- `catch` journalise uniquement l'operation et son etat, puis leve une `InvalidOperationException` au message fixe. Il n'ajoute pas l'exception native comme `InnerException`, car son message pourrait contenir des donnees sensibles. Ne pas serialiser un ErrorRecord complet ou son InvocationInfo dans les journaux ou les reponses web.
- `Write-SecurityLog` identifie une panne par `Exception.Data['SecurityCode'] = 'AuditUnavailable'`. Les huit API publiques utilisent alors `throw` sans argument : l'exception assainie est propagee sans seconde tentative d'ecriture, meme entre appels imbriques. On ne masque ni ne reessaie automatiquement une panne de journalisation.
- `finally` efface les tableaux d'octets sensibles et libere les BSTR, objets cryptographiques et verrous selon les fonctions. Les SecureString construits mais non retournes sont detruits sur erreur ; ceux retournes restent a la charge de l'appelant. Cela ne garantit pas l'effacement des chaines immuables gerees par .NET.

Une erreur apres remplacement du JSON peut survenir alors que la modification est deja enregistree. Le refus signale l'echec de l'operation complete, pas une transaction avec rollback garanti : inspecter l'etat avant toute nouvelle tentative.

## Verification

`Scripts/Test-Security.ps1` couvre les 18 vecteurs officiels de l'annexe B de la RFC 6238 (SHA1/SHA256/SHA512), les zeros initiaux, les fenetres temporelles, l'anti-rejeu avec compteur fourni, le stockage DPAPI, les donnees alterees, les ACL, les conflits de verrou, le JSON corrompu, l'idempotence et les echecs de journalisation. Il ne modifie pas la configuration du projet.

La suite [Scripts/Security.Tests.ps1](Scripts/Security.Tests.ps1) ajoute 85 tests Pester : DPAPI CurrentUser reel (Unicode, alea, alteration, entropie), tous les vecteurs RFC 6238, validation et rejeu, Base32 invalide, limites des compteurs, JSON, ACL NTFS, verrouillage, absence de secrets dans l'audit et propagation des pannes sans retry dans les huit API. Seules les dependances necessaires aux pannes injectees sont mockees ; les calculs cryptographiques et les permissions utilisent Windows.

Depuis la racine du depot, dans le runtime a tester (Windows PowerShell 5.1 ou PowerShell 7) :

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Repository PSGallery -Scope CurrentUser -Force -SkipPublisherCheck
Import-Module Pester -RequiredVersion 5.7.1 -ErrorAction Stop
Invoke-Pester -Path .\Scripts\Security.Tests.ps1 -Output Detailed
.\Scripts\Test-Security.ps1
```

Pester 5.7.1 est utilise pour les verifications ; Pester 3.4 livre avec Windows ne convient pas. L'installation est necessaire une fois par emplacement de modules utilisateur et requiert Internet. Aucun droit administrateur n'est requis. `TestDrive:` isole les fichiers et journaux temporaires ; `AfterEach` libere les SecureString. La configuration et les logs reels du projet ne sont pas utilises. En CI, ajouter `-CI` a `Invoke-Pester` pour obtenir un code de sortie non nul en cas d'echec.

La suite n'utilise aucun identifiant reel. Le comportement entre deux comptes Windows et la recuperation DPAPI apres migration necessitent des essais de deploiement distincts. Reference normative : https://www.rfc-editor.org/rfc/rfc6238#appendix-B

## Moteur De Sauvegarde

Le module [Modules/BackupEngine.psm1](Modules/BackupEngine.psm1) ajoute une file JSON FIFO protegee par un verrou interprocessus. Le pipeline execute Export/Pull, Compress & Encrypt, Upload, Archive, Offsite puis VERIFY. Un job ne devient `Success` qu'apres interrogation des deux destinations distantes et comparaison du hash disponible ou de la taille, ainsi que controle SHA256 de l'archive locale.

Le moteur necessite `rclone.exe` et `age.exe` pour les sauvegardes reelles. Le module de securite et les tests autonomes restent utilisables sans ces executables. Le [guide du moteur](BACKUP_ENGINE.md) decrit la preparation, les commandes, les objets de monitoring et les limites de verification.

```powershell
Import-Module .\Modules\BackupEngine.psd1 -Force
Get-BackupQueue | Select-Object JobId, Status, UpdatedUtc
.\Scripts\Test-BackupEngine.ps1
```

## Hyperviseurs

[Modules/Hypervisors.psm1](Modules/Hypervisors.psm1) ajoute les exports Proxmox VE (REST vzdump et suivi UPID), Hyper-V (capture coherente native) et VMware (PowerCLI, VM deja arretee). Chaque adaptateur retourne un resultat commun utilisable avec `New-BackupJob -ExportResult`, puis `Start-BackupPipeline` ou la file JSON.

Voir [HYPERVISORS.md](HYPERVISORS.md) pour les prerequis, la recuperation Proxmox depuis un stockage fichier accessible, les limites de coherence et les exemples. Tests autonomes : `Scripts/Test-Hypervisors.ps1`.

## Maintenance Et Alertes

[Modules/Maintenance.psm1](Modules/Maintenance.psm1) ajoute les alertes Telegram avec l'etape exacte en echec et une projection assainie de l'ErrorRecord, ainsi qu'une retention locale/rclone par source. Les suppressions sont controlees par WhatIf/Confirm et tracees dans un journal JSONL durable avant et apres chaque action.

Voir [MAINTENANCE.md](MAINTENANCE.md) et [Config/retention.example.json](Config/retention.example.json) pour les commandes, le rattachement des JobIds aux sources, les limites de retention et d'archivage des journaux. Aucune politique reelle ni notification automatique n'est activee. Tests : `Scripts/Test-Maintenance.ps1`.
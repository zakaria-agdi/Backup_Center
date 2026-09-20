# Interface BackupCenter

Tableau de bord raccorde au serveur PowerShell local : dernier releve Proxmox,
file reelle du moteur et etapes du travail selectionne. Un test vzdump snapshot peut
etre declenche explicitement pour la cible fixe. Il cree une vraie sauvegarde Proxmox.
Apres succes, une continuation distincte et configuree execute Pull SFTP, chiffrement
et upload, sans retention ni lancement de la pipeline complete.

## Demarrage Local

Depuis la racine, dans le runtime PowerShell choisi (Windows PowerShell 5.1 ou 7) :

```powershell
Install-Module Pode -RequiredVersion 2.14.1 -Scope CurrentUser -Repository PSGallery -Force
.\Scripts\Start-BackupCenter.ps1
```

La tache VS Code `Backup Center: serveur local` utilise PowerShell 7. Ouvrir l'URL
affichee, normalement `http://127.0.0.1:8080/` ; le serveur cherche un port libre
jusqu'a 8080 + 20. `-Port` permet de choisir le debut de cette plage.
Ouvrir directement le HTML ne permet pas de charger les donnees.

La cible par defaut de [proxmox.example.json](../Config/proxmox.example.json) est
`https://192.168.1.45:8006/`, noeud `pve`, VM `9001`, nom attendu `srv-app-01`.
Une autre configuration locale peut etre fournie avec `-TargetPath` ; le navigateur
ne peut pas changer la cible. Le fichier local Config/proxmox.json est ignore par Git
mais n'est pas selectionne automatiquement.

1. Creer un token Proxmox disposant de `VM.Audit` sur `/vms/9001`. Avec la separation
	de privileges, verifier les droits effectifs du compte et du token.
2. Faire approuver le certificat Proxmox par Windows selon la procedure de votre
	organisation, avec un nom ou une IP conforme au certificat. Aucun contournement
	TLS n'est disponible ; ne pas approuver aveuglement un certificat inconnu.
3. Saisir l'identifiant `utilisateur@realm!token` et son secret uniquement dans le
	formulaire local, puis **Enregistrer**. Ne jamais les transmettre dans le chat.
4. Cliquer sur **Tester la connexion**. Ce bouton contacte Proxmox avec un GET
	de statut ; le nom retourne doit correspondre au nom attendu.

L'enregistrement et l'actualisation locale ne contactent pas Proxmox. Les statistiques
sont celles du dernier test de connexion ; un echec
efface les anciennes mesures. La file expose au plus 100 travaux dans l'ordre du
moteur, sans chemin source ni detail d'execution prive. Le dernier test vzdump apparait
en plus, distinct des travaux de pipeline. Aucun travail de pipeline n'est cree par ce test.

## Premier Test vzdump

Ce n'est pas un dry-run : Proxmox ecrit une archive et consomme espace disque et I/O.
Le mode snapshot ne demande pas l'arret de la VM, mais ne garantit ni absence d'impact
sur ses performances, ni coherence applicative, ni restaurabilite.

1. Accorder au compte et au token les droits effectifs necessaires : `VM.Audit` et
	`VM.Backup` sur `/vms/9001`, `Datastore.Audit` et `Datastore.AllocateSpace` sur le
	stockage choisi. La lecture de l'inventaire peut necessiter des droits d'audit
	supplementaires selon la configuration Proxmox. Ne pas attribuer Administrator par defaut.
2. Dans **Test vzdump**, charger les stockages avec le bouton de rafraichissement.
	Cette action effectue uniquement un GET Proxmox. Seuls les stockages fichiers
	actifs et disponibles pour `backup`, avec de l'espace libre, sont proposes.
	Le controle d'espace non nul ne prouve pas que la sauvegarde entiere tiendra.
3. Choisir explicitement le stockage, verifier sa capacite, cocher la confirmation
	de sauvegarde reelle puis cliquer **Lancer vzdump**. Aucun stockage n'est preselectionne.
4. Le serveur repond `202` apres avoir persiste l'admission et lance un processus
	PowerShell de fond. Celui-ci decrypte le token avec DPAPI, revalide le nom de la VM
	et le stockage, prend le verrou commun du moteur puis effectue un seul POST vzdump.
	Parametres imposes : VM cible, `mode=snapshot`, `compress=zstd`, `remove=0`,
	`prune-backups=keep-all=1`. Aucun retry du POST n'est effectue.
5. Le worker suit l'UPID par GET toutes les 5 secondes environ, pendant au plus une
	heure apres admission Proxmox. Le navigateur lit seulement le statut local toutes
	les 2 secondes pendant l'activite. `stopped` avec `exitstatus=OK` valide l'export
	distant ; cela ne valide pas le Pull ou la restauration. L'UPID est affiche pour
	permettre la consultation dans Proxmox. Les autres etapes restent non executees.

Le dernier etat est ecrit atomiquement dans Config/proxmox-backup-test.json (ignore
par Git). Les identifiants de requete et la version du precedent test evitent les
doubles soumissions. Un autre test et le remplacement du token sont refuses tant
qu'une tache est active ou incertaine. La fermeture du navigateur ne stoppe pas le
worker ; l'arret du serveur peut interrompre le suivi, pas la sauvegarde distante.
Un etat actif sans mise a jour depuis 120 secondes est affiche comme incertain.

En cas de timeout, reponse POST perdue ou redemarrage pendant une tache, **ne pas
relancer aveuglement** : consulter les taches Proxmox de la VM (meme sans UPID local).
Il n'y a pas encore de reprise automatique du suivi ni de bouton d'annulation.
Apres verification independante que toute tache distante est terminee, un operateur
peut arreter le serveur, conserver le fichier d'etat pour audit hors de son chemin
actif, puis redemarrer pour autoriser un nouveau test. Ne jamais reinitialiser cet
etat pendant qu'une sauvegarde pourrait encore tourner.

Pour reprendre cette sauvegarde sans nouveau vzdump, configurer SSH et rclone selon
le [guide Pull](../PROXMOX_PULL.md), puis utiliser **Rapatrier, chiffrer et envoyer**.
Le worker execute les trois premieres etapes ; Archive, Offsite et VERIFY restent
non executees. Les octets et le debit sont actualises pendant les transferts.

## Limites De Securite

Le serveur ecoute uniquement sur `127.0.0.1`. Il est reserve a un poste mono-utilisateur
de confiance, sans proxy ni exposition reseau. Il n'y a pas d'authentification web :
un processus local peut acceder au service. Le nonce CSRF n'est pas une session
authentifiee. Le token est chiffre avec DPAPI CurrentUser dans Config/secrets.json,
sous le compte Windows du serveur ; les ACL sont limitees au compte courant et SYSTEM.
DPAPI ne protege pas contre un processus compromis du meme compte ou un administrateur.

Le backend controle Host, Origin, adresse locale, en-tete client et nonce des POST.
Le navigateur n'utilise aucun stockage persistant pour le token. Les journaux de
securite contiennent des actions et resultats fixes, jamais les secrets ou les
exceptions fournisseur brutes. Les fichiers Config, Logs et Modules ne sont pas servis.

| Methode | Route | Effet |
| --- | --- | --- |
| GET | `/api/session` | Nonce anti-CSRF |
| GET | `/api/dashboard` | File et dernier releve en memoire |
| POST | `/api/proxmox/credentials` | Stockage DPAPI du token |
| POST | `/api/proxmox/test` | Lecture du statut de la VM fixe |
| POST | `/api/proxmox/storages` | Lecture des stockages compatibles |
| POST | `/api/proxmox/backup-test` | Admission asynchrone d'un test vzdump snapshot |
| POST | `/api/proxmox/transfer` | Continuation asynchrone Pull, chiffrement et upload |

Les appels API exigent `X-BackupCenter-Client: dashboard`. Les POST exigent aussi
l'Origin exacte du serveur, un JSON et `X-BackupCenter-CSRF`. Les requetes sont limitees
a 16 Kio ; le test distant a un delai de 15 secondes et un intervalle minimal de 5 secondes.

## Fichiers et compilation

- `index.html` : structure semantique et etats initiaux inconnus.
- `styles.css` : source Tailwind et styles des composants, variables de couleur et breakpoints.
- `assets/tailwind.css` : CSS compile et minifie, a regenerer apres modification HTML/CSS.
- `assets/lucide.min.js` : distribution UMD locale de Lucide 0.468.0, licence ISC incluse.
- `dashboard.js` : rendu par textContent, appels API, formulaire et selection du travail.

Depuis la racine du depot, avec Node.js/npm et Internet pour recuperer l'outil de build :

```powershell
npx --yes tailwindcss@3.4.17 -i './WebUI/styles.css' -o './WebUI/assets/tailwind.css' --content './WebUI/index.html' --minify
```

Tailwind 3.4.17 est fige ; il n'y a pas de CDN au chargement de la page. Les etats
dynamiques utilisent `data-status` plutot que des classes Tailwind generees a la volee.
Le navigateur doit prendre en charge CSS Grid, `color-mix()` et les variables CSS
(Edge/Chrome/Firefox recents). La page n'utilise aucune API PowerShell dans le navigateur.

## Verification

Depuis la racine :

```powershell
.\Scripts\Test-WebBackend.ps1
.\Scripts\Test-ProxmoxBackupTest.ps1
.\Scripts\Test-WebBackupWorker.ps1
.\Scripts\Test-Hypervisors.ps1
.\Scripts\Test-Security.ps1
```

Les tests utilisent des secrets factices dans un dossier temporaire et simulent
Proxmox. Ils n'effectuent aucune sauvegarde ni connexion a un hyperviseur reel.
Avec le serveur lance, PowerShell 7 peut verifier les routes et protections HTTP :

```powershell
.\Scripts\Test-WebServer.ps1 -BaseUri 'http://127.0.0.1:8080'
```

Les scenarios navigateur de succes et d'echec peuvent etre simules sans token reel.
Une verification locale reussie ne prouve pas la connectivite Proxmox, les droits
du token, la validite du certificat ou la restaurabilite d'une sauvegarde.

## Contrat d'authentification a implementer

1. Verifier le premier facteur avant de demander le TOTP. Stocker les mots de passe de connexion sous forme de hachages adaptes, pas sous forme DPAPI reversible.
2. Retrouver la cle TOTP propre a l'utilisateur authentifie avec `Get-BackupSecret`, sans la transmettre au navigateur.
3. Lire le dernier compteur accepte dans un stockage serveur durable, puis appeler `Test-TotpCode -PassThru -LastAcceptedTimeStep ...`.
4. N'accepter qu'un resultat `IsValid = $true`. Toute exception doit refuser l'acces.
5. Enregistrer atomiquement le nouveau `TimeStep` avant de creer la session. Deux requetes concurrentes ne doivent pas pouvoir consommer le meme compteur.
6. Ajouter HTTPS, cookies Secure/HttpOnly/SameSite, protection CSRF, expiration des sessions, limitation des tentatives par compte et par origine et verrouillage temporaire.
7. Prevoir un enrollement protege avec confirmation du premier code, des codes de recuperation haches et la rotation des cles. La future page d'enrollement sera la seule exposition ponctuelle de la cle a son proprietaire.

La validation TOTP seule ne constitue pas une authentification web complete. L'option `LastAcceptedTimeStep` ne persiste aucun etat : l'interface doit assurer ce stockage et la synchronisation des acces.
Les codes et cles TOTP ne doivent jamais etre places dans les URL, journaux HTTP, traces PowerShell ou reponses ordinaires.
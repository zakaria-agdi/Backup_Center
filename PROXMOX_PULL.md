# Pull Proxmox

La continuation reprend une sauvegarde vzdump deja terminee avec `stopped/OK`.
Elle ne relance pas vzdump et ne supprime pas l'archive distante. Elle execute
**Pull SFTP, chiffrement, puis upload** ; ce bouton n'est pas un test de lecture seul.
Les etapes Archive, Offsite et VERIFY restent non executees. La verification de
l'objet envoye fait partie de l'etape Upload, pas d'une pipeline complete.

## Configuration

Adapter les six champs de [l'exemple](Config/proxmox-transfer.example.json) dans
le fichier local `Config/proxmox-transfer.json`, ignore par Git. Aucun mot de passe,
token ou contenu de cle ne doit figurer dans ce JSON ni dans le chat.

- Installer un rclone officiel et verifier son empreinte SHA256 publiee. Le test
  d'integration a ete execute avec rclone 1.75.1 ; fournir son chemin absolu.
- L'hote SSH est impose par `ApiUri` de la cible Proxmox. Le compte SSH est distinct
  du token API. Lui accorder uniquement la lecture des archives necessaires via SFTP.
- Le chemin SFTP doit etre le chemin absolu du dump annonce par Proxmox. Un chroot
  qui change ce chemin ne convient pas sans adapter la configuration cote serveur.
- Fournir une cle privee OpenSSH lisible par le compte Windows du worker, protegee
  par des ACL restrictives. Aucun prompt de passphrase n'est gere par cette pipeline.
  Ne pas placer la cle dans le depot ; provisionner une cle dediee selon votre politique.
- Le fichier `known_hosts` doit contenir la cle de l'hote verifiee par un canal
  independant. Pour un port non standard, utiliser `[hote]:port`. Ne pas approuver
  aveuglement la sortie de ssh-keyscan. Une cle inconnue ou differente est refusee.
- Configurer le remote rclone sous le meme compte Windows que le serveur, avec
  ses secrets et ACL geres separement. La destination doit etre `nomremote:chemin`.
  Verifier espace libre et quotas avant de lancer ; aucune estimation de capacite
  locale suffisante n'est garantie. Prevoir la place pour le clair et le chiffre.

Le token API enregistre localement doit pouvoir lire la VM, la tache vzdump, ses logs
et le contenu du stockage. Le proprietaire de l'UPID doit correspondre exactement a
l'identifiant du token actuel (`utilisateur@realm!token`), sans valeur codee en dur.
La rotation du token peut donc empecher la continuation d'une ancienne tache.

## Execution

Apres mise a jour des modules, redemarrer [le serveur](Scripts/Start-BackupCenter.ps1)
uniquement quand aucun worker n'est actif. Ne pas reinitialiser l'etat de sauvegarde.
Dans le tableau de bord, reprendre le test vzdump reussi avec **Rapatrier, chiffrer et
envoyer**. L'admission est idempotente pour un meme identifiant de requete.

Le resolveur recoupe la VM, l'UPID, son resultat, le chemin du journal et le volume
de stockage. Le Pull ecrit `Temp/<runId>/<archive>.partial` dans un dossier protege,
controle la taille annoncee puis renomme le fichier. Rclone verifie la cle SSH et
n'execute pas de shell distant (`--sftp-shell-type none`). SSH et la taille ne
constituent pas une verification par hash independant de l'archive source.

L'archive `.vma.zst` est deja compressee. Elle est chiffree sans recompression avec
AES-256-CBC et HMAC-SHA256 (format BCA1), avec un secret aleatoire de 64 octets par
archive, conserve via Security/DPAPI CurrentUser. Aucun secret ne passe en argument
de processus. Le clair et le partiel sont supprimes a la fin normale ou sur erreur
geree, mais pas garantis en cas d'arret brutal. La suppression n'est pas un effacement
securise. Le fichier chiffre reste dans Temp, y compris apres un echec d'upload.

L'upload impose `--transfers 8 --checkers 8 --drive-chunk-size 256M --buffer-size 128M`.
Il est suivi d'un `lsjson --stat --hash` independant : taille et hash pris en charge,
ou taille seule si le remote ne propose aucun hash compatible. Cela ne prouve pas
la restaurabilite d'une VM. Les octets et le debit proviennent des statistiques
rclone ; le backend synchronise ses lectures/ecritures d'etat entre processus.

Un etat `Unknown` demande une verification operateur. Aucun redemarrage automatique
ni reprise partielle n'est implemente. Ne pas supprimer un verrou ou relancer vzdump
pour contourner cet etat.

## Restauration

Conserver le fichier chiffre **et** le magasin de secrets avec le profil/les moyens
de recuperation DPAPI du compte Windows. Copier seulement le JSON de secrets vers
une autre machine ne garantit pas son dechiffrement. Tester votre procedure de
recuperation avant toute utilisation en production. Ce format n'est pas un fichier age.

```powershell
Import-Module .\Modules\BackupEngine.psd1 -Force
Unprotect-BackupArchive -SourcePath 'C:\Restore\archive.vma.zst.bca' `
    -OutputPath 'C:\Restore\archive.vma.zst' `
    -ConfigPath '.\Config\secrets.json' -LogDirectory '.\Logs'
```

Executer sous le compte DPAPI d'origine, vers un fichier inexistant dans un dossier
protege. Le HMAC est verifie avant production du clair. La restauration Proxmox
de cette archive reste une operation distincte a valider.

## Tests Isoles

Depuis la racine, avec Windows PowerShell 5.1 puis PowerShell 7 :

```powershell
.\Scripts\Test-ProxmoxPull.ps1 -RclonePath 'C:\Tools\rclone\rclone.exe'
.\Scripts\Test-ProxmoxTransfer.ps1
.\Scripts\Test-ProxmoxBackupTest.ps1
.\Scripts\Test-BackupArchive.ps1
.\Scripts\Test-WebBackend.ps1
.\Scripts\Test-WebBackupWorker.ps1
.\Scripts\Test-Security.ps1
```

Le test Pull necessite aussi `ssh-keygen.exe` (client OpenSSH Windows). Il genere des
cles jetables, sert 8 Mio de donnees factices en SFTP sur loopback et port ephemere,
teste les refus de cle hote/client, la taille incorrecte, le nettoyage, la progression,
le worker reel et une restauration comparee par hash. L'upload utilise un remote local.
Le resolveur Proxmox est simule et refuse tout nouveau vzdump : aucun hyperviseur
reel, compte cloud ou archive VM reelle n'est utilise par ces tests.
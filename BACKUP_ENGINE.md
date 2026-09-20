# BackupEngine

Moteur Windows PowerShell 5.1 / PowerShell 7, avec une file JSON locale et des transferts rclone. Il ne contient aucun adaptateur REST ni base SQLite : JSON et rclone sont les implementations retenues.

Ce guide decrit la pipeline de file ZIP/age a six etapes. La [continuation Proxmox](PROXMOX_PULL.md)
utilise `Invoke-ProxmoxTransferPipeline`, `Protect-BackupArchive` et `Unprotect-BackupArchive` :
Pull SFTP d'une archive deja compressee, chiffrement BCA1/DPAPI et upload, sans age.

## Preparation

- Installer les versions officielles de [rclone](https://rclone.org/downloads/) et [age](https://github.com/FiloSottile/age#installation). Le moteur attend `rclone.exe` et `age.exe` dans PATH, ou leurs chemins explicites via `-RclonePath` et `-AgePath`.
- Configurer les remotes rclone sous le compte Windows du worker. Utiliser des noms de remotes de 2 a 64 caracteres, sans URL contenant des identifiants. La configuration rclone et ses secrets doivent etre proteges separement ; aucun jeton ne doit figurer dans un job JSON.
- Creer et conserver hors du depot une identite age X25519, dans un emplacement protege et sauvegarde. Le job ne contient que le destinataire public `age1...` de 62 caracteres. La cle privee n'est pas necessaire pour sauvegarder, mais elle est indispensable pour restaurer. Les destinataires SSH et post-quantiques ne sont pas pris en charge par ce module.
- Choisir une destination offsite reellement independante. Le moteur refuse deux chemins identiques, mais ne peut pas determiner si deux remotes pointent vers la meme infrastructure.
- Utiliser un dossier local NTFS pour la file et les verrous, sur un hote unique. Proteger les dossiers parents Config, Work, Logs et Archive contre les modifications non autorisees. Ne pas utiliser un partage reseau comme mecanisme de coordination multi-hotes.
- Fournir un export coherent et stable. La copie de fichiers ne cree pas un snapshot VSS, Hyper-V, VMware ou de base de donnees. L'export applicatif doit etre produit avant le job. Les sources locales contenant des reparse points sont refusees.

Les tests ne necessitent aucun binaire tiers ni compte cloud. Ils remplacent les commandes age/rclone par des doubles ; ils ne prouvent pas le chiffrement age ou l'acces a un fournisseur reel.

## Creer Et Executer Un Job

Adapter les chemins et remotes de cet exemple a l'environnement. Saisir uniquement une cle publique age, jamais une cle privee :

```powershell
Import-Module .\Modules\BackupEngine.psd1 -Force
$recipient = Read-Host 'Destinataire public age1...'
$parameters = @{
    Name = 'VM01-Nightly'
    SourcePath = 'D:\Exports\VM01'
    PrimaryDestination = 'gdrive:BackupCenter'
    ArchiveDirectory = 'E:\BackupArchive'
    OffsiteDestination = 'sftp:BackupCenter'
    Recipient = $recipient
}
try {
    $job = New-BackupJob @parameters
    $queued = Add-BackupJob -Job $job
    $results = @(Start-BackupQueue)
    $results | Select-Object JobId, RunId, Status, ErrorCode
}
catch {
    throw 'Le moteur ne peut pas acceder a la file, au verrou ou aux journaux.'
}
```

`Add-BackupJob` cree automatiquement `Config/backup-queue.json` s'il n'existe pas. Il refuse les doublons d'identifiant. Une definition provient de `New-BackupJob` ; aucune commande PowerShell arbitraire n'est stockee ou executee depuis le JSON.

Pour un pull distant, ajouter `SourceKind = 'Rclone'` et utiliser un `SourcePath` tel que `source:exports/VM01`. Pour exiger un hash distant, ajouter `-RequireRemoteHash` a `New-BackupJob`.

Pour une VM, les [adaptateurs d'hyperviseurs](HYPERVISORS.md) peuvent preparer un export avant le job. Passer leur resultat a `New-BackupJob -ExportResult $export` a la place de SourcePath/SourceKind. Seul un export reussi est accepte ; le job persiste ensuite le chemin local, sans identifiants fournisseur. L'etape Export/Pull copie cet export deja prepare, elle ne redeclenche pas une tache sur l'hyperviseur.

`Start-BackupPipeline -Job $job` lance un job directement, avec le meme verrou d'execution, mais sans enregistrer son resultat dans la file. Utiliser `Add-BackupJob` puis `Start-BackupQueue` pour un suivi persistant.

## Ordre Strict

| Etape | Action et preuve |
| --- | --- |
| Export/Pull | Copie locale ou `rclone copy` dans un dossier de travail prive. Refus des exports sans fichier. |
| Compress & Encrypt | Creation ZIP avec .NET, puis chiffrement par `age --encrypt --recipient ... --output ...`. Mesure de taille et SHA256 de l'artefact chiffre. |
| Upload | `rclone copyto` vers le stockage primaire. Le code retour est controle, mais ce n'est pas encore une verification distante. |
| Archive | Copie de l'artefact chiffre vers l'archive locale, sans ecrasement. |
| Offsite | `rclone copyto` de cette archive vers la destination secondaire. |
| VERIFY | Nouvelle interrogation du fichier exact sur les deux remotes, comparaison taille/hash, controle SHA256 et taille de l'archive locale et de l'artefact source. |

Le nom d'artefact contient l'identifiant du job et un RunId UUID unique : `backup-<JobId>-<RunId>.zip.age`. Les commandes ne font aucun `sync` ni suppression distante. Une etape en echec interrompt le pipeline ; toutes les etapes restantes sont `Skipped`.

La compression et le chiffrement passent par le disque, sans charger l'archive entiere en memoire. Prevoir l'espace pour l'export, le ZIP et le fichier chiffre. Le dossier propre au run est limite au compte courant et a SYSTEM avant toute copie. L'export temporaire et le ZIP sont supprimes dans `finally` ; les artefacts chiffres sont conserves. Une suppression n'est pas un effacement securise du support : utiliser aussi le chiffrement du volume selon les exigences.

## VERIFY Et Success

Le moteur execute apres les transferts :

```text
rclone lsjson --stat --hash -- <remote:chemin/fichier.zip.age>
```

Il exige un objet fichier, le nom attendu et une taille entiere exactement egale a l'artefact chiffre. Une reponse vide, invalide, un repertoire, un objet absent ou une erreur rclone font echouer VERIFY.

Si un hash commun est disponible, il compare le plus fort des algorithmes pris en charge dans cet ordre : SHA-256, SHA-1, MD5. Une valeur invalide ou differente echoue sans repli sur la taille. MD5 et SHA-1 servent ici de controles de transfert, pas de garanties cryptographiques contre un attaquant.

Sans hash commun, la verification utilise la taille et expose explicitement `Method = 'Size'`. Avec `RequireRemoteHash = true`, l'absence de hash echoue avec `RemoteHashUnavailable`. Certains serveurs SFTP ne fournissent pas de hash ; cette politique peut donc refuser une copie pourtant complete. Aucune comparaison par taille seule ne prouve l'identite du contenu.

Seuls les jobs ayant termine les six etapes, VERIFY inclus, et le nettoyage des donnees en clair obtiennent `Status = 'Success'`. Dans les details d'Upload et d'Offsite, `Verified = false` rappelle que ces etapes n'apportent pas la preuve finale : consulter `Steps[5].Details`.

La verification utilise les metadonnees du fournisseur, pas un telechargement integral ni un test de restauration. Elle ne prouve pas que la cle privee est disponible ou que l'export applicatif est coherent. Prevoir des restaurations periodiques. Le moteur n'effectue pas de retry de verification : une visibilite distante retardee provoque un echec conservateur a examiner.

## File Et Exclusion

- FIFO : l'ordre est celui des insertions dans `Jobs`, pas l'ordre alphabetique ou la date modifiable d'un job.
- `Config/backup-engine.run.lock` est detenu pendant toute l'execution d'une file ou d'un pipeline direct. Un second worker est refuse avant tout travail. Toutes les invocations sur cet hote doivent conserver le meme `EngineLockPath`.
- Un verrou distinct, `<QueuePath>.lock`, couvre chaque lecture/modification/ecriture JSON. Les modifications utilisent un fichier temporaire du meme dossier, un flush disque et un remplacement atomique.
- Les producteurs et le monitoring peuvent acceder a la file entre ces transactions courtes. Un conflit echoue immediatement avec `LockBusyOrUnavailable`, sans attente active. Le demandeur doit reessayer ; un conflit pendant la persistance d'un resultat arrete le traitement de facon conservatrice.
- L'etat `Running` et le RunId sont persistes avant la premiere etape. Les changements d'etat de chaque etape sont ensuite enregistres.
- Apres acquisition du verrou d'execution, les anciens jobs `Running` sont marques `Interrupted`, ainsi que leur etape active. Ils ne sont jamais remis automatiquement en attente : certaines copies distantes peuvent deja exister.
- Les jobs `Failed`, `Success` et `Interrupted` ne sont pas relances. Pour un nouvel essai apres diagnostic, creer un nouveau job avec `New-BackupJob` puis l'ajouter a la file.
- Par defaut, un appel traite au plus 100 jobs et s'arrete si la file est vide. `-MaxJobs` ajuste cette limite. Un job en echec n'empeche pas le traitement du prochain job Pending, sauf defaut d'infrastructure ou de persistance.
- Le JSON est limite a 16 Mio et conserve l'historique. Organiser son archivage administratif hors execution avant cette limite. Un fichier corrompu n'est jamais remplace par une file vide.

Les fichiers `.lock` restent presents apres fermeture : seule l'ouverture exclusive fait foi. Ne pas les supprimer pour debloquer un worker. Apres un crash brutal, verifier aussi les processus age/rclone orphelins et les dossiers Work, qui peuvent encore contenir des donnees en clair sous ACL privees, avant de redemarrer. Ce module n'est pas un superviseur de processus persistant ni un systeme de verrous distribues.

## Objets De Monitoring

Chaque resultat est un `PSCustomObject` contenant :

- `JobId`, `RunId`, `Status`, `StartedUtc`, `CompletedUtc`, `ErrorCode`, `CleanupStatus`.
- `ArtifactPath`, `ArchivePath`, `PrimaryPath`, `OffsitePath`.
- `Steps` : six objets avec `Name`, `Status`, `StartedUtc`, `CompletedUtc`, `DurationMs`, `ErrorCode` et `Details`.
- `Steps[5].Details.Primary` et `Offsite` : destination, statut, methode, tailles attendue/reelle, algorithme, hashes attendu/reel et horodatage du controle.

Une verification qui echoue conserve les preuves deja obtenues pour les autres copies. Un job nouvellement reserve peut avoir un tableau `Steps` vide jusqu'au premier evenement du pipeline.

```powershell
$queue = @(Get-BackupQueue)
$queue | Select-Object JobId, Status, UpdatedUtc
if ($queue.Count -gt 0 -and $null -ne $queue[0].Result) {
    $queue[0].Result.Steps |
        Select-Object Name, Status, DurationMs, ErrorCode
}
```

Les statuts de job sont `Pending`, `Running`, `Success`, `Failed`, `Interrupted`. Les etapes ajoutent `Skipped`. Les erreurs metier retournent un resultat Failed ; les erreurs de file, d'audit ou de verrou peuvent lever une exception. L'ordonnanceur doit donc traiter a la fois les exceptions et les objets Failed.

## Parametres Et Journaux

`Start-BackupQueue` accepte `QueuePath`, `WorkDirectory`, `LogDirectory`, `EngineLockPath`, `RclonePath`, `AgePath`, `CommandTimeoutSeconds` et `MaxJobs`. `Start-BackupPipeline` prend les memes options sauf QueuePath/MaxJobs, et exige Job. Le delai par commande externe est de 3600 secondes par defaut, reglable de 1 a 86400. Le processus lance est termine au depassement de delai ; les copies/compressions .NET n'ont pas de delai configurable.

`CommandRunner` est un point d'injection reserve aux tests de confiance, non a exposer dans une API ou un fichier JSON. Il remplace les appels natifs et peut donc fabriquer des reponses ; en production, l'omettre pour utiliser les executables reels.

Les logs `Logs/backup-YYYY-MM-DD.jsonl` contiennent horodatage UTC, composant, JobId, RunId, etape, statut, code d'erreur et PID. Les arguments des commandes, stdout/stderr bruts et valeurs sensibles ne sont pas journalises. Une panne d'audit est bloquante. Le journal et le JSON ne forment pas une transaction commune : un crash peut laisser une derniere trace ou un statut incomplet ; la reprise conservatrice evite alors une fausse reussite.

## Tests

```powershell
.\Scripts\Test-BackupEngine.ps1
.\Scripts\Test-Security.ps1
```

La suite du moteur couvre le FIFO, les ajouts pendant un run, le monitoring, l'exclusion entre processus, la persistance, les etapes interrompues et sautees, les mauvaises tailles/hashes, les objets absents ou incorrects, l'archive alteree, le repli taille et son interdiction, les codes natifs et les timeouts. Les tests executent de vrais processus PowerShell pour le verrouillage et le lanceur, mais simulent age et les fournisseurs rclone dans un dossier temporaire isole. Aucun secret reel ni transfert reseau n'est utilise.
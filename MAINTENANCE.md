# Maintenance Et Alertes

Le module [Modules/Maintenance.psm1](Modules/Maintenance.psm1) expose `Send-TelegramAlert` et `Invoke-RetentionPolicy`. Il utilise le moteur existant pour l'execution bornee de rclone et le verrou commun. Compatible Windows PowerShell 5.1 et PowerShell 7 ; aucune connexion ni suppression n'est effectuee a l'import.

```powershell
Import-Module .\Modules\BackupEngine.psd1
Import-Module .\Modules\Maintenance.psd1
```

## Alertes Telegram

Le parametre `PipelineResult` accepte le resultat de `Start-BackupPipeline`, chaque resultat de `Start-BackupQueue`, ou le champ Result d'un job persiste. Le premier element de Steps en etat Failed/Interrupted determine l'etape exacte. Un echec de nettoyage est signale separement pour ne pas masquer l'erreur initiale. Les erreurs sans etape connue sont explicitement marquees hors etape ; un ancien resultat sans exception n'est pas presente comme s'il en contenait une.

Le moteur conserve maintenant `ErrorRecord` sur le resultat et sur l'etape en echec, ainsi que `CleanupErrorRecord` pour le nettoyage. Ce sont des projections JSON de l'ErrorRecord capture dans catch, pas des objets PowerShell executables : type d'exception, categorie, numero de ligne et message interne avec code d'erreur. Elles survivent au passage par la file JSON. Les messages libres, les objets cibles, la pile, InvocationInfo.Line et les arguments ne sont pas persistes, car ils peuvent contenir des secrets.

L'alerte inclut les identifiants JobId/RunId et, par exemple :

```text
Echec lors de Compress & Encrypt
ErrorRecord: System.InvalidOperationException; Category=OperationStopped; ligne=12; code=ExternalCommandFailed; message libre masque
```

`-ErrorRecord` peut aussi recevoir directement un objet `System.Management.Automation.ErrorRecord`, par exemple depuis catch. Ses details structurels sont projetes de la meme facon. L'alerte ne transmet jamais le message brut de l'exception, meme avec ce parametre ; les types et codes non reconnus sont masques. Les diagnostics natifs age/rclone restent volontairement assainis par le moteur. Cette restriction est necessaire pour ne pas envoyer de mots de passe, tokens ou codes TOTP a Telegram.

### Utilisation

Creer le bot et autoriser son acces au chat selon les regles de votre organisation. Saisir son token directement dans l'invite masquee du script existant :

```powershell
.\Scripts\Set-BackupCenterSecret.ps1 -Name 'Telegram.BotToken'
Import-Module .\Modules\Security.psd1
$token = Get-BackupSecret -Name 'Telegram.BotToken'
$chatId = Read-Host 'Identifiant du chat Telegram autorise'
try {
    $result = Start-BackupPipeline -Job $job
    $delivery = Send-TelegramAlert -PipelineResult $result -BotToken $token -ChatId $chatId
}
finally { $token.Dispose() }
```

`$job` doit etre prepare comme indique dans [BACKUP_ENGINE.md](BACKUP_ENGINE.md). Un appel de pipeline qui leve une exception avant de produire un resultat peut etre signale avec un resultat minimal :

```powershell
try {
    $result = Start-BackupPipeline -Job $job
}
catch {
    $pipelineError = $_
    $failure = [pscustomobject]@{ JobId = $job.Id; Status = 'Failed'; Steps = @() }
    $delivery = Send-TelegramAlert -PipelineResult $failure -ErrorRecord $pipelineError `
        -BotToken $token -ChatId $chatId
    throw
}
```

Le second extrait s'utilise pendant la duree de vie du SecureString. Gerer aussi les erreurs de livraison dans l'ordonnanceur pour qu'elles ne soient pas confondues avec une nouvelle erreur de sauvegarde. Aucun envoi n'est automatique dans le moteur ; pour une file, traiter chaque resultat retourne.

Le POST HTTPS vise uniquement `api.telegram.org`, sans redirection, sans mode Markdown/HTML et avec un delai de 30 secondes par defaut (`TimeoutSeconds`, 1 a 120). Le token est un SecureString fourni par l'appelant, jamais un champ du job ou de la politique de retention. L'API Telegram impose son inclusion dans l'URL : une chaine geree existe temporairement en memoire, meme si le BSTR est efface dans finally. Ne pas activer une trace HTTP/proxy qui journalise cette URL. La fonction ne journalise ni cette URL ni la reponse brute.

Un succes retourne `{ Status = 'Sent'; TimestampUtc = ... }`. Une erreur HTTP, un timeout ou `ok=false` leve une erreur assainie. Il n'y a pas de nouvelle tentative automatique : un timeout peut survenir apres reception par Telegram et un nouvel envoi pourrait dupliquer le message. Les donnees transmises sortent de l'infrastructure vers le chat autorise ; valider cet usage avant activation.

## Politique De Retention

[Config/retention.example.json](Config/retention.example.json) contient deux sources fictives avec des politiques differentes. Le module ne cree ni n'active de politique reelle. Le chemin PolicyPath est obligatoire ; le fichier local usuel `Config/retention.json` est ignore par Git et reste distinct du coffre DPAPI.

Chaque source definit :

| Champ | Signification |
| --- | --- |
| SourceId | GUID stable de regroupement choisi par l'operateur |
| JobIds | Liste des GUID de jobs appartenant a cette source |
| KeepLast | Nombre de versions a conserver par emplacement, entier de 1 a 100000 |
| Locations | Liste des dossiers `{ Kind: Local ou Rclone, Path: ... }` |

Les fichiers produits par le moteur s'appellent `backup-<JobId>-<RunId>.zip.age`. Le moteur ne met pas l'identifiant de VM dans ce nom. La correspondance JobIds/source est donc explicite : recuperer les Id des jobs crees ou les JobId de la file, et ne pas inventer un filtre de nom de VM. Chaque appel a New-BackupJob cree un nouvel Id ; si l'ordonnanceur recree les jobs, il doit maintenir cette liste pour regrouper leur historique. Plusieurs JobIds peuvent appartenir a une source, mais un JobId ne peut appartenir a deux sources de la meme politique. Un job absent de la politique n'est jamais purge.

Les sources peuvent partager un dossier avec des KeepLast differents. Chaque emplacement conserve ses propres N copies ; il ne s'agit pas d'un total reparti entre stockage primaire, archive et offsite. Les policies invalides, les scopes ambigus, les champs inconnus et KeepLast=0 sont refuses avant suppression. Le fichier de politique doit etre protege contre les modifications non autorisees ; il ne doit contenir aucun identifiant secret.

### Execution

Apres preparation d'une politique reelle et controle de ses chemins :

```powershell
$planned = @(Invoke-RetentionPolicy -PolicyPath .\Config\retention.json -WhatIf)
$planned | Select-Object SourceId, Path, Status

# Validation interactive de chaque suppression.
$deleted = @(Invoke-RetentionPolicy -PolicyPath .\Config\retention.json)

# Pour un ordonnanceur autorise, apres validation de la politique.
$deleted = @(Invoke-RetentionPolicy -PolicyPath .\Config\retention.json -Confirm:$false)
```

WhatIf effectue les lectures et acquiert le verrou commun, mais ne supprime aucun fichier et n'ecrit pas le journal de retention. Les sorties sont des objets RunId, OperationId, SourceId, Path, Status : Planned pour WhatIf, Skipped pour un refus, Deleted apres confirmation technique. Aucun candidat signifie aucune sortie. Un echec arrete le traitement et leve une exception ; des suppressions precedentes peuvent deja avoir abouti et restent tracees.

### Selection Et Securite

1. Lecture et validation de toute la politique, puis acquisition de `Config/backup-engine.run.lock`, partage avec le moteur et les exports d'hyperviseurs. Utiliser le meme EngineLockPath pour tous les workers.
2. Inventaire de tous les emplacements AVANT toute suppression. Un emplacement inaccessible ou un inventaire invalide bloque le lancement des suppressions.
3. Scan non recursif des fichiers exactement conformes au nommage du moteur et aux JobIds de la source. Les fichiers ordinaires, autres jobs, sous-dossiers et exports hyperviseur bruts sont ignores. Les dossiers locaux ou ancetres reparse/junction sont refuses ; un fichier cible reparse l'est egalement.
4. Tri par LastWriteTimeUtc local ou ModTime rclone, du plus recent au plus ancien ; le nom departage les dates identiques de facon deterministe. Conservation des N premiers, puis suppression des candidats en commencant par le plus ancien. Une date absente/invalide ou une taille nulle sur une archive cible bloque l'operation.
5. Avant chaque suppression, nouvelle lecture et comparaison de TOUS les fichiers de cette source dans cet emplacement (nom, taille, date), y compris ceux a conserver. Une variation bloque la suppression. Les suppressions distantes utilisent seulement `rclone deletefile -- <chemin exact>`, jamais purge, delete recursif ou wildcard.
6. Apres l'action, nouvelle lecture pour verifier la disparition du seul candidat et la stabilite des autres fichiers. Un code de sortie zero sans disparition n'est pas considere comme un succes.

rclone doit etre installe et ses remotes nommes configures sous le compte du worker. Les listes utilisent `lsjson --files-only --max-depth 1`; les tableaux vides et les dates JSON des deux versions PowerShell sont geres. La sortie est limitee a 16 Mio et chaque commande a 3600 secondes par defaut (`CommandTimeoutSeconds`). CommandRunner est reserve aux tests ou a un appelant de confiance, comme dans le moteur.

Les dates des fichiers ne prouvent pas leur date de sauvegarde : une recopie, une modification externe ou un backend sans ModTime fiable peut changer l'ordre. Les versions historiques internes d'un bucket versionne, snapshots fournisseur, corbeilles et politiques WORM ne sont pas purgees par ce module. Un stockage eventuellement coherent peut retarder la disparition d'un objet : l'action est alors non confirmee et le traitement s'arrete.

La retention ne certifie pas la restaurabilite des N fichiers conserves et ne lit pas les anciens resultats VERIFY. La declencher de preference apres une sauvegarde verifiee, sur des repertoires d'archives dedies, jamais sur un staging ou une source encore necessaire a un job. Les outils externes doivent respecter le meme protocole d'exclusion ; le verrou est local Windows, pas distribue. Une substitution externe entre le dernier controle et la suppression reste possible : proteger les racines, les ACL et les comptes distants. Il n'y a pas de suppression conditionnelle atomique par version distante.

## Journal Durable

Le journal par defaut est `Logs/Maintenance/retention.jsonl`, parametrable avec AuditPath (extension `.jsonl` obligatoire). Il est ouvert sans troncature, avec un seul ecrivain, et jamais inclus dans les candidats ni purge par la maintenance. Les execution suivantes ajoutent des lignes au meme fichier. Chaque ecriture appelle `FileStream.Flush(true)` avant de continuer :

- `DeleteIntent` : intention persistante AVANT toute suppression. Si cette ecriture echoue, le fichier n'est pas supprime.
- `Deleted` : disparition controlee et confirmation persistante APRES suppression.
- `DeleteUnconfirmed` : commande en erreur ou resultat non verifiable. L'objet peut etre encore present OU deja supprime ; inspecter avant toute nouvelle tentative.

Chaque ligne contient les horodatages UTC, RunId, OperationId, SourceId, KeepLast, type et repertoire, nom exact d'archive, taille, date observee, statut, code d'erreur assaini et PID. OperationId relie l'intention et son resultat. Aucune sortie native ni token n'est enregistree. Ne pas mettre de secrets dans les chemins configures.

Une panne apres suppression mais avant confirmation peut laisser seulement DeleteIntent : aucune transaction atomique ne couvre le disque local, rclone et le journal. Cet evenement durable est justement la trace a reconcilier. Une derniere ligne incomplete bloque l'ouverture pour ecriture ; archiver et examiner le journal avant reparation, sans l'effacer automatiquement. Une panne d'audit arrete toutes les suppressions suivantes.

"Permanent" signifie ici persiste sur disque et sans purge automatique, pas inviolable : le module ne peut empecher un administrateur, une panne disque ou une politique externe d'effacer le fichier. Pour une garantie d'archivage reglementaire, placer/collecter ces journaux sur un stockage protege, sauvegarde ou WORM avec sa propre politique de conservation. Restreindre les ACL du dossier d'audit au compte de service et aux administrateurs autorises.

## Tests

```powershell
.\Scripts\Test-Maintenance.ps1
.\Scripts\Test-BackupEngine.ps1
.\Scripts\Test-Hypervisors.ps1
.\Scripts\Test-Security.ps1
```

Les tests de maintenance utilisent uniquement des fichiers temporaires, un token fictif et des doubles HTTP/rclone. Ils couvrent les erreurs et etapes d'alerte, le passage JSON, la retention par source/emplacement, WhatIf, les changements d'inventaire, les chemins incoherents, les suppressions sans effet, les verrous et la persistance du journal. Aucun message Telegram reel ni aucune suppression distante reelle n'est effectue.
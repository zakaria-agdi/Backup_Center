# Integration Des Hyperviseurs

[Modules/Hypervisors.psm1](Modules/Hypervisors.psm1) fournit `Export-ProxmoxVM`, `Export-HyperVVM`, `Export-VMwareVM`, `Get-ProxmoxVMStatus`, `Get-ProxmoxBackupStorage`, `Invoke-ProxmoxBackupTest` et `Get-ProxmoxBackupArtifact`. Le test distant de la [WebUI](WebUI/README.md) impose stockage explicite, snapshot sans suppression et suivi UPID. `Invoke-ProxmoxBackupTest` est synchrone ; le serveur l'execute dans un worker separe. `Get-ProxmoxBackupArtifact` valide une tache terminee et resout son archive sans relancer vzdump, pour la [continuation Pull](PROXMOX_PULL.md). Importer le manifeste :

```powershell
Import-Module .\Modules\Hypervisors.psd1 -Force
Import-Module .\Modules\BackupEngine.psd1 -Force
```

Le module est compatible avec Windows PowerShell 5.1 et PowerShell 7. Les dependances fournisseur doivent elles aussi etre compatibles avec la version de PowerShell utilisee. Elles sont resolues a l'appel de l'adaptateur, pas a l'import du module. Les tests utilisent des doubles : aucun hyperviseur reel ni aucune restauration n'ont ete valides dans cet environnement.

## Contrat Commun

Chaque fonction d'export retourne un seul `PSCustomObject`, sans melanger les sorties natives ou les reponses HTTP :

| Champ | Contenu |
| --- | --- |
| SchemaVersion | `1` |
| ExportId / Provider / VMId | Identifiant unique d'export, fournisseur, identifiant de VM |
| Status | `Success` ou `Failed` a la fin de l'appel |
| Phase | Preparing, Exporting, WaitingForTask, Retrieving, Validating ou Completed selon le fournisseur |
| SourceKind / SourcePath | `Local` et dossier exploitable, uniquement en cas de succes ; SourcePath reste null en echec |
| WorkPath | Dossier propre a l'export, y compris en cas d'echec partiel |
| StartedUtc / CompletedUtc / DurationMs | Horodatages UTC et duree de l'appel |
| TaskId / TaskState | UPID Proxmox et dernier etat connu : Unknown, Running, Stopped ; NotApplicable pour les cmdlets synchrones |
| Consistency | Snapshot, OrderlyShutdown, ProductionCheckpoint ou PoweredOff |
| ErrorCode | Code stable sans message brut du fournisseur |
| Files / TotalBytes | Inventaire relatif avec Size/SHA256 par fichier et taille totale |

`Success` signifie que l'export source et son inventaire local sont termines, pas que la sauvegarde complete ou sa restauration sont validees. La reussite finale reste decidee par `Start-BackupPipeline` apres VERIFY. `Snapshot` Proxmox ne garantit pas a lui seul la coherence applicative ; `PoweredOff` ne prouve pas que l'arret precedent de l'invite etait propre.

Les erreurs d'export retournent `Failed`. Les erreurs de liaison des parametres et d'audit peuvent lever une exception. Le demandeur doit gerer ces deux situations. `Phase` indique ou l'export a echoue ; TaskState est le dernier etat observe, pas une observation permanente du serveur.

## Proxmox VE

### Releve En Lecture Seule

`Get-ProxmoxVMStatus -ApiUri ... -TokenId ... -TokenSecret $secret -Node pve -VMId 9001`
effectue uniquement un GET sur `/nodes/pve/qemu/9001/status/current`. Le secret
est un `SecureString`. La reponse expose Node, VMId, Name, Status, CpuUsage,
MemoryBytes, MaxMemoryBytes, UptimeSeconds et CheckedUtc ; une reponse invalide
leve une exception. Aucun export, arret de VM ni ajout a la file n'est effectue.

Pour ce releve, accorder `VM.Audit` sur `/vms/9001` et verifier les droits effectifs
du compte ET du token si la separation de privileges est active. Les privileges
de sauvegarde ci-dessous ne sont pas requis pour ce simple test. HTTPS avec un
certificat approuve reste obligatoire. Le backend local verifie aussi que le nom
retourne correspond exactement a `srv-app-01`.

### Prerequis

- Un endpoint HTTPS racine, par exemple `https://pve.example.internal:8006/`, avec certificat approuve par Windows. Les URL HTTP, identifiants dans l'URL, chemins supplementaires et redirections sont refuses. Aucun contournement TLS n'est ajoute.
- Un jeton API sous forme d'identifiant `utilisateur@realm!nom` et de secret `SecureString`. Il peut provenir du module Security (DPAPI CurrentUser). La conversion en chaine requise pour l'en-tete HTTP est temporaire ; le tampon BSTR est efface et l'en-tete retire apres chaque requete. Le runtime .NET ne garantit pas l'effacement immediat des copies de chaines gerees.
- Des privileges suffisants pour sauvegarder la VM QEMU, consulter sa configuration, suivre ses taches et leurs logs, lire la configuration et le contenu du stockage et y creer une sauvegarde. Typiquement VM.Backup, VM.Audit, Datastore.Audit et Datastore.AllocateSpace selon la version et les ACL. Verifier les droits effectifs du compte ET du token avec separation de privileges.
- Un stockage fichier `dir`, `nfs`, `cifs` ou `cephfs`. PBS n'est pas un fichier VMA et est refuse avant de lancer vzdump. Les conteneurs LXC ne sont pas pris en charge par cette fonction.
- `DumpDirectory` doit etre le dossier contenant les archives du stockage choisi, accessible au compte Windows du worker, par exemple via un partage SMB du NAS. Il s'agit du dossier `dump`, pas de sa racine parente. La correspondance entre ce chemin Windows et le stockage Proxmox est une responsabilite de deploiement.

L'API REST Proxmox ne fournit pas de telechargement generique d'une archive vzdump sur ces stockages. L'adaptateur utilise donc REST pour la sauvegarde et l'identification, puis copie le fichier depuis ce dossier accessible. Il ne simule pas un endpoint HTTP de telechargement et ne configure ni partage ni montage automatiquement. Sans acces fichier au stockage, il faut preparer un transport distinct avant d'utiliser cet adaptateur.

### Exemple

Les valeurs suivantes sont des exemples a adapter. Saisir le secret directement dans l'invite masquee, jamais dans un job JSON :

```powershell
$token = Read-Host 'Secret du token Proxmox' -AsSecureString
try {
    $parameters = @{
        ApiUri = 'https://pve.example.internal:8006/'
        TokenId = 'backup@pve!worker'
        TokenSecret = $token
        Node = 'pve01'
        VMId = 100
        Storage = 'backup-nas'
        DumpDirectory = '\\nas\pve-backups\dump'
        DestinationDirectory = 'D:\BackupStaging'
        TaskTimeoutSeconds = 3600
        PollIntervalSeconds = 5
    }
    $export = Export-ProxmoxVM @parameters
}
finally { $token.Dispose() }
```

### Execution

Toutes les routes ci-dessous sont relatives a `/api2/json`. Chaque requete utilise `Authorization: PVEAPIToken=utilisateur@realm!nom=secret` ; ce mode ne necessite ni ticket de connexion ni jeton CSRF. Le secret reste un SecureString dans les parametres de la fonction et n'est jamais inclus dans le resultat ou les journaux.

1. Controle du stockage et de la configuration QEMU via REST.
2. `POST /nodes/{node}/vzdump` pour une seule VM, avec storage, mode, compression zstd, `remove=0` et `prune-backups=keep-all=1`. Le module ne purge aucune ancienne sauvegarde.
3. Validation de l'UPID, du noeud et de l'identifiant de VM lorsqu'il est present ; encodage de l'UPID comme segment d'URL.
4. Interrogation de `/nodes/{node}/tasks/{upid}/status` jusqu'a `status=stopped` ET `exitstatus=OK`. Un retour HTTP reussi ou un simple arret de la tache ne suffisent pas.
5. Lecture paginee du log de cette tache pour identifier exactement l'archive creee. Croisement avec le volid et la taille du contenu du stockage. Le fichier le plus recent du dossier n'est jamais choisi par approximation.
6. Copie locale de cette archive, controle de taille contre l'API et comparaison SHA256 entre fichier accessible et copie. Les archives sources sont conservees.

L'appel est synchrone : la boucle continue tant que `status=running`, meme si un champ `exitstatus=OK` est present prematurement. Une reponse vide, un etat inconnu ou un etat `stopped` sans resultat exploitable produit `Failed/ProxmoxInvalidTaskStatus`. Un resultat final different de `OK` produit `Failed/ProxmoxTaskFailed`. Aucun log d'archive ni contenu du stockage n'est consulte apres un echec de suivi ; `SourcePath` reste null et `New-BackupJob -ExportResult` refuse le resultat, ce qui bloque la compression du pipeline. La compression zstd effectuee par vzdump lui-meme fait partie de la tache distante attendue.

`-Mode snapshot` est le defaut. Configurer et verifier le QEMU guest agent et les mecanismes de gel applicatif/VSS si necessaires. Le mode snapshot seul n'est pas une promesse de coherence de base de donnees. `-Mode stop -AllowGuestShutdown` autorise explicitement le mode vzdump avec arret propre et interruption de service. Le module ne change pas la configuration de l'invite et ne force aucun arret lui-meme.

`TaskTimeoutSeconds` vaut 3600 (1 a 86400) et couvre le declenchement et le suivi de la tache. `PollIntervalSeconds` vaut 5 (1 a 60). Chaque requete HTTP est bornee a 60 secondes au maximum, et au temps restant pendant le suivi. Le parcours du log est limite a 100000 lignes. Une evolution du format du log non reconnue produit un echec conservateur.

Une expiration ou une perte reseau n'annule PAS la tache Proxmox. `TaskId` reste disponible si l'UPID a ete recu ; `TaskState=Unknown` signifie notamment que le POST a pu etre accepte sans reponse exploitable. Examiner le serveur avant tout nouvel essai, sans relancer aveuglement le POST. Le verrou Windows ne peut pas arreter une tache distante orpheline.

Les disques marques `backup=0` et les limitations de vzdump restent applicables. Le controle SHA256 porte sur le fichier fourni par le partage configure, pas sur une empreinte cryptographique fournie par Proxmox. Un test de restauration avec `qmrestore` reste necessaire.

## Hyper-V

```powershell
$export = Export-HyperVVM -VMId '11111111-2222-3333-4444-555555555555' `
    -DestinationDirectory 'D:\BackupStaging'
```

Executer sur l'hote Hyper-V local avec le module Windows `Hyper-V` et les droits d'export necessaires. Utiliser un chemin local accessible au service VMMS/SYSTEM. L'adaptateur n'utilise pas de `ComputerName` distant, pour ne pas confondre un chemin de l'hote distant avec un chemin du worker.

La selection se fait par GUID, sans wildcard ni ambiguite de nom. Les cmdlets sont qualifiees `Hyper-V\Get-VM` et `Hyper-V\Export-VM` pour eviter la collision avec Get-VM de PowerCLI. Seuls les etats Running et Off sont acceptes.

L'export synchrone demande explicitement `CaptureLiveState=CaptureDataConsistentState`, qui utilise la technologie des checkpoints de production. Les services d'integration et le support VSS/gel du systeme invite doivent etre fonctionnels. Une erreur native echoue sans tentative de repli en mode crash-consistent. Le module ne modifie pas CheckpointType, ne cree pas de checkpoint nomme persistant et n'appelle aucune commande de suppression de checkpoint.

Un fichier de configuration non vide `.vmcx` ou `.xml` doit etre produit ; tous les fichiers exportes sont ensuite inventories et hashes. Cela ne remplace pas un essai d'import Hyper-V et ne garantit pas la coherence de toutes les applications de l'invite.

## VMware / PowerCLI

Installer une version de PowerCLI compatible avec l'hote et vCenter/ESXi, en particulier `VMware.VimAutomation.Core`. Etablir une connexion explicite, avec certificats approuves et droits d'export OVF. La fonction ne modifie pas la politique de certificats, n'ouvre pas de connexion par defaut et ne deconnecte pas une session appartenant a l'appelant.

```powershell
$server = Connect-VIServer -Server 'vcenter.example.internal' `
    -Credential (Get-Credential) -NotDefault
try {
    $export = Export-VMwareVM -VMId 'VirtualMachine-vm-42' -Server $server `
        -DestinationDirectory 'D:\BackupStaging'
}
finally { Disconnect-VIServer -Server $server -Confirm:$false }
```

L'identifiant est celui de PowerCLI (par exemple VirtualMachine-vm-42), pas le nom d'affichage. Un seul VIServer connecte est obligatoire. Les commandes sont qualifiees `VMware.VimAutomation.Core\Get-VM` et `VMware.VimAutomation.Core\Export-VApp`, avec le serveur explicitement fourni aux deux.

La VM doit deja etre `PoweredOff`. L'adaptateur refuse les VMs en marche ou suspendues ; il ne les arrete pas et ne pretend pas fournir une sauvegarde VMware a chaud. Organiser auparavant un arret propre de l'invite et maintenir cet etat pendant l'export. L'export OVF est synchrone avec manifeste SHA256, dans un dossier unique, sans Force ni ecrasement d'un export existant. Les incompatibilites OVF, disques RDM, chiffrement, vTPM ou licences sont soumises aux restrictions natives de PowerCLI/vSphere.

## Passage Au Pipeline

Utiliser le resultat d'un des exemples precedents :

```powershell
if ($export.Status -ne 'Success') {
    throw ('Export echoue : ' + $export.ErrorCode)
}
$recipient = Read-Host 'Destinataire public age1...'
$jobOptions = @{
    Name = 'VM-Nightly'
    ExportResult = $export
    PrimaryDestination = 'primary:BackupCenter'
    OffsiteDestination = 'offsite:BackupCenter'
    ArchiveDirectory = 'E:\BackupArchive'
    Recipient = $recipient
}
$job = New-BackupJob @jobOptions
$result = Start-BackupPipeline -Job $job
```

`New-BackupJob -ExportResult` refuse un resultat Failed, un contrat inconnu ou un dossier absent, puis produit le job Local habituel. Les jobs existants utilisant SourcePath/SourceKind restent inchanges. Pour la file persistante, remplacer l'appel direct par :

```powershell
$queued = Add-BackupJob -Job $job
$results = @(Start-BackupQueue)
```

L'export fournisseur est execute AVANT la creation du job. La file ne stocke ni token, ni session PowerCLI, ni commande arbitraire, et ne redeclenche pas l'export au traitement. `Export/Pull` du pipeline copie le dossier prepare ; les cinq etapes suivantes restent inchangees. L'inventaire d'export n'est pas une signature ni un verrou contre une modification ulterieure : conserver la source immuable tant que le job est en attente ou en cours. Pour une planification de bout en bout, l'ordonnanceur doit appeler l'adaptateur puis le moteur et gerer leurs resultats respectifs.

## Verrous, Fichiers Et Audit

- Les trois adaptateurs partagent par defaut `Config/backup-engine.run.lock` avec les pipelines et le worker JSON. Un conflit renvoie Failed/LockBusyOrUnavailable avant tout appel fournisseur. Les invocations doivent toutes utiliser le meme EngineLockPath sur le meme hote Windows.
- Le verrou couvre chaque export synchrone, puis est libere avant la creation et l'execution du job. L'ensemble export + pipeline n'est pas une transaction unique. Aucune exclusion distribuee avec les outils d'administration externes n'est garantie.
- Le dossier d'export porte un GUID et recoit une ACL privee compte courant/SYSTEM avant l'ecriture des donnees. Les reparse points produits sont refuses. Proteger aussi les dossiers parents contre les modifications non autorisees.
- Les exports sont en clair. Les exports reussis et partiels sont conserves, y compris apres VERIFY, car le pipeline ne supprime jamais sa source. L'operateur doit gerer leur retention et les supprimer seulement quand leur conservation n'est plus necessaire. WorkPath identifie les restes d'un echec. Prevoir un volume chiffre et suffisamment d'espace.
- Les appels natifs Hyper-V et PowerCLI et les copies/hashes de fichiers sont synchrones, sans timeout global. Ne pas interrompre le processus sans ensuite inspecter les taches et fichiers restants. Le delai TaskTimeoutSeconds ne concerne que le declenchement/suivi Proxmox.
- Les logs `Logs/hypervisors-YYYY-MM-DD.jsonl` tracent ExportId, Provider, Phase, Status, ErrorCode et PID, sans token, identifiant de session, reponse REST ni erreur brute du fournisseur. Une panne d'audit est bloquante. Les resultats complets sont disponibles au retour de l'appel ; les phases sont tracees pendant son execution.

## Verification

```powershell
.\Scripts\Test-Hypervisors.ps1
.\Scripts\Test-BackupEngine.ps1
.\Scripts\Test-Security.ps1
```

Les 81 assertions isolees couvrent le releve Proxmox en lecture seule, les contrats natifs et REST avec doubles, l'UPID, le polling borne et repete sans nouveau POST, les reponses de statut incompletes, le blocage de la compression apres echec de suivi, la pagination du log, les fichiers manquants, les mauvaises tailles, le refus PBS, la coherence demandee a Hyper-V, le refus des VMs VMware actives, les ACL, les erreurs d'audit, la protection des tokens et le passage des trois exports dans le pipeline et la file. Ils n'installent aucun outil fournisseur, ne contactent aucun serveur et n'utilisent aucun secret reel. Une recette sur les versions et stockages cibles, suivie d'une restauration, est requise avant exploitation.
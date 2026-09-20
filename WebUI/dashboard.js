"use strict";

lucide.createIcons({ attrs: { "aria-hidden": "true" } });

document.getElementById("theme-toggle").addEventListener("click", () => {
  const isAqua = document.documentElement.dataset.theme === "aqua";
  document.documentElement.dataset.theme = isAqua ? "emerald" : "aqua";
  document.getElementById("theme-name").textContent = isAqua ? "Emerald" : "Aqua";
  document.getElementById("theme-toggle").setAttribute(
    "aria-label", `Switch accent color to ${isAqua ? "aqua" : "emerald"}`
  );
});

const element = (id) => document.getElementById(id);
const text = (id, value) => { element(id).textContent = value; };
const date = (value) => value ? new Date(value).toLocaleString("fr-FR") : "Jamais";
const states = {
  NotConfigured: "Token absent", NotChecked: "Non testee", Connected: "Dernier test reussi",
  Failed: "Echec du dernier test", CredentialsUnavailable: "Token inaccessible"
};
const statuses = { Pending: "En attente", Submitting: "Soumission", Running: "En cours", Success: "Reussi", Failed: "Echec", Unknown: "A verifier sur Proxmox", Interrupted: "Interrompu", Skipped: "Non execute" };
const errors = {
  InvalidCredentials: "Format du token invalide.", CredentialsRequired: "Token requis.",
  ProxmoxConnectionFailed: "Connexion Proxmox impossible : verifier reseau, certificat TLS et droits du token.",
  UnexpectedVM: "La VM retournee ne correspond pas a srv-app-01. Test refuse.",
  ProbeCooldown: "Attendre 5 secondes entre deux tests.",
  BackupTestActive: "Un test est actif ou incertain. Verifier son etat sur Proxmox avant toute nouvelle sauvegarde.",
  InvalidBackupTest: "Choisir un stockage et confirmer la sauvegarde snapshot.",
  BackupStorageUnavailable: "Stockage inactif, plein ou incompatible avec les sauvegardes.",
  ProxmoxTaskFailed: "La tache vzdump a echoue. Consulter son journal dans Proxmox.",
  ProxmoxTaskTimeout: "Delai de suivi depasse. La sauvegarde peut continuer sur Proxmox.",
  TransferConfigurationRequired: "Configuration SSH et destination rclone absentes.",
  SuccessfulBackupRequired: "Un vzdump termine avec succes est requis.",
  TransferAlreadyRequested: "Ce transfert a deja ete demande. Actualiser son etat.",
  TaskTokenMismatch: "Le token courant ne correspond pas au proprietaire de l'UPID.",
  SSHFilesRequired: "Cle SSH ou fichier known_hosts absent.",
  PullSizeMismatch: "La taille du fichier rapatrie ne correspond pas a l'archive Proxmox.",
  ExternalCommandFailed: "Transfert refuse ou interrompu. Verifier SSH, known_hosts et la configuration rclone.",
  ArchiveEncryptionFailed: "Chiffrement interrompu. Verifier espace disque et acces DPAPI.",
  RequestRejected: "Requete refusee. Actualiser la page avant de reessayer.",
  OperationUnavailable: "Operation indisponible. Verifier les fichiers locaux et leurs permissions."
};
let nonce = null;
let dashboard = null;
let busy = false;
let selectedJob = null;
let pollTimer = null;
let refreshing = false;
let lastTransferLog = "";
let transferRequest = null;

function backupActive() {
  return (dashboard?.BackupTest && !["Success", "Failed"].includes(dashboard.BackupTest.Status)) ||
    (dashboard?.Transfer && !["Success", "Failed"].includes(dashboard.Transfer.Status));
}

function controls() {
  element("credential-fields").disabled = busy || !nonce || backupActive();
  element("test-proxmox").disabled = busy || !nonce || !dashboard?.CredentialsConfigured;
  element("refresh").disabled = busy;
  const unavailable = busy || !nonce || !dashboard?.CredentialsConfigured || backupActive();
  element("load-storages").disabled = unavailable;
  element("backup-storage").disabled = unavailable || element("backup-storage").options.length < 2;
  element("backup-confirm").disabled = unavailable || !element("backup-storage").value;
  element("start-backup").disabled = unavailable || !element("backup-storage").value || !element("backup-confirm").checked;
  element("start-transfer").disabled = unavailable || dashboard?.BackupTest?.Status !== "Success" ||
    !dashboard?.TransferConfigured || Boolean(dashboard?.Transfer);
}

async function api(path, data) {
  const headers = { "X-BackupCenter-Client": "dashboard" };
  const options = { headers, cache: "no-store", credentials: "omit", redirect: "error", signal: AbortSignal.timeout(25000) };
  if (data !== undefined) {
    options.method = "POST";
    headers["Content-Type"] = "application/json";
    headers["X-BackupCenter-CSRF"] = nonce;
    options.body = JSON.stringify(data);
  }
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(errors[result.ErrorCode] || "Operation refusee par le serveur.");
  return result;
}

function pipeline(job) {
  text("pipeline-job", job ? job.Name : "Aucun travail selectionne");
  document.querySelectorAll(".pipeline-step").forEach((step) => {
    const remote = job?.Kind === "ProxmoxBackupTest";
    const status = job?.Steps?.find((record) => record.Name === step.dataset.step)?.Status || (remote ? "Skipped" : null);
    step.dataset.status = status ? status.toLowerCase() : "idle";
    step.querySelector("p").textContent = remote && step.dataset.step === "Export/Pull"
      ? (status === "Success" ? "Export termine / Pull non effectue" : `${statuses[status] || "En attente"} / Export distant`)
      : statuses[status] || "Non demarre";
    const icon = status === "Running" ? "loader-circle" : status === "Success" ? "check" : status === "Failed" ? "circle-x" : status === "Unknown" ? "triangle-alert" : "minus";
    const symbol = document.createElement("i");
    symbol.dataset.lucide = icon;
    step.querySelector(".pipeline-icon").replaceChildren(symbol);
  });
  lucide.createIcons({ attrs: { "aria-hidden": "true" } });
}

function render(data) {
  const probe = data.Proxmox;
  const vm = probe.VM;
  text("overview-title", data.Target.Name);
  text("target-id", `VM ${data.Target.VMId}`);
  text("target-api", data.Target.ApiUri);
  text("target-node", data.Target.Node);
  text("backup-target", `${data.Target.Name} / VM ${data.Target.VMId}`);
  const test = data.BackupTest;
  text("last-backup-storage", test?.Storage || "Aucun");
  if (test) {
    const outcome = test.Status === "Success" ? (data.Transfer ? "Export distant termine." : "Export distant termine. Pull non effectue.")
      : test.Status === "Unknown" ? "Etat incertain : verifier la tache sur Proxmox. Relance bloquee."
      : test.Status === "Failed" ? (errors[test.ErrorCode] || "Test echoue. Verifier les droits VM.Backup, Datastore.AllocateSpace et les journaux Proxmox.")
      : `${statuses[test.Status]} : ${test.PollCount} lecture(s) du statut Proxmox.`;
    text("backup-status", outcome);
    text("backup-task", test.TaskId ? `UPID : ${test.TaskId}` : "");
  }
  const transfer = data.Transfer;
  text("transfer-status", transfer ? (transfer.Status === "Success" ? "Archive chiffree envoyee."
    : transfer.Status === "Unknown" ? "Etat du transfert incertain. Verification operateur requise."
    : transfer.Status === "Failed" ? (errors[transfer.ErrorCode] || "Transfert interrompu. Verification operateur requise.")
    : `Transfert : ${statuses[transfer.Status] || "Inconnu"}`)
    : data.TransferConfigured ? "Configuration de transfert chargee." : "Configuration SSH / rclone absente.");
  const progress = transfer?.Progress;
  const allowedSteps = ["Export/Pull", "Compress & Encrypt", "Upload"];
  const validProgress = progress && allowedSteps.includes(progress.Step) &&
    [progress.Bytes, progress.TotalBytes, progress.BytesPerSecond].every((value) => Number.isFinite(value) && value >= 0);
  const detail = validProgress ? `${progress.Step} : ${(progress.Bytes / 1048576).toFixed(1)} / ${(progress.TotalBytes / 1048576).toFixed(1)} Mio | ${(progress.BytesPerSecond / 1048576).toFixed(2)} Mio/s` : "";
  text("transfer-progress", detail);
  const transferLog = transfer ? `${statuses[transfer.Status] || "Inconnu"}${detail ? ` | ${detail}` : ""}` : "";
  if (transferLog && transferLog !== lastTransferLog) {
    console.info(`[Backup Center] ${transferLog}`);
    lastTransferLog = transferLog;
  }
  text("queue-status", transfer ? "Continuation : Pull, chiffrement, upload" : "Pipeline complete non lancee");
  text("credential-state", data.CredentialsConfigured ? "Token enregistre" : "Token non configure");
  text("probe-state", states[probe.State] || "Etat inconnu");
  text("probe-time", date(probe.CheckedUtc));
  text("vm-state", vm ? (vm.Status === "running" ? "En marche" : "Arretee") : "Inconnu");
  text("vm-cpu", vm ? `${(vm.CpuUsage * 100).toFixed(1)} %` : "--");
  text("vm-memory", vm ? `${(vm.MemoryBytes / 1073741824).toFixed(2)} Gio` : "--");
  text("vm-memory-total", vm ? `Sur ${(vm.MaxMemoryBytes / 1073741824).toFixed(2)} Gio` : "Capacite inconnue");
  text("vm-uptime", vm ? `${Math.floor(vm.UptimeSeconds / 86400)} j ${Math.floor(vm.UptimeSeconds % 86400 / 3600)} h ${Math.floor(vm.UptimeSeconds % 3600 / 60)} min` : "--");
  text("dashboard-updated-at", date(data.ServerUtc));
  text("connection-status", "API locale disponible");
  element("dashboard-updated-at").dateTime = data.ServerUtc;
  const jobs = data.Jobs;
  text("queue-count", `${jobs.length} travail(aux) affiche(s)`);
  element("queue-items").replaceChildren();
  if (!jobs.length) {
    const empty = document.createElement("li");
    empty.className = "supporting-text";
    empty.textContent = "Aucun travail dans la file.";
    element("queue-items").append(empty);
  }
  if (!jobs.some((job) => job.Id === selectedJob)) selectedJob = jobs.find((job) => job.Status === "Running")?.Id || jobs[0]?.Id;
  jobs.forEach((job) => {
    const item = document.createElement("li");
    item.className = "queue-item";
    item.dataset.status = job.Status.toLowerCase();
    const button = document.createElement("button");
    button.type = "button";
    button.className = "queue-copy";
    button.setAttribute("aria-pressed", String(job.Id === selectedJob));
    const name = document.createElement("span");
    name.className = "queue-name";
    name.textContent = job.Name;
    const status = document.createElement("span");
    status.className = "queue-state";
    status.textContent = statuses[job.Status] || "Inconnu";
    button.append(name, status);
    button.addEventListener("click", () => { selectedJob = job.Id; render(dashboard); });
    item.append(button);
    element("queue-items").append(item);
  });
  pipeline(jobs.find((job) => job.Id === selectedJob));
}

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    if (!nonce) nonce = (await api("/api/session")).Nonce;
    dashboard = await api("/api/dashboard");
    render(dashboard);
  } catch {
    nonce = null;
    text("connection-status", "API locale indisponible - donnees non actualisees");
    throw new Error("Serveur local inaccessible. Actualiser pour reessayer.");
  } finally {
    refreshing = false;
    controls();
    clearTimeout(pollTimer);
    if (["Pending", "Submitting", "Running"].includes(dashboard?.BackupTest?.Status) ||
      ["Pending", "Running"].includes(dashboard?.Transfer?.Status)) {
      pollTimer = setTimeout(() => { if (busy) { pollTimer = setTimeout(() => refresh().catch(() => {}), 2000); } else { refresh().catch(() => {}); } }, 2000);
    }
  }
}

async function action(callback) {
  if (busy) return;
  busy = true;
  controls();
  try { await callback(); }
  catch (error) { text("auth-status", error.message); }
  finally { busy = false; controls(); }
}

element("refresh").addEventListener("click", () => action(refresh));
element("login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (busy || !nonce) return;
  const credentials = { TokenId: element("token-id").value.trim(), TokenSecret: element("token-secret").value };
  element("token-secret").value = "";
  action(async () => {
    text("auth-status", "Enregistrement...");
    try {
      await api("/api/proxmox/credentials", credentials);
      element("token-id").value = "";
      text("auth-status", "Token enregistre. Aucun test lance.");
    } finally {
      credentials.TokenSecret = "";
      credentials.TokenId = "";
      await refresh();
    }
  });
});
element("test-proxmox").addEventListener("click", () => action(async () => {
  text("auth-status", "Test Proxmox en cours...");
  try {
    await api("/api/proxmox/test", {});
    text("auth-status", "VM confirmee. Aucune sauvegarde lancee.");
  } finally { await refresh(); }
}));
element("backup-storage").addEventListener("change", () => { element("backup-confirm").checked = false; controls(); });
element("backup-confirm").addEventListener("change", controls);
element("load-storages").addEventListener("click", () => action(async () => {
  text("backup-status", "Lecture des stockages Proxmox...");
  try {
    const result = await api("/api/proxmox/storages", {});
    element("backup-storage").replaceChildren(new Option("Choisir un stockage", ""));
    result.Storages.forEach((storage) => {
      element("backup-storage").add(new Option(`${storage.Name} (${(storage.AvailableBytes / 1073741824).toFixed(1)} Gio libres)`, storage.Name));
    });
    element("backup-confirm").checked = false;
    text("backup-status", result.Storages.length ? "Stockages disponibles. Aucune sauvegarde lancee." : "Aucun stockage de sauvegarde accessible avec de l'espace libre.");
  } catch (error) { text("backup-status", error.message); }
}));
element("backup-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (element("start-backup").disabled) return;
  const request = { Storage: element("backup-storage").value, Confirmation: `SNAPSHOT ${dashboard.Target.VMId}`,
    RequestId: crypto.randomUUID(), PreviousId: dashboard.BackupTest?.Id || "" };
  element("backup-confirm").checked = false;
  action(async () => {
    try {
      text("backup-status", "Soumission du test...");
      const accepted = await api("/api/proxmox/backup-test", request);
      selectedJob = accepted.Id;
    } catch (error) { text("backup-status", `${error.message} Actualiser pour verifier la prise en charge avant de reessayer.`); }
    finally { await refresh(); }
  });
});
element("start-transfer").addEventListener("click", () => {
  if (element("start-transfer").disabled) return;
  if (!transferRequest || transferRequest.BackupId !== dashboard.BackupTest.Id) {
    transferRequest = { BackupId: dashboard.BackupTest.Id, RequestId: crypto.randomUUID(), Confirmation: `TRANSFER ${dashboard.Target.VMId}` };
  }
  action(async () => {
    try {
      await api("/api/proxmox/transfer", transferRequest);
      selectedJob = transferRequest.BackupId;
    } catch (error) { text("transfer-status", error.message); }
    finally { await refresh(); }
  });
});
action(refresh);
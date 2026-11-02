# NewAuditroV2 — Framework d'audit Active Directory & infrastructure Windows / Linux

> Framework PowerShell modulaire pour auditer un SI Windows : comptes AD (Tier 0, standards, Microsoft 365), groupes, stratégies de mot de passe affinées (PSO), silos d'authentification, OU, GPO, permissions NTFS, VMs, postes, hyperviseurs Hyper-V et réplication AD. Une brique de reconnaissance réseau (Nmap) permet d'auditer à distance les machines découvertes via WinRM, PsExec ou SSH (Linux). Les CSV collectés sont injectés dans des classeurs Excel formatés par `Process_excels.py`.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Structure du projet](#structure-du-projet)
- [Utilisation](#utilisation)
- [Modules d'audit](#modules-daudit)
- [Reconnaissance et audit distant](#reconnaissance-et-audit-distant)
- [Sorties](#sorties)
- [Génération des Excel](#génération-des-excel)
- [Configuration](#configuration)
- [Ajouter un module](#ajouter-un-module)
- [Compatibilité](#compatibilité)

---

## Fonctionnalités

- **Audit local ou distant** : sur la machine courante, ou sur les cibles découvertes par la reconnaissance (WinRM, repli PsExec pour Windows, SSH pour Linux).
- **Reconnaissance réseau** : découverte Nmap, scan de ports, détection d'OS, validation machine par machine avant toute action distante.
- **Prérequis automatiques** : `init.ps1` vérifie et installe les outils RSAT nécessaires (serveur membre ou poste), Microsoft.Graph et PsExec (avec repli hors ligne via `Tools\`). Npcap reste interactif. Aucun prérequis n'est bloquant.
- **Exports Excel structurés** : chaque CSV est injecté dans un template formaté (couleurs d'alerte, feuille Légende). Les templates manquants sont générés automatiquement.
- **Synthèse avec KPI** : un classeur `Synthese_Audit.xlsx` donne une note globale, une note par thème, une quarantaine d'indicateurs et le top des risques avec recommandations.
- **Logging complet** : transcript PowerShell global, log par script et logs Nmap par étape.
- **Modulaire** : un script par module, numéroté pour fixer l'ordre d'exécution, sélectionnable par menu ou en paramètre.

---

## Prérequis

### Machine qui lance le framework

| Composant | Version minimale | Installé automatiquement |
|---|---|---|
| Windows Server / Windows 10+ | — | — |
| PowerShell | 5.1+ | — |
| Outils RSAT (AD, GPMC, DFS) | — | ✅ via `init.ps1`, après confirmation (voir plus bas) |
| Microsoft.Graph | 2.x | ✅ via `init.ps1` (si `12_Audit_Comptes_365` sélectionné) |
| Nmap | 7.99 (portable) | Fourni dans `Tools\Nmap\` |
| Npcap | 1.88 | ❌ installeur interactif lancé par `init.ps1` |
| PsExec | — | ✅ via `init.ps1` (ou `Tools\PsExec64.exe` / `Tools\PSTools.zip`) |
| Client SSH | — | OpenSSH installé si absent, sinon `Tools\plink.exe` |

> Python et openpyxl ne sont **pas** nécessaires aux audits. Ils ne servent qu'à `Process_excels.py` (voir [Génération des Excel](#génération-des-excel)), qui peut tourner sur une autre machine.

### Outils RSAT

Sur un contrôleur de domaine, tout est déjà présent. Sur un serveur membre ou un poste du domaine, `init.ps1` vérifie les outils nécessaires **aux scripts sélectionnés**, liste ceux qui manquent et propose de les installer (confirmation `[O/N]`). Sans eux, les scripts concernés s'ignorent ou se limitent à l'audit local.

| Outil | Scripts concernés | Serveur (`Install-WindowsFeature`) | Poste (`Add-WindowsCapability`) |
|---|---|---|---|
| Module ActiveDirectory | `10_`, `11_`, `13_`, `14_`, `15_`, `32_`, `33_` | `RSAT-AD-PowerShell` | `Rsat.ActiveDirectory.DS-LDS.Tools` |
| repadmin | `21_`, `30_` | `RSAT-ADDS-Tools` | `Rsat.ActiveDirectory.DS-LDS.Tools` |
| Module GroupPolicy (GPMC) | `32_`, `33_` (colonne `ReferenceGPO`) | `GPMC` | `Rsat.GroupPolicy.Management.Tools` |
| Module DFSN | `31_` (partages DFS) | `RSAT-DFS-Mgmt-Con` | `Rsat.FileServices.Tools` |

- Sur un poste, les RSAT sont des « Features on Demand » : il faut un accès Internet, ou un WSUS autorisé à les distribuer. Sinon, les installer depuis l'ISO Features on Demand.
- Machine hors domaine : la vérification est ignorée.
- Mode non interactif (`AUDIT_NONINTERACTIVE=1`) : rien n'est installé, les absences sont seulement signalées.
- Le rôle Hyper-V, nécessaire à `20_Audit_Hyperviseurs`, n'est pas un RSAT : ce script ne tourne que sur un hôte Hyper-V.

### Cibles distantes

| Méthode | Conditions |
|---|---|
| WinRM | `Enable-PSRemoting -Force`, ports 5985/5986, compte administrateur local ou de domaine |
| PsExec (repli sans WinRM) | SMB/445 et partage `C$` accessibles, compte Admin du domaine |
| SSH (Linux) | Port 22, compte avec accès shell |

---

## Installation

### 1. Cloner le dépôt

```powershell
git clone https://github.com/<votre-org>/NewAuditroV2.git
cd NewAuditroV2
```

### 2. Vérifier Nmap et Npcap

Si la version de Nmap du dépôt n'est pas à jour, télécharger la version **zip** (pas l'installeur) sur [nmap.org/download.html](https://nmap.org/download.html) et l'extraire dans `Tools\Nmap\`.

Même chose pour Npcap : télécharger l'installeur sur [npcap.com](https://npcap.com/#download), le renommer `npcap-installer.exe` et le placer dans `Tools\Nmap\`.

Fichiers nécessaires :

```
Tools\
└─ Nmap\
    ├─ nmap.exe
    ├─ npcap-installer.exe
    ├─ ncat.exe
    ├─ nping.exe
    ├─ libcrypto-3.dll
    ├─ libssl-3.dll
    ├─ libssh2.dll
    ├─ zlibwapi.dll
    ├─ nmap-os-db
    ├─ nmap-services
    ├─ nmap-service-probes
    ├─ nmap-mac-prefixes
    ├─ nmap-protocols
    ├─ nmap-rpc
    ├─ nse_main.lua
    ├─ scripts\
    └─ nselib\
```

### 3. Machines sans Internet (optionnel)

| Fichier à déposer | Usage |
|---|---|
| `Tools\PsExec64.exe` ou `Tools\PSTools.zip` | PsExec hors ligne |
| `Tools\plink.exe` | Client SSH si OpenSSH ne peut pas être installé |

Les RSAT d'un poste sans Internet s'installent depuis l'ISO Features on Demand de la version de Windows concernée.

### 4. Lancer

```powershell
# Depuis la racine du projet
.\main.ps1
```

`main.ps1` se relance automatiquement en administrateur (UAC) si besoin, puis exécute `init.ps1` pour vérifier les prérequis.

### 5. Sur la machine qui produira les Excel

```powershell
python -m pip install openpyxl
```

Python 3.10+ et openpyxl suffisent. Cette machine peut être différente de celle qui collecte (par exemple ton poste, en y copiant `Temp_CSV\`).

---

## Structure du projet

```
NewAuditroV2\
├─ main.ps1                             ← orchestrateur (menu, exécution, résumé)
├─ init.ps1                             ← prérequis : RSAT, Microsoft.Graph, Npcap, PsExec
├─ Process_excels.py                    ← injection CSV → Excel
├─ Synthese_audit.py                    ← Excel de synthèse (KPI, scores, top risques)
├─ modules_config.json                  ← correspondance CSV → template / feuille / classeur
├─ Scripts\
│   ├─ PowerShell\
│   │   ├─ 00_Reconnaissance.ps1       ← scan réseau + audit distant (WinRM / PsExec / SSH)
│   │   ├─ 10_Audit_comptes_T0.ps1      ← comptes Tier 0 (adminCount=1)
│   │   ├─ 11_Audit_comptes.ps1         ← comptes AD hors T0, ou comptes locaux
│   │   ├─ 12_Audit_Comptes_365.ps1     ← comptes Microsoft 365 (Graph)
│   │   ├─ 13_Arborescence_OU.ps1       ← arborescence des OU
│   │   ├─ 14_Audit_PSO.ps1             ← stratégies de mot de passe affinées
│   │   ├─ 15_Audit_Silos.ps1           ← silos et stratégies d'authentification
│   │   ├─ 20_Audit_Hyperviseurs.ps1    ← inventaire Hyper-V
│   │   ├─ 21_Audit_VMs.ps1             ← inventaire serveur / VM
│   │   ├─ 22_Audit_Workstation.ps1     ← inventaire poste (même schéma que les VMs)
│   │   ├─ 23_Audit_Linux.ps1           ← marqueur (l'audit Linux est fait par la reconnaissance)
│   │   ├─ 30_Audit_Replication.ps1     ← réplication AD (dépend de 21_)
│   │   ├─ 31_Audit_NTFS.ps1            ← droits NTFS et de partage
│   │   ├─ 32_Audit_GPO.ps1             ← inventaire des GPO
│   │   └─ 33_Audit_Groupes.ps1         ← groupes AD (dépend de 31_ pour le croisement NTFS)
│   └─ Python\
│       └─ Template*.py                 ← générateurs des templates Excel
├─ Templates_Excel\                     ← templates .xlsx (générés par Process_excels.py)
├─ Tools\                               ← Nmap, Npcap, PsExec, plink
├─ Temp_CSV\                            ← CSV collectés (voir Sorties)
├─ Excel\                               ← classeurs finaux
└─ Logs\                                ← transcripts et logs Nmap
```

---

## Utilisation

### Lancement standard

```powershell
.\main.ps1
```

Déroulement :

1. Élévation automatique en administrateur si nécessaire.
2. Menu de sélection (si `-Include` n'est pas fourni).
3. `init.ps1` : vérification des prérequis des scripts sélectionnés (RSAT, Graph, Npcap, PsExec), avec installation proposée. Un prérequis manquant n'arrête pas l'audit.
4. Récapitulatif des scripts et confirmation `[O/N]`.
5. Exécution dans l'ordre des numéros. `00_Reconnaissance` et `31_Audit_NTFS` tournent dans un processus console dédié (saisies interactives), les autres dans un processus séparé dont la sortie est journalisée.
6. Résumé (statut, code de retour, durée de chaque script).

### Menu

| Choix | Contenu |
|---|---|
| 1 | Tous les scripts |
| 2 | Bundle Comptes : `10_`, `11_`, `12_`, `14_`, `15_` |
| 3 | Bundle SI : `13_`, `20_`, `21_`, `30_` |
| 4 | Bundle AD : `10_`, `11_`, `13_`, `14_`, `15_`, `31_`, `32_`, `33_` |
| 5 | Reconnaissance seule : `00_` |
| 6 | Sélection manuelle (numéros séparés par des virgules, ex. `10,31,33`) |

### Paramètres de `main.ps1`

```powershell
# Sélection sans menu
.\main.ps1 -Include "10_*,33_*"

# Exclure des scripts
.\main.ps1 -Include "*.ps1" -Exclude "main.ps1,00_*,12_*"

# Ne pas relancer init.ps1
.\main.ps1 -SkipInit

# Arrêter au premier script en erreur
.\main.ps1 -StopOnErr

# Simulation : liste les scripts sans les exécuter
.\main.ps1 -DryRun
```

### Désactiver un script

Préfixer le nom du fichier par `_` : il est ignoré par `main.ps1` dans tous les cas (menu, bundles, y compris « Tous les scripts », et `-Include`). Retirer le `_` pour le réactiver.

```powershell
Rename-Item "Scripts\PowerShell\00_Reconnaissance.ps1" "00_Reconnaissance.ps1"   # désactiver
Rename-Item "Scripts\PowerShell\00_Reconnaissance.ps1" "00_Reconnaissance.ps1"   # réactiver
```

Le commentaire `# AUDIT: disabled` dans les 15 premières lignes d'un script a le même effet sans le renommer.

---

## Modules d'audit

### `10_Audit_comptes_T0.ps1`
Comptes avec `adminCount=1` (Tier 0) sur un DC, ou comptes locaux sur une machine hors domaine. Colonnes : nom, type, date de création, actif, réglage du mot de passe, date de désactivation, description, dernier changement de mot de passe, groupes, services et tâches planifiées exécutés sous le compte.

### `11_Audit_comptes.ps1`
Tous les comptes AD hors Tier 0, ou comptes locaux. Mêmes colonnes que `10_`, sans la date de création. Les deux modules sont regroupés dans un seul Excel.

La colonne `DerniereConnexion` (10_ et 11_) vient de `lastLogonTimestamp`, répliqué entre DC avec une précision d'environ 14 jours ; pour les comptes locaux, de `LastLogon`. Dans l'Excel des comptes M365, elle reprend la date de dernière connexion Entra ID.

### `12_Audit_Comptes_365.ps1`
Comptes Microsoft 365 via `Connect-MgGraph` : UPN, licences, dernière connexion, dernier changement de mot de passe, date de création.

> ⚠️ Authentification Graph interactive. Jamais exécuté sur les cibles distantes.

### `13_Arborescence_OU.ps1`
Fichier texte représentant l'arborescence des OU du domaine.

### `14_Audit_PSO.ps1`
Stratégies de mot de passe affinées (Fine-Grained Password Policies). Deux sorties :

- **PSO** : une ligne par cible. La politique par défaut du domaine sert de ligne de référence. Pour chaque PSO : précédence, longueur, historique, complexité, chiffrement réversible, âges, verrouillage, nombre de comptes pour lesquels elle s'applique réellement (`msDS-ResultantPSO`). Pour chaque cible : type, OU, nombre d'utilisateurs.
- **Comptes** : politique effective de chaque utilisateur.

Alertes : réglages sous les seuils (longueur < 12, historique < 12, réglables en tête de script), précédence en doublon, PSO sans cible, cible vide ou introuvable, cible sur laquelle la PSO est ignorée (groupe non global ou de distribution), compte T0 sans PSO.

### `15_Audit_Silos.ps1`
Silos et stratégies d'authentification (niveau fonctionnel 2012 R2 minimum). Deux sorties :

- **Silos** : une ligne par compte, avec le mode (Appliqué / Audit), les stratégies associées et les colonnes `Autorise` / `Assigne` (un compte n'est réellement dans un silo que s'il est les deux). Un bloc final « (Aucun silo) » liste les comptes T0 actifs hors de tout silo.
- **Politiques** : une ligne par stratégie, avec les durées de vie TGT, les conditions d'authentification (SDDL rendu lisible, SID traduits en noms), les silos et comptes qui l'utilisent.

Alertes : mode audit, silo vide ou sans stratégie, compte autorisé mais non assigné (ou l'inverse), stratégie non utilisée, aucune restriction d'origine, TGT de plus de 240 min.

### `20_Audit_Hyperviseurs.ps1`
Inventaire Hyper-V : IP physiques et vEthernet, MAC, rôles, processeurs, RAM, stockage, VMs hébergées, cluster ou standalone.

### `21_Audit_VMs.ps1`
Inventaire serveur : OS, IP, MAC, numéro de série, rôles, hyperviseur hôte (KVP Hyper-V), WinRM, réplication, activation Windows, rôles FSMO, synchronisation de l'heure.

Colonnes NTP :

- **NTP Type** : `Hierarchie du domaine (NT5DS)`, `Serveur(s) NTP (NTP)`, `Domaine + NTP (AllSync)` ou `Aucune synchronisation (NoSync)`, suivi de `(GPO)` si la configuration vient d'une stratégie de groupe ;
- **NTP Serveur(s)** : serveurs configurés (sans les options `,0x...`) ; non utilisé en NT5DS ;
- **NTP Source** : source réellement utilisée (`w32tm /query /source`), par exemple un DC, un serveur externe ou l'horloge CMOS locale.

> Point de contrôle classique : le DC émulateur PDC doit être en type `NTP` vers une source fiable, et non en `NT5DS` ou sur l'horloge CMOS locale.

### `22_Audit_Workstation.ps1`
Même schéma que `21_` pour les postes Windows. Les champs propres aux serveurs (FSMO, réplication, KVP) valent `-`.

### `23_Audit_Linux.ps1`
Sans action sur Windows. L'audit Linux est réalisé en SSH par `00_Reconnaissance` (voir plus bas).

### `30_Audit_Replication.ps1`
Lit le CSV de `21_Audit_VMs` (dans `VM\`) et contrôle la réplication AD via `repadmin /showrepl`. Le résultat est écrit dans `AD\`.

> Dépendance : `21_Audit_VMs` doit avoir été exécuté avant.

### `31_Audit_NTFS.ps1`
Découvre les partages SMB et DFS, demande lesquels auditer et jusqu'à quelle profondeur, puis exporte les ACL NTFS de chaque dossier et les droits de partage. Génère aussi un schéma de l'arborescence (`.html` interactif et `.txt`). Les liens DFS sont suivis vers leur cible réelle. SYSVOL et NETLOGON sont toujours exclus.

Alertes : ACE de refus, groupe large en écriture, SID orphelin, contrôle total explicite, héritage désactivé.

Variables utiles en mode non interactif : voir [Configuration](#variables-denvironnement).

### `32_Audit_GPO.ps1`
Inventaire des GPO du domaine : créateur, date de création, OU liées, statut, délégations. Les colonnes `Description` et `Utilité` sont à compléter à la main dans l'Excel.

La colonne `Délégation` liste les comptes et groupes ayant un droit de modification sur la GPO, hors administrateurs par défaut (Admins du domaine, Admins de l'entreprise, Administrateurs, SYSTEM, CREATEUR PROPRIETAIRE, contrôleurs de domaine de l'entreprise).

### `33_Audit_Groupes.ps1`
Groupes AD de sécurité et de distribution, **une ligne par membre effectif** (les infos du groupe ne sont remplies que sur sa première ligne). Colonnes :

- identité : nom, SamAccountName, OU, SID, mail, catégorie, portée, groupe natif ;
- membres : nombre de membres effectifs (récursif, groupe principal inclus), membre, type de membre, chemin d'appartenance (`Direct`, `Groupe principal` ou `Via GRP_A > GRP_B`) ;
- imbrication : groupes parents, imbrication circulaire, chemin vers un groupe privilégié ;
- privilèges : groupe T0 (détection par SID, indépendante de la langue), `adminCount` ;
- cycle de vie : création, modification, dernier ajout ou retrait de membre (métadonnées de réplication) ;
- utilisation : partages où le groupe apparaît dans les ACL (CSV de `31_`), GPO où il apparaît (filtrage, délégation, groupes restreints, droits utilisateur, préférences de groupes).

> Numéroté `33_` pour tourner après `31_Audit_NTFS`. Sans CSV NTFS, la colonne `ReferenceNTFS` vaut « Non audite ». Les groupes BUILTIN (S-1-5-32-*) ne sont pas croisés : dans une ACL ou une GPO, ces SID désignent le groupe local de la machine ciblée.

---

## Reconnaissance et audit distant

`00_Reconnaissance.ps1` découvre les machines du réseau puis les audite à distance.

### Étapes

1. Avertissement et confirmation obligatoire avant tout scan.
2. Saisie des plages réseau.
3. Découverte des hôtes actifs.
4. Scan des ports clés (22, 135, 139, 445, 3389, 5985, 5986) et détection d'OS (`nmap -O`).
5. Validation machine par machine : inclusion, exclusion avec raison, ou inventaire seul.
6. Export `Temp_CSV\Reconnaissance_<runId>.csv`.
7. Audit distant des machines retenues.

### Choix de la méthode, par ordre de préférence

| Méthode | Cible | Scripts exécutés |
|---|---|---|
| WinRM | Windows avec WinRM | Tous les scripts, sauf les exclusions ci-dessous |
| SSH | Linux | Collecte intégrée : hostname, OS, interfaces, utilisateurs (UID ≥ 1000 avec shell), services systemd actifs |
| PsExec | Windows sans WinRM, SMB ouvert | `11_` + `10_` et `21_` (serveur) ou `22_` (poste) |

### Exécution WinRM

1. Connexion Kerberos (FQDN) ou demande d'identifiants (IP / hors domaine).
2. Copie des scripts dans `C:\Windows\Temp\Audit_<runId>\` sur la cible.
3. Exécution avec les variables `AUDIT_TEMP_*` et `AUDIT_NONINTERACTIVE=1`.
4. Rapatriement des fichiers dans `Temp_CSV\<HOST>\<sous-dossier>\` (Comptes, AD, HV, VM, NTFS).
5. Nettoyage du dossier distant.

### Scripts exclus de l'exécution WinRM

| Script | Raison |
|---|---|
| Scripts préfixés par `_` | Désactivés |
| `00_Reconnaissance` | Local uniquement, évite un scan non contrôlé depuis la cible |
| `12_Audit_Comptes_365` | Authentification Graph interactive |
| `23_Audit_Linux` | Sans objet sur Windows |
| `13_`, `14_`, `15_`, `30_`, `33_` | Hors DC : exclus pour éviter des doublons des données du domaine |
| `20_Audit_Hyperviseurs` | Hors hôte Hyper-V |

### Logs

```
Logs\Reconnaissance_<runId>\
├─ fichiers XML Nmap par étape
└─ psexec_<IP>.log          ← erreurs PsExec éventuelles
```

---

## Sorties

### Arborescence `Temp_CSV\`

```
Temp_CSV\
├─ Comptes\        ← comptes T0, standards, M365
├─ AD\             ← GPO, PSO, silos, groupes, réplication
├─ HV\
├─ VM\
├─ NTFS\
├─ Reconnaissance_<runId>.csv
└─ <HOST>\         ← une arborescence par machine auditée à distance
    ├─ Comptes\ AD\ HV\ VM\ NTFS\
    └─ <HOST>_Audit_Linux.csv   (cibles SSH)
```

`<HOST>` vaut `NOM.domaine` pour les scripts Windows.

### CSV produits

| Fichier | Dossier | Script |
|---|---|---|
| `<HOST>_Audit_comptes_T0.csv` | `Comptes\` | `10_` |
| `<HOST>_Audit_comptes.csv` | `Comptes\` | `11_` |
| `<HOST>_Audit_Comptes_365.csv` | `Comptes\` | `12_` |
| `<HOST>_AD_OU_Tree.txt` | `Temp_CSV\` | `13_` |
| `<HOST>_Audit_PSO.csv`, `<HOST>_Audit_PSO_Comptes.csv` | `AD\` | `14_` |
| `<HOST>_Audit_Silos.csv`, `<HOST>_Audit_Silos_Politiques.csv` | `AD\` | `15_` |
| `<HOST>_Audit_Hyperviseurs.csv` | `HV\` | `20_` |
| `<HOST>Audit_VMs.csv` | `VM\` | `21_` |
| `<HOST>_Audit_Workstation.csv` | `VM\` | `22_` |
| `<HOST>_Audit_Linux.csv` | `Temp_CSV\<HOST>\` | `00_` (SSH) |
| `<HOST>_Audit_Replication.csv` | `AD\` | `30_` |
| `<HOST>_Audit_NTFS.csv`, `<HOST>_Audit_NTFS_Partages.csv`, schémas `.html` / `.txt` | `NTFS\` | `31_` |
| `<HOST>Audit_GPO.csv` | `AD\` | `32_` |
| `<HOST>_Audit_Groupes.csv` | `AD\` | `33_` |
| `Reconnaissance_<runId>.csv` | `Temp_CSV\` | `00_` |

### Logs (`Logs\`)

| Fichier | Contenu |
|---|---|
| `Audit_<runId>.log` | Transcript complet de `main.ps1` |
| `Init_<runId>.log` | Transcript de `init.ps1` |
| `<Script>_<runId>.log` | Sortie de chaque script d'audit |
| `Reconnaissance_<runId>\` | Logs Nmap et PsExec |

---

## Génération des Excel

`Process_excels.py` se lance manuellement après la collecte, sur une machine disposant de Python 3.10+ et d'openpyxl (`python -m pip install openpyxl`). Il peut tourner ailleurs que sur la machine auditée : il suffit d'y copier `Temp_CSV\`.

```powershell
python Process_excels.py            # réutilise les Excel existants et y ajoute les lignes
python Process_excels.py --force    # recopie les templates : à utiliser pour une relance
python Process_excels.py --ts       # ajoute un horodatage au nom des Excel
python Process_excels.py --config autre_config.json
python Process_excels.py --no-synthese  # ne pas générer Synthese_Audit.xlsx
```

Fonctionnement :

- Pour chaque module de `modules_config.json`, les CSV sont cherchés dans `Temp_CSV\...` **et** dans `Temp_CSV\<HOST>\...` (machines auditées à distance).
- Un Excel est produit par CSV, nommé comme le CSV, sauf pour les modules qui partagent une clé `classeur` (voir plus bas).
- Si le template est absent, le générateur correspondant de `Scripts\Python\` est lancé automatiquement. Seuls les templates des modules ayant des CSV sont générés.
- Un bilan par module s'affiche en fin d'exécution : nombre de CSV traités, « aucun CSV » ou « template introuvable ».

> Sans `--force`, une relance ajoute les lignes une deuxième fois dans l'Excel existant. Utiliser `--force` pour repartir des templates.

### Excel produits

| Module(s) | Template | Feuille(s) | Excel |
|---|---|---|---|
| `comptes_T0` + `comptes` | `Template_Audit_Comptes_t0.xlsx` | Comptes | `<HOST>_Audit_Comptes.xlsx` (regroupé) |
| `comptes_365` | `Template_Audit_Comptes.xlsx` | Comptes | un par CSV |
| `pso`, `pso_comptes` | `Template_Audit_PSO.xlsx` | PSO, Comptes | un par CSV |
| `silos`, `silos_politiques` | `Template_Audit_Silos.xlsx` | Silos, Politiques | un par CSV |
| `hyperviseurs` | `Template_Audit_Hyperviseurs.xlsx` | Hyperviseurs | un par CSV |
| `vms` | `Template_Audit_VMs.xlsx` | VMs | un par CSV |
| `workstation` | `Template_Audit_Workstation.xlsx` | Workstations | un par CSV |
| `linux` | `Template_Audit_Linux.xlsx` | Linux | un par CSV |
| `replication` | `Template_Audit_Replication.xlsx` | Replication | un par CSV |
| `ntfs`, `ntfs_partages` | `Template_Audit_NTFS.xlsx` | NTFS, Partages | un par CSV |
| `gpo` | `Template_Audit_GPO.xlsx` | GPO | un par CSV |
| `groupes` | `Template_Audit_Groupes.xlsx` | Groupes | un par CSV |

Chaque template récent contient une feuille **Légende** qui explique les couleurs et les colonnes.

### Synthèse et KPI

À la fin de son exécution, `Process_excels.py` génère `Excel\Synthese_Audit.xlsx` à partir de **tous les CSV** de `Temp_CSV` (locaux et distants). Il peut aussi être lancé seul : `python Synthese_audit.py`.

| Feuille | Contenu |
|---|---|
| Tableau de bord | Note globale (A à E), note et score par thème, nombre de constats critiques / attention, radar des scores, répartition des OS et des hyperviseurs, liste des points critiques |
| Indicateurs | Tous les KPI : valeur, statut, criticité, seuils, détail (comptes, groupes, dossiers concernés), Excel détaillé à consulter |
| Top risques | Constats critiques puis attention, triés par criticité, avec une recommandation pour chacun |
| Inventaire | Données des graphiques |
| Méthode | Règles de calcul des statuts, scores et notes |

Thèmes et principaux indicateurs :

| Thème | Indicateurs |
|---|---|
| Comptes | Comptes T0 actifs, T0 sans expiration du mot de passe, T0 avec mot de passe de plus d'un an, T0 utilisés par des services ou tâches, comptes sans mot de passe obligatoire, comptes inactifs depuis 90 jours, comptes désactivés encore dans des groupes, M365 (inactifs depuis 6 mois, licences sur comptes inactifs, jamais connectés) |
| Mots de passe et authentification | Politique par défaut, PSO inopérantes, comptes T0 couverts par une PSO, silos appliqués, comptes T0 hors silo, membres de silo mal configurés |
| Groupes | Imbrication circulaire, groupes non T0 menant à un groupe privilégié, membres des groupes d'administration, membres permanents Admins du schéma / de l'entreprise, groupes vides, groupes sans usage (ni NTFS ni GPO) |
| GPO | GPO non liées, GPO désactivées, GPO modifiables par des non-administrateurs |
| Partages et NTFS | Groupe large en écriture, contrôle total explicite, SID orphelins, héritage désactivé, partages « Tout le monde » en écriture |
| Infrastructure | OS hors support, Windows non activé, serveurs sans WinRM, erreurs de réplication, source de temps du PDC, serveurs sur horloge locale |

Calcul :

- **Statut** : OK, Attention ou Critique selon les seuils ; `Info` pour une donnée de contexte ; `N/A` si la donnée n'a pas été collectée (module non lancé ou ancienne version d'un script, la raison est indiquée).
- **Score d'un thème** : moyenne pondérée par la criticité (★ à ★★★), avec OK = 100, Attention = 50, Critique = 0.
- **Note** : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E < 40. La note globale est la moyenne des thèmes évalués.
- Les comptes, groupes et GPO collectés sur plusieurs DC sont dédoublonnés.

Les seuils (90 jours d'inactivité, 1 an pour un mot de passe T0, nombre maximal de comptes T0, etc.) se modifient dans le dictionnaire `SEUILS` en tête de `Synthese_audit.py`, et la liste des OS hors support dans `OS_HORS_SUPPORT`.

---

## Configuration

### `modules_config.json`

```json
{
  "modules": [
    {
      "name": "comptes",
      "template": "Templates_Excel/Template_Audit_Comptes.xlsx",
      "out_file": "Excel/Audit_Comptes.xlsx",
      "sheet": "Comptes",
      "csv_glob": "Temp_CSV/Comptes/*Audit_comptes.csv",
      "start_row": 1,
      "header_map": {},
      "classeur": "{host}_Audit_Comptes"
    }
  ]
}
```

| Clé | Rôle |
|---|---|
| `name` | Nom du module (affiché dans les logs et le bilan) |
| `template` | Template Excel, relatif à la racine |
| `sheet` | Feuille dans laquelle injecter les lignes (créée si absente) |
| `csv_glob` | Motif des CSV ; plusieurs motifs séparés par `;`. `Temp_CSV/<HOST>/...` est cherché automatiquement ; `**` active la recherche récursive |
| `start_row` | Ligne des en-têtes dans le template (ex. `3` pour le template GPO, qui a un titre en ligne 1) |
| `header_map` | Renommage des colonnes CSV vers les en-têtes du template (ex. accents pour GPO, colonnes Graph pour M365) |
| `classeur` | *Optionnel.* Les modules ayant la même valeur écrivent dans le même Excel. `{host}` est remplacé par le nom de la machine ; sans `{host}`, toutes les machines vont dans un seul fichier. Le template utilisé est celui du premier module de la liste |
| `generator` | *Optionnel.* Chemin du générateur du template, si son nom ne suit pas la convention (voir plus bas) |
| `out_file` | Conservé pour compatibilité, n'est plus utilisé |

### Variables d'environnement

| Variable | Script | Rôle |
|---|---|---|
| `AUDIT_NTFS_PATHS` | `31_` | Chemins à auditer, séparés par `;` (évite la sélection interactive) |
| `AUDIT_NTFS_DEPTH` | `31_` | Profondeur d'analyse (entier, `*` = illimitée), défaut 3 |
| `AUDIT_NTFS_DFS_DEPTH` | `31_` | Profondeur sur les cibles DFS distantes, défaut = `AUDIT_NTFS_DEPTH` |
| `AUDIT_NTFS_EXCLURE` | `31_` | Partages à exclure en plus de SYSVOL / NETLOGON, séparés par `;` |
| `AUDIT_NTFS_MAX_DOSSIERS` | `31_` | Nombre maximal de dossiers par racine, défaut 50000 |
| `AUDIT_NTFS_SIZE_DEPTH` | `31_` | Profondeur du détail de taille disque, défaut 5 |
| `AUDIT_GROUPES_REPLMETA` | `33_` | `0` désactive la colonne `DerniereModifMembres` (très gros domaines) |
| `AUDIT_NONINTERACTIVE` | tous | Positionnée à `1` par l'audit distant (aucune saisie) |

```powershell
$env:AUDIT_NTFS_PATHS = "\\SRV-FIC01\Commun;\\SRV-FIC01\RH"
$env:AUDIT_NTFS_DEPTH = "4"
.\main.ps1 -Include "31_*"
```

---

## Ajouter un module

1. **Script PowerShell** dans `Scripts\PowerShell\`, numéroté selon l'ordre voulu, avec l'en-tête standard (`Version`, `Derniere modif`, `Role`, `Usage`). Il écrit son CSV dans `$env:AUDIT_TEMP_CSV\<sous-dossier>\` (Comptes, AD, HV, VM ou NTFS ; variables `AUDIT_TEMP_<SOUS-DOSSIER>`) sous la forme `$env:COMPUTERNAME.<domaine>_Audit_<Nom>.csv`.
2. **Générateur de template** `Scripts\Python\TemplateAudit<Nom>.py`. Les en-têtes doivent être identiques aux colonnes du CSV. Ne pas pré-dimensionner de table : `Process_excels.py` la pose à la bonne taille. Le fichier produit doit contenir `<Nom>` dans son nom (ex. `Template_Audit_<Nom>.xlsx`) pour être retrouvé automatiquement par `Process_excels.py`.
3. **Entrée** dans `modules_config.json`.
4. **`main.ps1`** : description dans `$descriptions` et ajout au bundle voulu.
5. **`00_Reconnaissance.ps1`** : exclusion hors DC si le module ne collecte que des données du domaine.
6. **`init.ps1`** : si le module a besoin d'un outil RSAT, ajouter son motif (`<NN>_*`) dans la liste `Scripts` du composant concerné (`$composantsRsat`).

---

## Compatibilité

| Environnement | Statut |
|---|---|
| Windows Server 2016 / 2019 / 2022 | ✅ Testé |
| Windows Server 2012 R2 | ⚠️ Non testé |
| PowerShell 5.1 | ✅ Minimum requis |
| PowerShell 7+ | ✅ Compatible |
| DC Active Directory | ✅ Toutes fonctionnalités |
| Serveur membre de domaine | ✅ Selon les modules RSAT installés |
| Hyperviseur Hyper-V standalone | ✅ Scripts AD ignorés proprement |
| Machine hors domaine (WORKGROUP) | ✅ Audit local uniquement |
| Silos d'authentification | Niveau fonctionnel du domaine 2012 R2 minimum |
| Cibles Linux | ✅ Via SSH depuis la reconnaissance |

---

## Licence

Projet à usage interne. Toute redistribution doit mentionner l'auteur original.

---

*Framework développé pour les audits de sécurité Active Directory et infrastructure Windows.*
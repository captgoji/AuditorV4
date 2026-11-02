# Synthese_audit.py
# Version      : 3.0
# Derniere modif : Synthese simplifiee pour le client : page unique « Synthèse » (note globale, anneau des constats,
#                  tuiles par domaine, 5 priorites en langage clair) et « Plan d'action » non technique ;
#                  textes client modifiables (colonnes Domaine / Constat / Impact de la feuille Indicateurs) ;
#                  calculs deplaces dans une feuille masquee
# v2.0         : Tableau de bord et Top risques entierement en formules (calcules depuis la feuille
#                  Indicateurs : modifier un statut met tout a jour), graphiques corriges (axes visibles,
#                  graphique des constats par theme), catalogue complet des KPI (chaque indicateur apparait
#                  toujours, en N/A si la donnee manque), ajout : comptes nominatifs utilises par des services,
#                  M365 inactifs 90 j, nombre de PSO, ACE directes a un utilisateur, repartition OS / hyperviseurs
# v1.1         : Racine du framework detectee (AUDIT_ROOT, dossier du script ou Scripts/Python)
# Role         : Genere Excel/Synthese_Audit.xlsx a partir des CSV de Temp_CSV (locaux et distants)
# Usage        : Appele automatiquement a la fin de Process_excels.py (sauf --no-synthese),
#                ou seul : python Synthese_audit.py
# Seuils       : dictionnaire SEUILS ; OS hors support : OS_HORS_SUPPORT ; comptes de service : MOTIF_COMPTE_SERVICE
import csv
import fnmatch
import io
import os
import re
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timedelta
from pathlib import Path

try:
    from openpyxl import Workbook
    from openpyxl.chart import BarChart, DoughnutChart, Reference
    from openpyxl.chart.series import DataPoint
    from openpyxl.chart.shapes import GraphicalProperties
    from openpyxl.drawing.line import LineProperties
    from openpyxl.chart.label import DataLabelList
    from openpyxl.formatting.rule import CellIsRule, FormulaRule
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation
except ImportError:
    print("openpyxl manquant. Installe: python -m pip install openpyxl")
    sys.exit(1)


def _racine():
    """Racine du framework : AUDIT_ROOT (passe par Process_excels.py), sinon le dossier du script
    s'il contient Temp_CSV, sinon deux niveaux au-dessus (script place dans Scripts/Python)."""
    if os.environ.get("AUDIT_ROOT"):
        return Path(os.environ["AUDIT_ROOT"]).resolve()
    ici = Path(__file__).resolve().parent
    if (ici / "Temp_CSV").exists():
        return ici
    if (ici.parent.parent / "Temp_CSV").exists():
        return ici.parent.parent
    return ici


ROOT = _racine()
TEMP = ROOT / "Temp_CSV"
SORTIE = ROOT / "Excel" / "Synthese_Audit.xlsx"
AUJOURDHUI = datetime.now()

# ─── SEUILS (a ajuster selon le referentiel de l'audit) ─────
# Pour chaque indicateur : valeur <= "ok" -> OK ; <= "attention" -> Attention ; sinon Critique
SEUILS = {
    "inactivite_ad_jours":      90,    # compte AD sans connexion depuis N jours = inactif
    "inactivite_m365_jours":    90,    # compte M365 sans connexion depuis N jours = inactif
    "age_mdp_t0_jours":         365,   # mot de passe T0 plus vieux que N jours
    "t0_actifs":                {"ok": 5,  "attention": 10},
    "t0_mdp_jamais_expire":     {"ok": 0,  "attention": 2},
    "t0_mdp_ancien":            {"ok": 0,  "attention": 2},
    "pct_comptes_inactifs":     {"ok": 5,  "attention": 15},   # en %
    "desactives_avec_groupes":  {"ok": 0,  "attention": 10},
    "nominatifs_services":      {"ok": 0,  "attention": 5},
    "pct_m365_inactifs":        {"ok": 5,  "attention": 15},   # en %
    "m365_licences_inactifs":   {"ok": 0,  "attention": 5},
    "membres_groupes_admin":    {"ok": 5,  "attention": 10},
    "pct_groupes_vides":        {"ok": 10, "attention": 25},   # en %
    "pct_groupes_sans_usage":   {"ok": 20, "attention": 40},   # en %
    "gpo_non_liees":            {"ok": 0,  "attention": 5},
    "dossiers_groupe_large":    {"ok": 0,  "attention": 5},
    "ace_directes_utilisateur": {"ok": 0,  "attention": 10},
    "sid_orphelins":            {"ok": 0,  "attention": 10},
    "controle_total_explicite": {"ok": 0,  "attention": 5},
    "pct_heritage_desactive":   {"ok": 10, "attention": 25},   # en %
}

# OS hors support editeur (expressions regulieres, insensibles a la casse) - a mettre a jour
OS_HORS_SUPPORT = [
    r"Windows Server 2003", r"Windows Server 2008", r"Windows Server 2012",   # 2012 et 2012 R2 : fin 10/2023
    r"Windows XP", r"Windows Vista", r"Windows 7\b", r"Windows 8(\.1)?\b",
    r"Windows 10",                                                              # fin 10/2025 (hors ESU / LTSC)
]

# Convention de nommage des comptes de service : un compte qui execute un service ou une tache planifiee
# et qui NE correspond PAS a ce motif est considere comme probablement nominatif.
MOTIF_COMPTE_SERVICE = r"^(svc|srv|sa|sql|gmsa|msa|service|app|task|job|bkp|backup)[-_.]|[-_.](svc|srv|sa|service)$|\$$"

# ─── STATUTS ET STYLES ──────────────────────────────────────
OK, ATT, CRIT, INFO, NA = "OK", "Attention", "Critique", "Info", "N/A"
COULEURS = {OK: "C6EFCE", ATT: "FFEB9C", CRIT: "FFC7CE", INFO: "DDEBF7", NA: "EDEDED"}
POLICE_STATUT = {OK: "006100", ATT: "9C5700", CRIT: "9C0006", INFO: "1F4E79", NA: "7F7F7F"}
COULEUR_NOTE = {"A": "63BE7B", "B": "B1D580", "C": "FFEB84", "D": "FBAA77", "E": "F8696B"}
ENTETE_FILL = PatternFill("solid", fgColor="1F4E79")
ENTETE_FONT = Font(bold=True, color="FFFFFF", name="Arial")
BORD = Border(*(Side(style="thin", color="D9D9D9"),) * 4)
THEMES = ["Comptes", "Mots de passe et authentification", "Groupes", "GPO", "Partages et NTFS", "Infrastructure"]
NB_LIGNES_TOP = 60   # lignes de formules preparees dans la feuille Top risques


class Kpi:
    def __init__(self, theme, nom, valeur, statut, seuil="", detail="", source="", criticite=1, reco=""):
        self.theme, self.nom, self.valeur, self.statut = theme, nom, valeur, statut
        self.seuil, self.detail, self.source, self.criticite, self.reco = seuil, detail, source, criticite, reco


def na(theme, nom, raison, criticite=1, reco=""):
    return Kpi(theme, nom, "-", NA, detail=raison, criticite=criticite, reco=reco)


# ─── LECTURE DES CSV ────────────────────────────────────────
def _lire_csv(chemin):
    with open(chemin, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        contenu = f.read()
    if not contenu.strip():
        return []
    premiere = contenu.splitlines()[0]
    delim = ";" if premiere.count(";") > premiere.count(",") else ","
    return list(csv.DictReader(io.StringIO(contenu), delimiter=delim))


_FICHIERS = None


def fichiers(motif):
    """Tous les CSV de Temp_CSV (y compris Temp_CSV/<HOST>/...) dont le nom correspond au motif."""
    global _FICHIERS
    if _FICHIERS is None:
        _FICHIERS = list(TEMP.rglob("*.csv")) if TEMP.exists() else []
    m = motif.lower()
    return [p for p in _FICHIERS if fnmatch.fnmatch(p.name.lower(), m)]


def lire(motif):
    lignes = []
    for p in fichiers(motif):
        try:
            lignes.extend(_lire_csv(p))
        except Exception as e:
            print(f"[synthese] WARN lecture {p.name} : {e}")
    return lignes


def v(ligne, col):
    return (ligne.get(col) or "").strip()


def parse_date(s):
    s = (s or "").strip()
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "")).replace(tzinfo=None)
    except ValueError:
        pass
    us = bool(re.search(r"\b(AM|PM)\b", s, re.I))
    formats_fr = ["%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y", "%d.%m.%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S"]
    formats_us = ["%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y"]
    for f in (formats_us + formats_fr) if us else (formats_fr + formats_us):
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    return None


def liste(noms, maxi=10):
    noms = [n for n in noms if n]
    if not noms:
        return ""
    if len(noms) <= maxi:
        return ", ".join(noms)
    return ", ".join(noms[:maxi]) + f" (+{len(noms) - maxi})"


def statut_seuil(valeur, cle):
    s = SEUILS[cle]
    if valeur <= s["ok"]:
        return OK
    if valeur <= s["attention"]:
        return ATT
    return CRIT


def libelle_seuil(cle, unite=""):
    s = SEUILS[cle]
    return f"OK <= {s['ok']}{unite} ; Attention <= {s['attention']}{unite}"


def pct(n, total):
    return round(100.0 * n / total, 1) if total else 0.0


def premieres_lignes(lignes, col_cle):
    """CSV 'une ligne par membre' : renvoie [(ligne_parent, [lignes_enfants])]."""
    blocs = []
    for l in lignes:
        if v(l, col_cle):
            blocs.append((l, [l]))
        elif blocs:
            blocs[-1][1].append(l)
    return blocs


def comptes_domaine():
    """Comptes du domaine (T0, standards), dedoublonnes par nom (plusieurs DC audites)."""
    def dedup(lignes):
        d = OrderedDict()
        for l in lignes:
            d.setdefault(v(l, "Name").lower(), l)
        return list(d.values())
    t0 = dedup([l for l in lire("*_Audit_comptes_T0.csv") if v(l, "Type").startswith("Compte domaine")])
    std = dedup([l for l in lire("*_Audit_comptes.csv") if v(l, "Type").startswith("Compte domaine")])
    return t0, std


# ─── THEME COMPTES ──────────────────────────────────────────
def kpi_comptes():
    T, src = "Comptes", "Audit_Comptes.xlsx"
    k = []
    t0, std = comptes_domaine()
    j_inact, j_mdp = SEUILS["inactivite_ad_jours"], SEUILS["age_mdp_t0_jours"]
    noms_ad = [
        ("Comptes T0 actifs (adminCount=1)", 3), ("Comptes T0 dont le mot de passe n'expire jamais", 2),
        (f"Comptes T0 avec mot de passe de plus de {j_mdp} jours", 3),
        ("Comptes T0 utilisés par des services ou tâches planifiées", 3),
        ("Comptes probablement nominatifs utilisés par des services ou tâches", 2),
        ("Comptes actifs sans mot de passe obligatoire (PASSWD_NOTREQD)", 3),
        (f"Comptes actifs sans connexion depuis {j_inact} jours", 2),
        ("Comptes désactivés encore membres de groupes", 1),
    ]
    if not t0 and not std:
        k += [na(T, n, "Aucun CSV de comptes du domaine (10_ / 11_)", c) for n, c in noms_ad]
    else:
        t0_actifs = [l for l in t0 if v(l, "Active") == "Oui"]
        tous_actifs = t0_actifs + [l for l in std if v(l, "Active") == "Oui"]
        n = len(t0_actifs)
        k.append(Kpi(T, noms_ad[0][0], f"{n} ({pct(n, len(tous_actifs))} % des comptes actifs)",
                     statut_seuil(n, "t0_actifs"), libelle_seuil("t0_actifs"),
                     liste([v(l, "Name") for l in t0_actifs]), src, 3,
                     "Limiter les comptes à privilèges au strict nécessaire ; utiliser des comptes d'administration "
                     "dédiés, distincts des comptes de travail quotidien."))

        jamais = [v(l, "Name") for l in t0_actifs if "N'expire jamais" in v(l, "ReglageMdp")]
        k.append(Kpi(T, noms_ad[1][0], len(jamais), statut_seuil(len(jamais), "t0_mdp_jamais_expire"),
                     libelle_seuil("t0_mdp_jamais_expire"), liste(jamais), src, 2,
                     "Retirer l'option « Le mot de passe n'expire jamais » des comptes à privilèges, ou leur "
                     "appliquer une PSO avec rotation."))

        limite = AUJOURDHUI - timedelta(days=j_mdp)
        anciens = [v(l, "Name") for l in t0_actifs
                   if (lambda d: d is None or d < limite)(parse_date(v(l, "PasswordLastSet")))]
        k.append(Kpi(T, noms_ad[2][0], len(anciens), statut_seuil(len(anciens), "t0_mdp_ancien"),
                     libelle_seuil("t0_mdp_ancien"), liste(anciens), src, 3,
                     "Renouveler les mots de passe des comptes à privilèges ; pour le compte krbtgt, prévoir "
                     "une double rotation."))

        svc = [v(l, "Name") for l in t0_actifs if v(l, "Services") or v(l, "ScheduledTask")]
        k.append(Kpi(T, noms_ad[3][0], len(svc), OK if not svc else CRIT, "OK = 0", liste(svc), src, 3,
                     "Ne jamais exécuter de service ou de tâche avec un compte à privilèges : utiliser des "
                     "comptes de service dédiés (gMSA)."))

        motif = re.compile(MOTIF_COMPTE_SERVICE, re.I)
        nomin = [f"{v(l, 'Name')} ({liste([x for x in (v(l, 'Services'), v(l, 'ScheduledTask')) if x], 3)})"
                 for l in tous_actifs if (v(l, "Services") or v(l, "ScheduledTask")) and not motif.search(v(l, "Name"))]
        k.append(Kpi(T, noms_ad[4][0], len(nomin), statut_seuil(len(nomin), "nominatifs_services"),
                     libelle_seuil("nominatifs_services") + " (nom hors convention de comptes de service)",
                     liste(nomin, 5), src, 2,
                     "Exécuter les services et tâches sous des comptes de service dédiés (gMSA de préférence) : "
                     "un compte nominatif bloque le service à son départ et expose son mot de passe."))

        non_requis = [v(l, "Name") for l in tous_actifs if "Non requis" in v(l, "ReglageMdp")]
        k.append(Kpi(T, noms_ad[5][0], len(non_requis), OK if not non_requis else CRIT, "OK = 0",
                     liste(non_requis), src, 3,
                     "Retirer le drapeau PASSWD_NOTREQD et vérifier que ces comptes ont un mot de passe robuste."))

        if tous_actifs and "DerniereConnexion" in tous_actifs[0]:
            limite = AUJOURDHUI - timedelta(days=j_inact)
            inactifs = [v(l, "Name") for l in tous_actifs
                        if (lambda d: d is None or d < limite)(parse_date(v(l, "DerniereConnexion")))]
            p = pct(len(inactifs), len(tous_actifs))
            k.append(Kpi(T, noms_ad[6][0], f"{len(inactifs)} ({p} %)", statut_seuil(p, "pct_comptes_inactifs"),
                         libelle_seuil("pct_comptes_inactifs", " %"), liste(inactifs), src, 2,
                         "Désactiver les comptes inactifs après validation métier, puis les supprimer après une "
                         "période de rétention."))
        else:
            k.append(na(T, noms_ad[6][0], "Colonne DerniereConnexion absente : relancer 10_ et 11_ (v1.9 / v2.0)", 2))

        desact = [v(l, "Name") for l in t0 + std if v(l, "Active") == "Non" and v(l, "Groupes")]
        k.append(Kpi(T, noms_ad[7][0], len(desact), statut_seuil(len(desact), "desactives_avec_groupes"),
                     libelle_seuil("desactives_avec_groupes"), liste(desact), src, 1,
                     "Retirer les comptes désactivés de leurs groupes (en particulier des groupes à privilèges)."))

    k.append(Kpi(T, "Comptes du domaine (actifs / total)",
                 f"{sum(1 for l in t0 + std if v(l, 'Active') == 'Oui')} / {len(t0) + len(std)}"
                 if (t0 or std) else "-", INFO if (t0 or std) else NA, source=src))

    # Microsoft 365
    j365 = SEUILS["inactivite_m365_jours"]
    m365 = lire("*_Audit_Comptes_365.csv")
    src365 = "Audit_Comptes_365.xlsx"
    noms_m365 = [(f"Comptes M365 sans connexion depuis {j365} jours", 2),
                 ("Licences M365 attribuées à des comptes inactifs", 1), ("Comptes M365 jamais connectés", 1)]
    if not m365:
        k += [na(T, n, "Audit Microsoft 365 (12_) non réalisé", c) for n, c in noms_m365]
    else:
        limite = AUJOURDHUI - timedelta(days=j365)
        vrai = lambda x: x.lower() == "true"

        def inactif(l):
            if vrai(v(l, "NeverConnected")):
                return True
            d = parse_date(v(l, "LastSignInDate"))
            if d is None:   # date illisible : repli sur la colonne calculee a 6 mois
                return vrai(v(l, "SignInOlderThan6Months"))
            return d < limite
        inactifs = [l for l in m365 if inactif(l)]
        p = pct(len(inactifs), len(m365))
        k.append(Kpi(T, noms_m365[0][0], f"{len(inactifs)} ({p} %)", statut_seuil(p, "pct_m365_inactifs"),
                     libelle_seuil("pct_m365_inactifs", " %"), liste([v(l, "UserPrincipalName") for l in inactifs]),
                     src365, 2, "Bloquer la connexion des comptes inactifs et revoir leur nécessité."))
        lic = [v(l, "UserPrincipalName") for l in inactifs if v(l, "Licences")]
        k.append(Kpi(T, noms_m365[1][0], len(lic), statut_seuil(len(lic), "m365_licences_inactifs"),
                     libelle_seuil("m365_licences_inactifs"), liste(lic), src365, 1,
                     "Récupérer les licences des comptes inactifs (gain financier direct)."))
        jamais = [v(l, "UserPrincipalName") for l in m365 if vrai(v(l, "NeverConnected"))]
        k.append(Kpi(T, noms_m365[2][0], len(jamais), OK if not jamais else ATT, "OK = 0", liste(jamais), src365, 1,
                     "Vérifier l'utilité des comptes jamais utilisés ; les supprimer s'ils ne servent pas."))
    return k


# ─── THEME MOTS DE PASSE ET AUTHENTIFICATION ────────────────
def kpi_authentification():
    T = "Mots de passe et authentification"
    k = []
    pso = lire("*_Audit_PSO.csv")
    if not pso:
        k += [na(T, "Politique de mot de passe par défaut", "Audit PSO (14_) non réalisé", 3),
              na(T, "PSO configurées", "Audit PSO (14_) non réalisé"),
              na(T, "PSO inopérantes ou mal ciblées", "Audit PSO (14_) non réalisé")]
    else:
        defaut = next((l for l in pso if v(l, "PSO") == "Politique par defaut du domaine"), None)
        if defaut:
            val = (f"{v(defaut, 'LongueurMin')} car. min., complexité {v(defaut, 'Complexite')}, "
                   f"verrouillage {v(defaut, 'SeuilVerrouillage')}")
            k.append(Kpi(T, "Politique de mot de passe par défaut", val, OK if not v(defaut, "Alerte") else CRIT,
                         "Aucune alerte", v(defaut, "Alerte"), "Audit_PSO.xlsx", 3,
                         "Renforcer la politique par défaut : 12 caractères minimum, complexité, historique, "
                         "verrouillage après quelques échecs."))
        else:
            k.append(na(T, "Politique de mot de passe par défaut", "Ligne de référence absente du CSV PSO", 3))
        blocs = premieres_lignes([l for l in pso if v(l, "PSO") != "Politique par defaut du domaine"], "PSO")
        k.append(Kpi(T, "PSO configurées", len(blocs), INFO, detail=liste([v(b, "PSO") for b, _ in blocs]),
                     source="Audit_PSO.xlsx"))
        motifs = re.compile(r"ignoree|Aucune cible|sans utilisateur|introuvable|doublon", re.I)
        ko = [v(b, "PSO") for b, enfants in blocs if any(motifs.search(v(e, "Alerte")) for e in enfants)]
        k.append(Kpi(T, "PSO inopérantes ou mal ciblées", f"{len(ko)} / {len(blocs)}" if blocs else 0,
                     OK if not ko else ATT, "OK = 0", liste(ko), "Audit_PSO.xlsx", 1,
                     "Cibler les PSO sur des groupes de sécurité globaux non vides ; éviter les précédences "
                     "en doublon."))

    pso_c = lire("*_Audit_PSO_Comptes.csv")
    t0 = [l for l in pso_c if v(l, "T0") == "Oui" and v(l, "Active") == "Oui"]
    nom = "Comptes T0 couverts par une PSO renforcée"
    if not pso_c:
        k.append(na(T, nom, "Audit PSO (14_) non réalisé", 2))
    elif not t0:
        k.append(na(T, nom, "Aucun compte T0 actif"))
    else:
        sans = [v(l, "Compte") for l in t0 if v(l, "PolitiqueEffective") == "Politique par defaut du domaine"]
        p = pct(len(t0) - len(sans), len(t0))
        k.append(Kpi(T, nom, f"{p} %", OK if p == 100 else ATT if p >= 50 else CRIT,
                     "OK = 100 % ; Attention >= 50 %", ("Sans PSO : " + liste(sans)) if sans else "",
                     "Audit_PSO_Comptes.xlsx", 2,
                     "Appliquer une PSO dédiée (longueur >= 16, rotation) au groupe des comptes d'administration."))

    silos = lire("*_Audit_Silos.csv")
    noms_silos = [("Silos d'authentification appliqués", 2), ("Comptes T0 hors silo", 2),
                  ("Membres de silo mal configurés (autorisés / assignés)", 1)]
    if not silos:
        k += [na(T, n, "Audit des silos (15_) non réalisé", c) for n, c in noms_silos]
    else:
        reels = [l for l in silos if v(l, "Silo") and not v(l, "Silo").startswith("(")]
        if not reels:
            k.append(Kpi(T, noms_silos[0][0], 0, CRIT, "Au moins un silo appliqué", "Aucun silo configuré",
                         "Audit_Silos.xlsx", 2,
                         "Mettre en place un silo d'authentification pour le Tier 0 (comptes et serveurs T0)."))
        else:
            app = [v(l, "Silo") for l in reels if v(l, "Mode") == "Applique"]
            audit = [v(l, "Silo") for l in reels if v(l, "Mode") != "Applique"]
            k.append(Kpi(T, noms_silos[0][0], f"{len(app)} / {len(reels)}", OK if not audit else ATT,
                         "OK = tous en mode appliqué", ("En audit : " + liste(audit)) if audit else "",
                         "Audit_Silos.xlsx", 2,
                         "Passer les silos en mode appliqué après une période d'observation en audit."))
        hors = [v(l, "Compte") for l in silos if v(l, "Compte") and "Compte T0 hors silo" in v(l, "Alerte")]
        k.append(Kpi(T, noms_silos[1][0], len(hors), OK if not hors else CRIT, "OK = 0", liste(hors),
                     "Audit_Silos.xlsx", 2, "Placer tous les comptes d'administration T0 dans le silo T0."))
        mal = [v(l, "Compte") for l in silos if re.search(r"non assigne|non autorise", v(l, "Alerte"))]
        k.append(Kpi(T, noms_silos[2][0], len(mal), OK if not mal else ATT, "OK = 0", liste(mal),
                     "Audit_Silos.xlsx", 1, "Un compte doit être à la fois autorisé dans le silo et assigné au silo."))
    return k


# ─── THEME GROUPES ──────────────────────────────────────────
def kpi_groupes():
    T, src = "Groupes", "Audit_Groupes.xlsx"
    noms = [("Groupes de sécurité (hors natifs)", 0), ("Groupes de sécurité vides (hors natifs)", 1),
            ("Groupes à imbrication circulaire", 2), ("Groupes non T0 imbriqués dans un groupe privilégié", 3),
            ("Membres effectifs des groupes d'administration", 3),
            ("Membres permanents Admins du schéma / de l'entreprise", 2),
            ("Groupes sans usage identifié (ni ACL NTFS, ni GPO)", 1)]
    lignes = lire("*_Audit_Groupes.csv")
    if not lignes:
        return [na(T, n, "Audit des groupes (33_) non réalisé", max(c, 1)) for n, c in noms]
    k = []
    vus, uniques = set(), []
    for b, enfants in premieres_lignes(lignes, "Groupe"):
        if v(b, "SID") not in vus:
            vus.add(v(b, "SID"))
            uniques.append((b, enfants))
    secu = [(b, e) for b, e in uniques if v(b, "Categorie") == "Securite" and v(b, "Builtin") == "Non"]
    nb_distri = sum(1 for b, _ in uniques if v(b, "Categorie") == "Distribution")
    k.append(Kpi(T, noms[0][0], len(secu), INFO, detail=f"+ {nb_distri} groupe(s) de distribution", source=src))

    vides = [v(b, "Groupe") for b, _ in secu if v(b, "NbMembresEffectifs") in ("0", "")]
    p = pct(len(vides), len(secu))
    k.append(Kpi(T, noms[1][0], f"{len(vides)} ({p} %)", statut_seuil(p, "pct_groupes_vides"),
                 libelle_seuil("pct_groupes_vides", " %"), liste(vides), src, 1,
                 "Supprimer les groupes vides devenus inutiles."))

    circ = [v(b, "Groupe") for b, _ in uniques if v(b, "ImbricationCirculaire").startswith("Oui")]
    k.append(Kpi(T, noms[2][0], len(circ), OK if not circ else CRIT, "OK = 0", liste(circ), src, 2,
                 "Casser les boucles d'imbrication en retirant un des liens."))

    chemin = [v(b, "Groupe") for b, _ in uniques if v(b, "CheminVersPrivilegie") and v(b, "PrivilegieT0") == "Non"]
    k.append(Kpi(T, noms[3][0], len(chemin), OK if not chemin else CRIT, "OK = 0", liste(chemin), src, 3,
                 "Supprimer ces imbrications : chaque membre hérite des privilèges T0 sans être identifié comme tel."))

    rid = lambda b: v(b, "SID").rsplit("-", 1)[-1]
    est_dom = lambda b: v(b, "SID").startswith("S-1-5-21-")
    admins = OrderedDict()
    for b, enfants in uniques:
        if v(b, "SID") == "S-1-5-32-544" or (est_dom(b) and rid(b) in ("512", "518", "519")):
            admins[v(b, "Groupe")] = [v(e, "Membres") for e in enfants if v(e, "Membres")]
    if admins:
        tous = sorted({m for ms in admins.values() for m in ms})
        detail = " ; ".join(f"{g} : {len(ms)}" for g, ms in admins.items()) + " — " + liste(tous)
        k.append(Kpi(T, noms[4][0], len(tous), statut_seuil(len(tous), "membres_groupes_admin"),
                     libelle_seuil("membres_groupes_admin"), detail, src, 3,
                     "Réduire les membres des groupes d'administration ; privilégier une délégation fine."))
        perm = sorted({m for b, enf in uniques if est_dom(b) and rid(b) in ("518", "519")
                       for m in (v(e, "Membres") for e in enf) if m})
        k.append(Kpi(T, noms[5][0], len(perm), OK if not perm else ATT, "OK = 0 (groupes vides hors opération)",
                     liste(perm), src, 2,
                     "Vider ces groupes et n'y ajouter un compte que le temps d'une opération ponctuelle."))
    else:
        k += [na(T, noms[4][0], "Groupes d'administration absents du CSV", 3),
              na(T, noms[5][0], "Groupes d'administration absents du CSV", 2)]

    if any(v(b, "ReferenceNTFS") not in ("Non audite", "") for b, _ in secu):
        sans = [v(b, "Groupe") for b, _ in secu if v(b, "PrivilegieT0") == "Non"
                and v(b, "ReferenceNTFS") == "Non" and v(b, "ReferenceGPO") == "Non"]
        p = pct(len(sans), len(secu))
        k.append(Kpi(T, noms[6][0], f"{len(sans)} ({p} %)", statut_seuil(p, "pct_groupes_sans_usage"),
                     libelle_seuil("pct_groupes_sans_usage", " %"), liste(sans), src, 1,
                     "Vérifier l'utilité de ces groupes (applications, messagerie) avant de les supprimer."))
    else:
        k.append(na(T, noms[6][0], "Audit NTFS non disponible au moment de l'audit des groupes"))
    return k


# ─── THEME GPO ──────────────────────────────────────────────
def kpi_gpo():
    T, src = "GPO", "Audit_GPO.xlsx"
    noms = [("GPO du domaine", 0), ("GPO non liées", 1), ("GPO entièrement désactivées", 1),
            ("GPO modifiables par des comptes non administrateurs", 3)]
    gpo = lire("*Audit_GPO.csv")
    if not gpo:
        return [na(T, n, "Audit des GPO (32_) non réalisé", max(c, 1)) for n, c in noms]
    d = OrderedDict()
    for l in gpo:
        d.setdefault(v(l, "Nom"), l)
    gpo = list(d.values())
    k = [Kpi(T, noms[0][0], len(gpo), INFO, source=src)]
    nl = [v(l, "Nom") for l in gpo if not v(l, "OUs liees")]
    k.append(Kpi(T, noms[1][0], len(nl), statut_seuil(len(nl), "gpo_non_liees"), libelle_seuil("gpo_non_liees"),
                 liste(nl), src, 1, "Supprimer les GPO non liées après sauvegarde, ou les documenter."))
    des = [v(l, "Nom") for l in gpo if v(l, "Active") == "Non"]
    k.append(Kpi(T, noms[2][0], len(des), OK if not des else ATT, "OK = 0", liste(des), src, 1,
                 "Supprimer ou réactiver les GPO désactivées pour simplifier l'administration."))
    if "Delegation" in gpo[0]:
        deleg = [f"{v(l, 'Nom')} : {v(l, 'Delegation')}" for l in gpo
                 if v(l, "Delegation") and v(l, "Delegation") != "Erreur lecture"]
        k.append(Kpi(T, noms[3][0], len(deleg), OK if not deleg else CRIT, "OK = 0", liste(deleg, 5), src, 3,
                     "Retirer les droits de modification des GPO aux comptes non T0 : modifier une GPO appliquée "
                     "aux DC ou aux serveurs T0 permet de prendre le contrôle du domaine."))
    else:
        k.append(na(T, noms[3][0], "Colonne Delegation absente : relancer 32_ (v1.4)", 3))
    return k


# ─── THEME PARTAGES ET NTFS ─────────────────────────────────
def kpi_ntfs():
    T, src = "Partages et NTFS", "Audit_NTFS.xlsx"
    noms = [("Partages / dossiers audités", 0), ("Dossiers avec un groupe large en écriture", 3),
            ("ACE accordées directement à un utilisateur", 1),
            ("Dossiers avec contrôle total explicite (hors administrateurs)", 2), ("ACE avec SID orphelin", 1),
            ("Dossiers avec héritage désactivé", 1),
            ("Partages avec « Tout le monde » en modification ou contrôle total", 1)]
    ntfs = lire("*_Audit_NTFS.csv")
    if not ntfs:
        return [na(T, n, "Audit NTFS (31_) non réalisé", max(c, 1)) for n, c in noms]
    dossiers = {v(l, "Dossier") for l in ntfs if v(l, "Dossier")}
    partages = {(v(l, "Serveur"), v(l, "Partage")) for l in ntfs}
    k = [Kpi(T, noms[0][0], f"{len(partages)} / {len(dossiers)}", INFO, source=src)]

    def doss(motif):
        return sorted({v(l, "Dossier") for l in ntfs if motif in v(l, "Alerte")})
    large = doss("Groupe large avec droits d'ecriture")
    k.append(Kpi(T, noms[1][0], len(large), statut_seuil(len(large), "dossiers_groupe_large"),
                 libelle_seuil("dossiers_groupe_large") + " (Tout le monde, Utilisateurs authentifiés, "
                 "Utilisateurs du domaine...)", liste(large, 5), src, 3,
                 "Remplacer « Tout le monde » / « Utilisateurs du domaine » par des groupes métier dédiés."))

    # ACE explicites dont l'identite est un compte utilisateur du domaine (liste issue de 10_ / 11_)
    t0, std = comptes_domaine()
    utilisateurs = {v(l, "Name").lower() for l in t0 + std}
    if utilisateurs:
        directes = sorted({(v(l, "Dossier"), v(l, "Identite")) for l in ntfs
                           if v(l, "Herite") == "Non" and v(l, "Identite")
                           and v(l, "Identite").split("\\")[-1].lower() in utilisateurs})
        k.append(Kpi(T, noms[2][0], len(directes), statut_seuil(len(directes), "ace_directes_utilisateur"),
                     libelle_seuil("ace_directes_utilisateur") + " (ACE explicites)",
                     liste([f"{d} ({i})" for d, i in directes], 5), src, 1,
                     "Donner les droits via des groupes (modèle AGDLP) plutôt que directement aux utilisateurs."))
    else:
        k.append(na(T, noms[2][0], "Liste des comptes du domaine nécessaire (10_ / 11_)"))

    ct = doss("Controle total explicite")
    k.append(Kpi(T, noms[3][0], len(ct), statut_seuil(len(ct), "controle_total_explicite"),
                 libelle_seuil("controle_total_explicite"), liste(ct, 5), src, 2,
                 "Limiter le contrôle total aux administrateurs ; donner « Modification » aux utilisateurs."))
    orph = sorted({(v(l, "Dossier"), v(l, "SID")) for l in ntfs if "SID orphelin" in v(l, "Alerte")})
    k.append(Kpi(T, noms[4][0], len(orph), statut_seuil(len(orph), "sid_orphelins"), libelle_seuil("sid_orphelins"),
                 liste([f"{d} ({s})" for d, s in orph], 5), src, 1,
                 "Supprimer les ACE pointant vers des comptes ou groupes supprimés."))
    herit = {v(l, "Dossier") for l in ntfs if v(l, "HeritageDesactive") == "Oui"}
    p = pct(len(herit), len(dossiers))
    k.append(Kpi(T, noms[5][0], f"{len(herit)} ({p} %)", statut_seuil(p, "pct_heritage_desactive"),
                 libelle_seuil("pct_heritage_desactive", " %"), liste(sorted(herit), 5), src, 1,
                 "Limiter les ruptures d'héritage, qui rendent les droits difficiles à maîtriser."))
    part = lire("*_Audit_NTFS_Partages.csv")
    if part:
        tlm = sorted({f"\\\\{v(l, 'Serveur')}\\{v(l, 'Partage')}" for l in part if v(l, "Alerte")})
        k.append(Kpi(T, noms[6][0], len(tlm), OK if not tlm else ATT, "OK = 0", liste(tlm, 5),
                     "Audit_NTFS_Partages.xlsx", 1,
                     "Restreindre les droits de partage aux utilisateurs authentifiés ; les droits fins se gèrent en NTFS."))
    else:
        k.append(na(T, noms[6][0], "CSV des droits de partage absent"))
    return k


# ─── THEME INFRASTRUCTURE ───────────────────────────────────
def kpi_infra(machines_inv):
    T = "Infrastructure"
    noms = [("Machines inventoriées (serveurs Windows / postes / Linux)", 0), ("Répartition des systèmes", 0),
            ("Systèmes Windows hors support éditeur", 3), ("Windows non activé", 1), ("Serveurs sans WinRM", 1),
            ("Contrôleurs de domaine en erreur de réplication", 3), ("Source de temps de l'émulateur PDC", 2),
            ("Serveurs synchronisés sur une horloge locale ou l'hôte (DC)", 2),
            ("Répartition des serveurs par hyperviseur", 0)]
    vms, postes = OrderedDict(), OrderedDict()
    for l in lire("*Audit_VMs.csv"):
        vms.setdefault(v(l, "Nom VM").lower(), l)
    for l in lire("*_Audit_Workstation.csv"):
        postes.setdefault(v(l, "Nom poste").lower(), l)
    vms, postes = list(vms.values()), list(postes.values())
    linux = lire("*_Audit_Linux.csv")
    hors = lambda o: any(re.search(r, o, re.I) for r in OS_HORS_SUPPORT)

    for l in vms:
        machines_inv.append([v(l, "Nom VM"), "Serveur", v(l, "OS") or "Inconnu", v(l, "Type HV") or "-",
                             "Oui" if hors(v(l, "OS")) else "Non"])
    for l in postes:
        machines_inv.append([v(l, "Nom poste"), "Poste", v(l, "OS") or "Inconnu", v(l, "Type HV") or "-",
                             "Oui" if hors(v(l, "OS")) else "Non"])
    for l in linux:
        machines_inv.append([v(l, "Hostname"), "Linux", v(l, "OS") or "Inconnu", "-", "Non"])

    if not (vms or postes or linux):
        return [na(T, n, "Aucun inventaire (21_, 22_, Linux)", max(c, 1)) for n, c in noms]
    k = [Kpi(T, noms[0][0], f"{len(vms)} / {len(postes)} / {len(linux)}", INFO, source="Audit_VMs.xlsx")]
    rep_os = Counter(m[2] for m in machines_inv)
    k.append(Kpi(T, noms[1][0], f"{len(rep_os)} version(s)", INFO,
                 detail=" ; ".join(f"{o} : {n}" for o, n in rep_os.most_common()), source="Feuille Inventaire"))

    win = [(v(l, "Nom VM"), l) for l in vms] + [(v(l, "Nom poste"), l) for l in postes]
    hs = [f"{n} ({v(l, 'OS')})" for n, l in win if hors(v(l, "OS"))]
    k.append(Kpi(T, noms[2][0], len(hs), OK if not hs else CRIT, "OK = 0", liste(hs),
                 "Audit_VMs.xlsx / Audit_Workstation.xlsx", 3,
                 "Migrer les systèmes hors support (plus de correctifs de sécurité) ou les isoler."))
    nact = [n for n, l in win if v(l, "Windows Active") == "Non"]
    k.append(Kpi(T, noms[3][0], len(nact), OK if not nact else ATT, "OK = 0", liste(nact),
                 "Audit_VMs.xlsx", 1, "Activer les licences Windows (conformité éditeur)."))
    if vms:
        winrm = [v(l, "Nom VM") for l in vms if v(l, "WinRM").lower().startswith("desact")]
        k.append(Kpi(T, noms[4][0], len(winrm), OK if not winrm else ATT, "OK = 0", liste(winrm),
                     "Audit_VMs.xlsx", 1, "Activer WinRM (HTTPS de préférence) pour une administration à distance maîtrisée."))
    else:
        k.append(na(T, noms[4][0], "Aucun serveur inventorié (21_)"))

    repl = lire("*_Audit_Replication.csv")
    if repl:
        err = [v(l, "Nom VM") for l in repl
               if v(l, "Nb erreurs replication") not in ("", "0")
               or v(l, "Statut derniere repl").startswith(("Erreur", "Injoignable"))]
        k.append(Kpi(T, noms[5][0], len(err), OK if not err else CRIT, "OK = 0", liste(err),
                     "Audit_Replication.xlsx", 3,
                     "Corriger les erreurs de réplication (repadmin /showrepl, dcdiag) : risque d'incohérence de l'annuaire."))
    else:
        k.append(na(T, noms[5][0], "Audit de réplication (30_) non réalisé", 3))

    if vms and any("NTP Source" in l for l in vms):
        horloge_locale = re.compile(r"CMOS|Free-running|Horloge", re.I)
        pdc = [l for l in vms if "PDC" in v(l, "Roles FSMO")]
        if pdc:
            l = pdc[0]
            bon = (("(NTP)" in v(l, "NTP Type") or "AllSync" in v(l, "NTP Type"))
                   and not horloge_locale.search(v(l, "NTP Source")))
            k.append(Kpi(T, noms[6][0], f"{v(l, 'NTP Type')} → {v(l, 'NTP Source')}", OK if bon else CRIT,
                         "Type NTP vers une source externe fiable", v(l, "Nom VM"), "Audit_VMs.xlsx", 2,
                         "Configurer le PDC en type NTP vers des sources fiables (w32tm /config /manualpeerlist "
                         "/syncfromflags:manual /reliable:yes) ; Kerberos tolère 5 minutes d'écart."))
        else:
            k.append(na(T, noms[6][0], "Émulateur PDC non inventorié", 2))
        mauvais = []
        for l in vms:
            s = v(l, "NTP Source")
            if horloge_locale.search(s) or ("AD-Domain-Services" in v(l, "Roles/Services") and "VM IC" in s):
                mauvais.append(f"{v(l, 'Nom VM')} ({s})")
        k.append(Kpi(T, noms[7][0], len(mauvais), OK if not mauvais else ATT, "OK = 0", liste(mauvais),
                     "Audit_VMs.xlsx", 2,
                     "Synchroniser les serveurs sur la hiérarchie du domaine ; désactiver la synchronisation "
                     "horaire Hyper-V/VMware sur les DC virtualisés."))
    else:
        k += [na(T, noms[6][0], "Colonnes NTP absentes : relancer 21_ (v1.5)", 2),
              na(T, noms[7][0], "Colonnes NTP absentes : relancer 21_ (v1.5)", 2)]

    rep_hv = Counter(v(l, "Type HV") or "-" for l in vms)
    k.append(Kpi(T, noms[8][0], f"{len(rep_hv)} type(s)" if vms else "-", INFO if vms else NA,
                 detail=" ; ".join(f"{h} : {n}" for h, n in rep_hv.most_common()), source="Feuille Inventaire"))
    return k


# ─── TEXTES POUR LE CLIENT ──────────────────────────────────
# Libelles des domaines et constats en langage non technique (modifiables aussi dans la feuille
# Indicateurs, colonnes "Constat (client)" et "Impact (client)", avant la restitution).
DOMAINE_CLIENT = OrderedDict([
    ("Comptes", "Comptes utilisateurs"),
    ("Mots de passe et authentification", "Mots de passe et administrateurs"),
    ("Groupes", "Groupes et droits"),
    ("GPO", "Stratégies de configuration"),
    ("Partages et NTFS", "Partages de fichiers"),
    ("Infrastructure", "Serveurs et postes"),
])
VERDICT = {"A": "Très bon", "B": "Bon", "C": "Moyen", "D": "Insuffisant", "E": "Critique"}

# Debut du nom de l'indicateur -> (constat pour le client, pourquoi c'est important)
TEXTES_CLIENT = [
    ("Comptes T0 actifs", "Trop de comptes ont les droits d'administration les plus élevés",
     "Chaque compte administrateur supplémentaire est une porte d'entrée pour prendre le contrôle de tout le système."),
    ("Comptes T0 dont le mot de passe n'expire", "Des mots de passe administrateurs ne sont jamais renouvelés",
     "Un mot de passe administrateur volé reste utilisable indéfiniment."),
    ("Comptes T0 avec mot de passe de plus", "Des mots de passe administrateurs sont anciens",
     "Plus un mot de passe est ancien, plus il a de chances d'avoir fuité ou d'être cassé."),
    ("Comptes T0 utilisés par des services", "Des comptes administrateurs sont utilisés par des applications",
     "Leur mot de passe est stocké sur des serveurs : le récupérer donne le contrôle total du domaine."),
    ("Comptes probablement nominatifs", "Des applications fonctionnent avec des comptes de personnes",
     "Le départ de la personne peut arrêter l'application, et son mot de passe est exposé sur les serveurs."),
    ("Comptes actifs sans mot de passe", "Des comptes peuvent exister sans mot de passe",
     "Un compte sans mot de passe est accessible à n'importe qui."),
    ("Comptes actifs sans connexion", "De nombreux comptes inutilisés sont encore actifs",
     "Les comptes oubliés (anciens salariés, prestataires) sont une cible facile et passent inaperçus."),
    ("Comptes désactivés encore membres", "Des comptes désactivés gardent leurs droits",
     "Une réactivation, même accidentelle, redonne immédiatement tous les accès."),
    ("Comptes M365 sans connexion", "Des comptes Microsoft 365 ne sont plus utilisés",
     "Ils restent accessibles depuis Internet sans que personne ne les surveille."),
    ("Licences M365", "Des licences Microsoft 365 sont payées pour des comptes inutilisés",
     "Coût inutile, récupérable immédiatement."),
    ("Comptes M365 jamais connectés", "Des comptes Microsoft 365 n'ont jamais servi",
     "Comptes probablement inutiles, à vérifier puis supprimer."),
    ("Politique de mot de passe par défaut", "La règle de mot de passe par défaut est trop faible",
     "Des mots de passe courts ou sans blocage après échecs peuvent être devinés par essais successifs."),
    ("PSO inopérantes", "Certaines règles de mot de passe renforcées ne s'appliquent pas",
     "Les comptes censés être mieux protégés ne le sont pas réellement."),
    ("Comptes T0 couverts", "Les administrateurs n'ont pas tous une règle de mot de passe renforcée",
     "Les comptes les plus sensibles sont protégés comme des comptes ordinaires."),
    ("Silos d'authentification", "Les comptes administrateurs ne sont pas cloisonnés",
     "Un administrateur peut se connecter depuis n'importe quel poste, où son identité peut être volée."),
    ("Comptes T0 hors silo", "Des comptes administrateurs échappent au cloisonnement",
     "Ils peuvent se connecter depuis des postes non maîtrisés, où leur identité peut être volée."),
    ("Membres de silo mal configurés", "Le cloisonnement des administrateurs est mal configuré",
     "Certains comptes ne sont pas protégés, ou risquent de ne plus pouvoir se connecter."),
    ("Groupes de sécurité vides", "Des groupes de droits inutiles encombrent l'annuaire",
     "Un annuaire encombré rend les droits difficiles à contrôler."),
    ("Groupes à imbrication circulaire", "Des groupes de droits s'incluent mutuellement",
     "Les droits deviennent impossibles à maîtriser : chaque membre obtient les accès de toute la boucle."),
    ("Groupes non T0 imbriqués", "Des groupes ordinaires donnent indirectement des droits d'administration",
     "Des personnes sont administrateurs sans le savoir et sans être identifiées comme telles."),
    ("Membres effectifs des groupes d'administration", "Trop de personnes sont administrateurs du domaine",
     "Chaque administrateur supplémentaire augmente le risque de prise de contrôle totale."),
    ("Membres permanents Admins", "Les groupes d'administration les plus puissants ne sont pas vides",
     "Ces droits ne devraient être attribués que le temps d'une opération ponctuelle."),
    ("Groupes sans usage", "De nombreux groupes ne semblent servir à rien",
     "Ils compliquent la gestion des droits ; à vérifier puis supprimer."),
    ("GPO non liées", "Des stratégies de configuration ne sont appliquées nulle part",
     "Elles encombrent la configuration et peuvent être réactivées par erreur."),
    ("GPO entièrement désactivées", "Des stratégies de configuration sont désactivées",
     "Configuration à nettoyer pour garder une administration lisible."),
    ("GPO modifiables", "Des non-administrateurs peuvent modifier la configuration des machines",
     "Modifier une stratégie permet d'exécuter du code sur toutes les machines ciblées, y compris les serveurs critiques."),
    ("Dossiers avec un groupe large", "Des dossiers partagés sont modifiables par tout le monde",
     "N'importe quel utilisateur, ou un rançongiciel, peut modifier ou chiffrer ces données."),
    ("ACE accordées directement", "Des droits sur les dossiers sont donnés personne par personne",
     "Les accès deviennent impossibles à suivre, notamment lors des départs."),
    ("Dossiers avec contrôle total", "Des utilisateurs ont le contrôle total sur des dossiers",
     "Ils peuvent modifier eux-mêmes les droits et ouvrir l'accès à d'autres."),
    ("ACE avec SID orphelin", "Des droits pointent vers des comptes supprimés",
     "Traces d'anciens droits jamais nettoyés."),
    ("Dossiers avec héritage", "Les droits de nombreux dossiers sont gérés au cas par cas",
     "La gestion des droits devient complexe et source d'erreurs."),
    ("Partages avec", "Des partages réseau sont ouverts à tout le monde",
     "La protection des données repose uniquement sur les droits des dossiers."),
    ("Systèmes Windows hors support", "Des systèmes ne reçoivent plus de correctifs de sécurité",
     "Les failles découvertes ne seront jamais corrigées : cible privilégiée des attaquants."),
    ("Windows non activé", "Des licences Windows ne sont pas activées", "Non-conformité vis-à-vis de l'éditeur."),
    ("Serveurs sans WinRM", "Des serveurs ne peuvent pas être administrés à distance de façon sécurisée",
     "Administration moins maîtrisée et plus difficile à automatiser."),
    ("Contrôleurs de domaine en erreur", "Les serveurs d'annuaire ne se synchronisent pas correctement",
     "Risque d'incohérence des comptes et des droits, et de pannes de connexion."),
    ("Source de temps", "L'heure de référence du réseau n'est pas fiable",
     "Un décalage d'heure peut bloquer les connexions et rend les journaux d'événements inexploitables."),
    ("Serveurs synchronisés", "Des serveurs ne sont pas à l'heure du réseau",
     "Risque d'échec des connexions et de journaux impossibles à rapprocher."),
]


def texte_client(nom):
    for debut, constat, impact in TEXTES_CLIENT:
        if nom.startswith(debut):
            return constat, impact
    return nom, ""


# ─── ECRITURE EXCEL ─────────────────────────────────────────
def entete(ws, ligne, titres, largeurs=None):
    for i, t in enumerate(titres, start=1):
        c = ws.cell(row=ligne, column=i, value=t)
        c.fill, c.font, c.border = ENTETE_FILL, ENTETE_FONT, BORD
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        if largeurs:
            ws.column_dimensions[get_column_letter(i)].width = largeurs[i - 1]


def regles_statut(ws, plage):
    for st in (CRIT, ATT, OK, INFO, NA):
        ws.conditional_formatting.add(plage, CellIsRule(
            operator="equal", formula=[f'"{st}"'], fill=PatternFill("solid", fgColor=COULEURS[st]),
            font=Font(bold=True, color=POLICE_STATUT[st])))


# Tuiles : fond pastel + lettre foncee selon la note
TUILE_FOND = {"A": "D9EAD3", "B": "E2EFDA", "C": "FFF2CC", "D": "FCE4D6", "E": "F4CCCC"}
TUILE_TEXTE = {"A": "38761D", "B": "548235", "C": "BF9000", "D": "C55A11", "E": "990000"}


def regles_tuile(ws, plage, cellule_note):
    for n in "ABCDE":
        ws.conditional_formatting.add(plage, FormulaRule(
            formula=[f'{cellule_note}="{n}"'], fill=PatternFill("solid", fgColor=TUILE_FOND[n]),
            font=Font(bold=True, color=TUILE_TEXTE[n]), stopIfTrue=True))


def formule_note(cellule):
    return (f'=IF(ISNUMBER({cellule}),IF({cellule}>=90,"A",IF({cellule}>=75,"B",IF({cellule}>=60,"C",'
            f'IF({cellule}>=40,"D","E")))),"-")')


def formule_verdict(cellule_note):
    return (f'=IF({cellule_note}="A","{VERDICT["A"]}",IF({cellule_note}="B","{VERDICT["B"]}",'
            f'IF({cellule_note}="C","{VERDICT["C"]}",IF({cellule_note}="D","{VERDICT["D"]}",'
            f'IF({cellule_note}="E","{VERDICT["E"]}","Non évalué")))))')


def axes_visibles(chart):
    # openpyxl >= 3.1 masque les axes par defaut : sans ca, Excel n'affiche ni libelles ni graduations
    chart.x_axis.delete = False
    chart.y_axis.delete = False


def fusion(ws, plage, valeur=None, font=None, fill=None, align=None):
    ws.merge_cells(plage)
    c = ws[plage.split(":")[0]]
    if valeur is not None:
        c.value = valeur
    if font:
        c.font = font
    if fill:
        c.fill = fill
    c.alignment = align or Alignment(horizontal="center", vertical="center", wrap_text=True)
    return c


def domaines_audites():
    noms = set()
    for p in fichiers("*.csv"):
        m = re.match(r"^[^.]+\.(.+?)_?Audit", p.name, re.I)
        if m and "." in m.group(1):
            noms.add(m.group(1).lower())
    return ", ".join(sorted(noms))


def generer(sortie=SORTIE):
    machines = []
    kpis = kpi_comptes() + kpi_authentification() + kpi_groupes() + kpi_gpo() + kpi_ntfs() + kpi_infra(machines)
    N = len(kpis) + 1
    R = lambda col: f"Indicateurs!${col}$2:${col}${N}"

    wb = Workbook()
    wb.calculation.fullCalcOnLoad = True
    ws = wb.active
    ws.title = "Synthèse"
    wp = wb.create_sheet("Plan d'action")
    wi = wb.create_sheet("Indicateurs")
    wv = wb.create_sheet("Inventaire")
    wm = wb.create_sheet("Méthode")
    wc = wb.create_sheet("Calculs")

    # ═════ Indicateurs (feuille de l'auditeur, source de toutes les formules) ═════
    # A Thème | B Indicateur | C Valeur | D Statut | E Criticité | F Poids | G Points | H Évalué (masquée)
    # I Seuils | J Détail | K Recommandation | L Excel détaillé | M Clé tri (masquée)
    # N Domaine (client) | O Constat (client) | P Impact (client)
    entete(wi, 1, ["Thème", "Indicateur", "Valeur", "Statut", "Criticité", "Poids", "Points", "Évalué",
                   "Seuils", "Détail", "Recommandation", "Excel détaillé", "Clé tri",
                   "Domaine (client)", "Constat (client)", "Impact (client)"],
           [24, 50, 24, 11, 9, 7, 8, 8, 32, 60, 60, 26, 10, 26, 50, 60])
    wi.freeze_panes = "C2"
    for r, x in enumerate(kpis, start=2):
        constat, impact = texte_client(x.nom)
        valeur = x.valeur if isinstance(x.valeur, (int, float)) else str(x.valeur)
        vals = {1: x.theme, 2: x.nom, 3: valeur, 4: x.statut, 6: x.criticite, 9: x.seuil, 10: x.detail,
                11: x.reco, 12: x.source, 14: DOMAINE_CLIENT[x.theme], 15: constat, 16: impact,
                5: f'=IF(H{r}=1,REPT("★",F{r}),"")',
                7: f'=IF(D{r}="OK",100,IF(D{r}="Attention",50,0))',
                8: f'=IF(OR(D{r}="OK",D{r}="Attention",D{r}="Critique"),1,0)',
                13: f'=IF(OR(D{r}="Critique",D{r}="Attention"),IF(D{r}="Critique",200000,100000)+F{r}*1000+1000-ROW(),0)'}
        for c, val in vals.items():
            cell = wi.cell(row=r, column=c, value=val)
            cell.border = BORD
            cell.alignment = Alignment(vertical="top", wrap_text=c in (2, 9, 10, 11, 15, 16),
                                       horizontal="center" if c in (4, 5, 6, 7) else None)
    regles_statut(wi, f"D2:D{N}")
    dv = DataValidation(type="list", formula1='"OK,Attention,Critique,Info,N/A"', allow_blank=False)
    wi.add_data_validation(dv)
    dv.add(f"D2:D{N}")
    dvp = DataValidation(type="whole", operator="between", formula1="1", formula2="3")
    wi.add_data_validation(dvp)
    dvp.add(f"F2:F{N}")
    for col in ("H", "M"):
        wi.column_dimensions[col].hidden = True
    wi.auto_filter.ref = f"A1:P{N}"

    # ═════ Calculs (masquée) ═════
    entete(wc, 1, ["Thème", "Domaine", "Score", "Note", "Verdict", "Critique", "Attention", "OK"],
           [32, 32, 8, 8, 12, 9, 9, 9])
    for i, (t, d) in enumerate(DOMAINE_CLIENT.items(), start=2):
        wc[f"A{i}"], wc[f"B{i}"] = t, d
        wc[f"C{i}"] = (f'=IFERROR(ROUND(SUMPRODUCT(({R("A")}=$A{i})*{R("G")}*{R("F")}*{R("H")})'
                       f'/SUMPRODUCT(({R("A")}=$A{i})*{R("F")}*{R("H")}),0),"-")')
        wc[f"D{i}"] = formule_note(f"C{i}")
        wc[f"E{i}"] = formule_verdict(f"D{i}")
        for col, st in (("F", CRIT), ("G", ATT), ("H", OK)):
            wc[f"{col}{i}"] = f'=COUNTIFS({R("A")},$A{i},{R("D")},"{st}")'
    wc["A9"], wc["C9"] = "Global", '=IFERROR(ROUND(AVERAGE(C2:C7),0),"-")'
    wc["D9"], wc["E9"] = formule_note("C9"), formule_verdict("D9")
    wc["F9"], wc["G9"], wc["H9"] = "=SUM(F2:F7)", "=SUM(G2:G7)", "=SUM(H2:H7)"
    wc["A11"], wc["C11"] = "Urgents", "=F9"
    wc["A12"], wc["C12"] = "À planifier", "=G9"
    wc["A13"], wc["C13"] = "Conformes", "=H9"
    wc["J1"], wc["K1"] = "Priorité", "Ligne Indicateurs"
    for k in range(1, 6):
        cle = f'LARGE({R("M")},{k})'
        wc[f"J{k + 1}"] = k
        wc[f"K{k + 1}"] = f'=IFERROR(IF({cle}>=100000,MATCH({cle},{R("M")},0),""),"")'
    wc.sheet_state = "hidden"

    # ═════ Synthèse (page client) ═════
    ws.sheet_view.showGridLines = False
    ws.column_dimensions["A"].width = 2
    for col in "BCDEFGHIJKLM":
        ws.column_dimensions[col].width = 11.5
    ws.column_dimensions["N"].hidden = True   # statut des priorites (pour les couleurs)
    BLEU = "1F4E79"
    titre_font = lambda taille, coul=BLEU, gras=True: Font(name="Arial", size=taille, bold=gras, color=coul)

    fusion(ws, "B1:M1", "Bilan de sécurité de votre système d'information", titre_font(20),
           align=Alignment(horizontal="left", vertical="center"))
    ws.row_dimensions[1].height = 34
    dom = domaines_audites()
    fusion(ws, "B2:M2", (f"Domaine {dom} — " if dom else "") + f"audit du {AUJOURDHUI:%d/%m/%Y}",
           Font(name="Arial", italic=True, color="7F7F7F"), align=Alignment(horizontal="left"))

    # Bloc note globale
    fusion(ws, "B4:E4", "Niveau de sécurité global", titre_font(12))
    fusion(ws, "B5:E8", "=Calculs!D9", Font(name="Arial", size=60, bold=True))
    regles_tuile(ws, "B5:E8", "$B$5")
    fusion(ws, "B9:E9", '=Calculs!E9&IF(ISNUMBER(Calculs!C9),"  ("&Calculs!C9&" / 100)","")', titre_font(13))
    for r in range(5, 9):
        ws.row_dimensions[r].height = 26

    # Anneau : repartition des points evalues (urgent / a planifier / conforme)
    anneau = DoughnutChart()
    anneau.holeSize = 50
    anneau.add_data(Reference(wc, min_col=3, min_row=11, max_row=13))
    anneau.set_categories(Reference(wc, min_col=1, min_row=11, max_row=13))
    serie = anneau.series[0]
    for idx, coul in enumerate(("C00000", "E69138", "6AA84F")):
        pt = DataPoint(idx=idx)
        pt.graphicalProperties.solidFill = coul
        pt.graphicalProperties.line.solidFill = "FFFFFF"
        serie.dPt.append(pt)
    anneau.dataLabels = DataLabelList()
    anneau.dataLabels.showVal = True
    for attr in ("showSerName", "showCatName", "showLegendKey", "showPercent"):
        setattr(anneau.dataLabels, attr, False)
    anneau.legend.position = "r"
    anneau.title = None
    anneau.graphical_properties = GraphicalProperties(ln=LineProperties(noFill=True))
    anneau.height, anneau.width = 4.6, 8.2
    ws.add_chart(anneau, "F4")

    # Chiffres cles
    fusion(ws, "J4:K4", "Points urgents", titre_font(11, "990000"))
    fusion(ws, "L4:M4", "Points à planifier", titre_font(11, "C55A11"))
    fusion(ws, "J5:K7", "=Calculs!F9", Font(name="Arial", size=36, bold=True, color="990000"),
           PatternFill("solid", fgColor="F4CCCC"))
    fusion(ws, "L5:M7", "=Calculs!G9", Font(name="Arial", size=36, bold=True, color="C55A11"),
           PatternFill("solid", fgColor="FCE4D6"))
    fusion(ws, "J8:M8", f"{len(machines)} machine(s) auditée(s)", Font(name="Arial", color="595959"))
    fusion(ws, "J9:M9", '=Calculs!H9&" point(s) conforme(s)"', Font(name="Arial", color="38761D", bold=True))

    # Tuiles par domaine
    fusion(ws, "B11:M11", "Résultat par domaine", titre_font(13, "FFFFFF"), PatternFill("solid", fgColor=BLEU),
           Alignment(horizontal="left", vertical="center", indent=1))
    ws.row_dimensions[11].height = 22
    blocs_cols = [("B", "E"), ("F", "I"), ("J", "M")]
    for idx in range(6):
        ligne_tuile = 13 if idx < 3 else 19
        c1, c2 = blocs_cols[idx % 3]
        r = ligne_tuile
        calc = idx + 2
        fusion(ws, f"{c1}{r}:{c2}{r}", f"=Calculs!B{calc}", Font(name="Arial", size=11, bold=True))
        fusion(ws, f"{c1}{r + 1}:{c2}{r + 2}", f"=Calculs!D{calc}", Font(name="Arial", size=30, bold=True))
        fusion(ws, f"{c1}{r + 3}:{c2}{r + 3}", f"=Calculs!E{calc}", Font(name="Arial", size=11, bold=True))
        fusion(ws, f"{c1}{r + 4}:{c2}{r + 4}",
               f'=IF(Calculs!F{calc}+Calculs!G{calc}=0,"Aucun point à traiter",'
               f'IF(Calculs!F{calc}>0,Calculs!F{calc}&" urgent(s)","")&IF(AND(Calculs!F{calc}>0,Calculs!G{calc}>0)," · ","")'
               f'&IF(Calculs!G{calc}>0,Calculs!G{calc}&" à planifier",""))',
               Font(name="Arial", size=10))
        regles_tuile(ws, f"{c1}{r}:{c2}{r + 4}", f"${c1}${r + 1}")
        for rr in (r + 1, r + 2):
            ws.row_dimensions[rr].height = 22

    # 5 priorites
    fusion(ws, "B25:M25", "Vos 5 priorités", titre_font(13, "FFFFFF"), PatternFill("solid", fgColor=BLEU),
           Alignment(horizontal="left", vertical="center", indent=1))
    ws.row_dimensions[25].height = 22
    fusion(ws, "C26:G26", "Constat", Font(name="Arial", bold=True, color="595959"), align=Alignment(horizontal="left"))
    fusion(ws, "H26:M26", "Pourquoi c'est important", Font(name="Arial", bold=True, color="595959"),
           align=Alignment(horizontal="left"))
    for k in range(1, 6):
        r = 26 + k
        ref = f"Calculs!$K${k + 1}"
        ws[f"N{r}"] = f'=IF({ref}="","",INDEX({R("D")},{ref}))'
        c = ws.cell(row=r, column=2, value=f'=IF({ref}="","",{k})')
        c.font = Font(name="Arial", size=16, bold=True, color="FFFFFF")
        c.alignment = Alignment(horizontal="center", vertical="center")
        fusion(ws, f"C{r}:G{r}", f'=IF({ref}="",IF({k}=1,"Aucun point prioritaire",""),INDEX({R("O")},{ref})&"")',
               Font(name="Arial", size=11, bold=True), align=Alignment(vertical="center", wrap_text=True))
        fusion(ws, f"H{r}:M{r}", f'=IF({ref}="","",INDEX({R("P")},{ref})&"")', Font(name="Arial", size=10),
               align=Alignment(vertical="center", wrap_text=True))
        ws.row_dimensions[r].height = 36
        for col in "BCDEFGHIJKLM":
            ws[f"{col}{r}"].border = Border(bottom=Side(style="thin", color="D9D9D9"))
    ws.conditional_formatting.add("B27:B31", FormulaRule(formula=['$N27="Critique"'],
                                  fill=PatternFill("solid", fgColor="C00000"), stopIfTrue=True))
    ws.conditional_formatting.add("B27:B31", FormulaRule(formula=['$N27="Attention"'],
                                  fill=PatternFill("solid", fgColor="E69138"), stopIfTrue=True))

    # Legende
    ws["B33"] = "Lecture :"
    ws["B33"].font = Font(name="Arial", bold=True, color="595959")
    for i, n in enumerate("ABCDE"):
        col = get_column_letter(3 + i * 2)
        cel = ws[f"{col}33"]
        cel.value = n
        cel.fill = PatternFill("solid", fgColor=TUILE_FOND[n])
        cel.font = Font(name="Arial", bold=True, color=TUILE_TEXTE[n])
        cel.alignment = Alignment(horizontal="center")
        ws[f"{get_column_letter(4 + i * 2)}33"] = VERDICT[n]
        ws[f"{get_column_letter(4 + i * 2)}33"].font = Font(name="Arial", size=9, color="595959")
    ws["B34"] = ("Rouge = urgent · Orange = à planifier. Le détail technique de chaque point figure "
                 "dans les feuilles « Plan d'action » et « Indicateurs ».")
    ws["B34"].font = Font(name="Arial", size=9, italic=True, color="7F7F7F")

    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = ws.page_setup.fitToHeight = 1
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.print_area = "A1:M34"

    # ═════ Plan d'action (client) ═════
    wp.sheet_view.showGridLines = False
    entete(wp, 1, ["#", "Urgence", "Domaine", "Constat", "Pourquoi c'est important", "Action recommandée", "Ligne"],
           [5, 13, 26, 46, 55, 65, 6])
    wp.freeze_panes = "A2"
    for r in range(2, NB_LIGNES_TOP + 2):
        cle = f'LARGE({R("M")},ROW()-1)'
        wp.cell(row=r, column=7, value=f'=IFERROR(IF({cle}>=100000,MATCH({cle},{R("M")},0),""),"")')
        wp.cell(row=r, column=1, value=f'=IF($G{r}="","",ROW()-1)')
        wp.cell(row=r, column=2, value=f'=IF($G{r}="","",IF(INDEX({R("D")},$G{r})="Critique","Urgent","À planifier"))')
        for c, col in ((3, "N"), (4, "O"), (5, "P"), (6, "K")):
            wp.cell(row=r, column=c, value=f'=IF($G{r}="","",INDEX({R(col)},$G{r})&"")')
        for c in range(1, 7):
            cell = wp.cell(row=r, column=c)
            cell.border = BORD
            cell.alignment = Alignment(vertical="top", wrap_text=c >= 3, horizontal="center" if c <= 2 else None)
    for txt, fond, coul in (("Urgent", "F4CCCC", "990000"), ("À planifier", "FCE4D6", "C55A11")):
        wp.conditional_formatting.add(f"B2:B{NB_LIGNES_TOP + 1}", CellIsRule(
            operator="equal", formula=[f'"{txt}"'], fill=PatternFill("solid", fgColor=fond), font=Font(bold=True, color=coul)))
    wp.conditional_formatting.add(f"D2:D{NB_LIGNES_TOP + 1}", FormulaRule(formula=['$B2<>""'], font=Font(bold=True)))
    wp.column_dimensions["G"].hidden = True
    wp.page_setup.orientation = "landscape"
    wp.page_setup.fitToWidth, wp.page_setup.fitToHeight = 1, 0
    wp.sheet_properties.pageSetUpPr.fitToPage = True

    # ═════ Inventaire (auditeur) ═════
    entete(wv, 1, ["Machine", "Type", "Système", "Hyperviseur", "Hors support"], [26, 10, 44, 18, 13])
    for r, m in enumerate(machines, start=2):
        for c, val in enumerate(m, start=1):
            wv.cell(row=r, column=c, value=val).border = BORD
    fin_m = max(2, len(machines) + 1)
    plage = lambda col: f"${col}$2:${col}${fin_m}"
    systemes = sorted({m[2] for m in machines})
    hvs = sorted({m[3] for m in machines if m[1] == "Serveur"})
    for col, titre in (("G", "Système"), ("H", "Nombre"), ("J", "Hyperviseur"), ("K", "Serveurs")):
        c = wv[f"{col}1"]
        c.value, c.fill, c.font = titre, ENTETE_FILL, ENTETE_FONT
    wv.column_dimensions["G"].width, wv.column_dimensions["J"].width = 44, 18
    for i, s in enumerate(systemes, start=2):
        wv[f"G{i}"], wv[f"H{i}"] = s, f'=COUNTIF({plage("C")},G{i})'
    for i, h in enumerate(hvs, start=2):
        wv[f"J{i}"], wv[f"K{i}"] = h, f'=COUNTIFS({plage("B")},"Serveur",{plage("D")},J{i})'

    def barres(titre, col_cat, col_val, nb, ancre):
        b = BarChart()
        b.type = "bar"
        b.title = titre
        b.legend = None
        b.add_data(Reference(wv, min_col=col_val, min_row=1, max_row=1 + nb), titles_from_data=True)
        b.set_categories(Reference(wv, min_col=col_cat, min_row=2, max_row=1 + nb))
        b.x_axis.scaling.orientation = "maxMin"
        b.y_axis.majorUnit = 1
        b.y_axis.majorGridlines = None
        b.dataLabels = DataLabelList()
        b.dataLabels.showVal = True
        for attr in ("showSerName", "showCatName", "showLegendKey"):
            setattr(b.dataLabels, attr, False)
        axes_visibles(b)
        b.height, b.width = 7, 15
        wv.add_chart(b, ancre)
    if systemes:
        barres("Répartition par système", 7, 8, len(systemes), "M2")
    if hvs:
        barres("Serveurs par hyperviseur", 10, 11, len(hvs), "M17")

    # ═════ Méthode ═════
    wm.column_dimensions["A"].width = 28
    wm.column_dimensions["B"].width = 110
    lignes = [
        ("Pour le client", "Feuilles « Synthèse » (une page, imprimable) et « Plan d'action » : vocabulaire non "
                           "technique, issu des colonnes Domaine / Constat / Impact (client) de la feuille Indicateurs."),
        ("Pour l'auditeur", "Feuilles « Indicateurs » (valeurs, seuils, détail technique, recommandations), "
                            "« Inventaire » et « Méthode ». La feuille « Calculs » est masquée."),
        ("Ajuster avant restitution", "Dans Indicateurs : le statut (liste déroulante), le poids (1 à 3) et les "
                                      "textes client sont modifiables ; la synthèse et le plan d'action suivent."),
        ("Statuts", "OK, Attention (à planifier), Critique (urgent) selon les seuils ; Info = donnée de contexte ; "
                    "N/A = donnée non collectée (raison en Détail)."),
        ("Score d'un domaine", "Moyenne pondérée par le poids : OK = 100 points, Attention = 50, Critique = 0. "
                               "Info et N/A ne comptent pas."),
        ("Note", "A >= 90 (Très bon), B >= 75 (Bon), C >= 60 (Moyen), D >= 40 (Insuffisant), E < 40 (Critique). "
                 "La note globale est la moyenne des domaines évalués."),
        ("Priorités", "Les points urgents d'abord, puis à planifier, classés par poids décroissant."),
        ("Sources", "Tous les CSV de Temp_CSV, y compris ceux des machines auditées à distance. Comptes, groupes "
                    "et GPO collectés sur plusieurs DC sont dédoublonnés."),
        ("Seuils", "SEUILS, OS_HORS_SUPPORT et MOTIF_COMPTE_SERVICE en tête de Synthese_audit.py ; textes client "
                   "par défaut dans TEXTES_CLIENT et DOMAINE_CLIENT."),
    ]
    entete(wm, 1, ["Élément", "Explication"])
    for i, (a, b) in enumerate(lignes, start=2):
        wm.cell(row=i, column=1, value=a).font = Font(bold=True, name="Arial")
        wm.cell(row=i, column=2, value=b).alignment = Alignment(wrap_text=True, vertical="top")

    sortie.parent.mkdir(parents=True, exist_ok=True)
    try:
        wb.save(str(sortie))
    except PermissionError:
        sortie = sortie.with_name(f"{sortie.stem}_{AUJOURDHUI:%Y%m%d_%H%M%S}{sortie.suffix}")
        wb.save(str(sortie))
        print(f"[synthese] Fichier précédent ouvert dans Excel : écriture dans {sortie.name}")

    nb = Counter(x.statut for x in kpis)
    print(f"[synthese] ✓ {sortie.relative_to(ROOT)} — {len(kpis)} indicateurs : {nb[CRIT]} urgent(s), "
          f"{nb[ATT]} à planifier, {nb[OK]} OK, {nb[INFO]} info, {nb[NA]} N/A")
    return sortie


if __name__ == "__main__":
    generer()
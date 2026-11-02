# TemplateAuditSilos.py
# Version      : 1.0
# Derniere modif : Creation
# Role         : Genere Template_Audit_Silos.xlsx (feuilles Silos, Politiques et Legende)
# NB           : aucune Table pre-dimensionnee : Process_excels.py la pose a la bonne taille apres injection.
#                Les en-tetes doivent rester identiques aux colonnes des CSV de 15_Audit_Silos.ps1.
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

_script_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir   = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir  = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, "Template_Audit_Silos.xlsx")

ENTETE_FONT = Font(bold=True, color="FFFFFF", name="Arial")
ENTETE_FILL = PatternFill("solid", fgColor="4F81BD")
ROUGE  = PatternFill("solid", fgColor="F8D7DA")
ORANGE = PatternFill("solid", fgColor="FFE5CC")
JAUNE  = PatternFill("solid", fgColor="FFF4CC")
SEPARATEUR = Border(top=Side(style="medium", color="1F4E79"))
MAX_LIGNES = 200000


def preparer_feuille(ws, colonnes, figer="B2"):
    for idx, (titre, largeur) in enumerate(colonnes, start=1):
        cell = ws.cell(row=1, column=idx, value=titre)
        cell.font = ENTETE_FONT
        cell.fill = ENTETE_FILL
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws.column_dimensions[cell.column_letter].width = largeur
    ws.row_dimensions[1].height = 30
    ws.freeze_panes = figer
    return f"A2:{get_column_letter(len(colonnes))}{MAX_LIGNES}"


def lettre(colonnes, titre):
    return get_column_letter([c[0] for c in colonnes].index(titre) + 1)


wb = Workbook()

# ─── Feuille Silos : une ligne par compte ───────────────────
ws = wb.active
ws.title = "Silos"
col_silo = [
    ("Silo", 26), ("Mode", 10), ("PolitiqueUtilisateur", 24), ("PolitiqueOrdinateur", 24), ("PolitiqueService", 24),
    ("NbComptes", 10), ("Compte", 24), ("TypeCompte", 13), ("OUCompte", 22), ("Active", 8), ("T0", 7),
    ("Autorise", 9), ("Assigne", 9), ("Description", 30), ("DateCreation", 19), ("DateModification", 19),
    ("Alerte", 55),
]
plage = preparer_feuille(ws, col_silo)
c_silo, c_mode, c_alerte = lettre(col_silo, "Silo"), lettre(col_silo, "Mode"), lettre(col_silo, "Alerte")
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'OR(ISNUMBER(SEARCH("hors silo",${c_alerte}2)),ISNUMBER(SEARCH("refusee",${c_alerte}2)))'], fill=ROUGE, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'${c_mode}2="Audit"'], fill=JAUNE, border=SEPARATEUR, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'AND(LEN(${c_silo}2)>0,LEN(${c_alerte}2)>0)'], fill=ORANGE, border=SEPARATEUR, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'LEN(${c_alerte}2)>0'], fill=ORANGE, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'LEN(${c_silo}2)>0'], border=SEPARATEUR))

# ─── Feuille Politiques : une ligne par strategie d'authentification ─
wp = wb.create_sheet("Politiques")
col_pol = [
    ("Politique", 26), ("Mode", 10), ("TGTUtilisateur", 16), ("UtilisateurDepuis", 50), ("UtilisateurVers", 40),
    ("TGTOrdinateur", 16), ("OrdinateurVers", 40), ("TGTService", 16), ("ServiceDepuis", 40), ("ServiceVers", 40),
    ("SilosUtilisant", 26), ("ComptesAssignesDirectement", 30), ("Description", 30),
    ("DateCreation", 19), ("DateModification", 19), ("Alerte", 55),
]
plage_p = preparer_feuille(wp, col_pol)
wp.conditional_formatting.add(plage_p, FormulaRule(formula=[f'${lettre(col_pol, "Mode")}2="Audit"'], fill=JAUNE, stopIfTrue=True))
wp.conditional_formatting.add(plage_p, FormulaRule(formula=[f'LEN(${lettre(col_pol, "Alerte")}2)>0'], fill=ORANGE))

# ─── Feuille Legende ────────────────────────────────────────
wl = wb.create_sheet("Legende")
legende = [
    ("Couleur / colonne", "Signification"),
    ("Rouge", "Compte T0 hors silo, compte autorise mais non assigne (donc hors silo), ou assigne sans etre autorise (authentification refusee)"),
    ("Jaune", "Silo ou strategie en mode audit : evenements journalises mais aucune restriction appliquee"),
    ("Orange", "Autre alerte : silo vide, sans strategie, strategie non utilisee, sans restriction d'origine, TGT trop long"),
    ("", ""),
    ("Disposition", "Feuille Silos : une ligne par compte ; les infos du silo ne sont remplies que sur sa premiere ligne."),
    ("(Aucun silo)", "Bloc final : comptes T0 actifs (adminCount=1) qui ne sont effectivement dans aucun silo"),
    ("Autorise / Assigne", "Un compte n'est dans un silo que s'il est a la fois autorise (liste du silo) ET assigne (attribut du compte)"),
    ("UtilisateurDepuis", "Condition 'Autoriser l'authentification depuis' : machines depuis lesquelles les utilisateurs peuvent obtenir un TGT. Vide = aucune restriction"),
    ("TGT*", "Duree de vie du TGT. 'Defaut' = duree definie dans la strategie Kerberos du domaine"),
]
for ligne in legende:
    wl.append(ligne)
wl["A1"].font = Font(bold=True, name="Arial")
wl["B1"].font = Font(bold=True, name="Arial")
wl["A2"].fill, wl["A3"].fill, wl["A4"].fill = ROUGE, JAUNE, ORANGE
wl.column_dimensions["A"].width = 22
wl.column_dimensions["B"].width = 120

wb.save(output_file)
print(f"Fichier genere : {output_file}")
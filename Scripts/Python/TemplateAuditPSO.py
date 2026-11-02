# TemplateAuditPSO.py
# Version      : 1.0
# Derniere modif : Creation
# Role         : Genere Template_Audit_PSO.xlsx (feuilles PSO, Comptes et Legende)
# NB           : aucune Table pre-dimensionnee : Process_excels.py la pose a la bonne taille apres injection.
#                Les en-tetes doivent rester identiques aux colonnes des CSV de 14_Audit_PSO.ps1.
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

_script_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir   = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir  = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, "Template_Audit_PSO.xlsx")

ENTETE_FONT = Font(bold=True, color="FFFFFF", name="Arial")
ENTETE_FILL = PatternFill("solid", fgColor="4F81BD")
ROUGE  = PatternFill("solid", fgColor="F8D7DA")
ORANGE = PatternFill("solid", fgColor="FFE5CC")
GRIS   = PatternFill("solid", fgColor="E7E6E6")
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

# ─── Feuille PSO : une ligne par cible ──────────────────────
ws = wb.active
ws.title = "PSO"
col_pso = [
    ("PSO", 30), ("Precedence", 11), ("LongueurMin", 11), ("Historique", 11), ("Complexite", 11),
    ("ChiffrementReversible", 13), ("AgeMin", 10), ("AgeMax", 10), ("SeuilVerrouillage", 12),
    ("DureeVerrouillage", 14), ("FenetreObservation", 13), ("NbComptesEffectifs", 12),
    ("Cible", 28), ("TypeCible", 24), ("OUCible", 22), ("NbComptesCible", 11),
    ("Description", 34), ("DateCreation", 19), ("DateModification", 19), ("Alerte", 60),
]
plage = preparer_feuille(ws, col_pso)
c_pso, c_prec, c_alerte = lettre(col_pso, "PSO"), lettre(col_pso, "Precedence"), lettre(col_pso, "Alerte")
# Politique par defaut (Precedence "-") en gris, ligne de reference
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'${c_prec}2="-"'], fill=GRIS, border=SEPARATEUR, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'ISNUMBER(SEARCH("ignoree",${c_alerte}2))'], fill=ROUGE, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'AND(LEN(${c_pso}2)>0,LEN(${c_alerte}2)>0)'], fill=ORANGE, border=SEPARATEUR, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'LEN(${c_alerte}2)>0'], fill=ORANGE, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'LEN(${c_pso}2)>0'], border=SEPARATEUR))

# ─── Feuille Comptes : politique effective par compte ───────
wc = wb.create_sheet("Comptes")
col_cpt = [
    ("Compte", 24), ("NomAffiche", 28), ("OU", 22), ("Active", 9), ("T0", 7),
    ("PolitiqueEffective", 32), ("Precedence", 11), ("LongueurMin", 11), ("Alerte", 30),
]
plage_c = preparer_feuille(wc, col_cpt)
wc.conditional_formatting.add(plage_c, FormulaRule(formula=[f'LEN(${lettre(col_cpt, "Alerte")}2)>0'], fill=ORANGE))

# ─── Feuille Legende ────────────────────────────────────────
wl = wb.create_sheet("Legende")
legende = [
    ("Couleur / colonne", "Signification"),
    ("Gris", "Politique par defaut du domaine (ligne de reference, s'applique aux comptes sans PSO)"),
    ("Rouge", "Cible sur laquelle la PSO ne s'applique pas (groupe non global, groupe de distribution, type non supporte)"),
    ("Orange", "Alerte : reglage faible (seuils en tete de 14_Audit_PSO.ps1), precedence en doublon, PSO sans cible, cible vide/introuvable"),
    ("", ""),
    ("Disposition", "Feuille PSO : une ligne par cible ; les reglages de la PSO ne sont remplis que sur sa premiere ligne."),
    ("Precedence", "La plus petite valeur l'emporte. Une PSO liee directement a un utilisateur prime sur celles heritees de ses groupes."),
    ("NbComptesEffectifs", "Comptes dont la PSO effective (msDS-ResultantPSO) est celle-ci, apres arbitrage des precedences"),
    ("NbComptesCible", "Utilisateurs membres (recursif) du groupe cible, hors appartenance par groupe principal"),
    ("AgeMax", "'Jamais' = les mots de passe n'expirent pas"),
    ("DureeVerrouillage", "'Deverrouillage manuel' = le compte reste verrouille jusqu'a intervention d'un administrateur"),
    ("Feuille Comptes", "Politique effective de chaque compte utilisateur ; alerte si un compte T0 (adminCount=1) n'a pas de PSO"),
]
for ligne in legende:
    wl.append(ligne)
wl["A1"].font = Font(bold=True, name="Arial")
wl["B1"].font = Font(bold=True, name="Arial")
wl["A2"].fill, wl["A3"].fill, wl["A4"].fill = GRIS, ROUGE, ORANGE
wl.column_dimensions["A"].width = 22
wl.column_dimensions["B"].width = 120

wb.save(output_file)
print(f"Fichier genere : {output_file}")
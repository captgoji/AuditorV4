# TemplateAuditGroupes.py
# Version      : 1.0
# Derniere modif : Creation
# Role         : Genere Template_Audit_Groupes.xlsx (feuilles Groupes et Legende)
# NB           : aucune Table pre-dimensionnee : Process_excels.py la pose a la bonne taille apres injection.
#                Les en-tetes doivent rester identiques aux colonnes du CSV de 33_Audit_Groupes.ps1.
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

_script_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir   = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir  = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, "Template_Audit_Groupes.xlsx")

ENTETE_FONT = Font(bold=True, color="FFFFFF", name="Arial")
ENTETE_FILL = PatternFill("solid", fgColor="4F81BD")
ROUGE  = PatternFill("solid", fgColor="F8D7DA")
ORANGE = PatternFill("solid", fgColor="FFE5CC")
JAUNE  = PatternFill("solid", fgColor="FFF4CC")
SEPARATEUR = Border(top=Side(style="medium", color="1F4E79"))
MAX_LIGNES = 200000

colonnes = [
    ("Groupe", 30), ("SamAccountName", 26), ("OU", 22), ("SID", 46), ("Mail", 28),
    ("Categorie", 13), ("Portee", 15), ("Builtin", 9), ("NbMembresEffectifs", 12),
    ("Membres", 28), ("TypeMembre", 14), ("MembreVia", 34),
    ("MemberOf", 34), ("ImbricationCirculaire", 34), ("CheminVersPrivilegie", 46),
    ("PrivilegieT0", 12), ("AdminCount", 12),
    ("DateCreation", 19), ("DateModification", 19), ("DerniereModifMembres", 21),
    ("ReferenceNTFS", 40), ("ReferenceGPO", 46),
]


def lettre(titre):
    return get_column_letter([c[0] for c in colonnes].index(titre) + 1)


wb = Workbook()

# ─── Feuille Groupes : une ligne par membre effectif ────────
ws = wb.active
ws.title = "Groupes"
for idx, (titre, largeur) in enumerate(colonnes, start=1):
    cell = ws.cell(row=1, column=idx, value=titre)
    cell.font = ENTETE_FONT
    cell.fill = ENTETE_FILL
    cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    ws.column_dimensions[cell.column_letter].width = largeur
ws.row_dimensions[1].height = 30
ws.freeze_panes = "B2"

plage = f"A2:{get_column_letter(len(colonnes))}{MAX_LIGNES}"
c_grp, c_cycle, c_t0, c_chemin = lettre("Groupe"), lettre("ImbricationCirculaire"), lettre("PrivilegieT0"), lettre("CheminVersPrivilegie")

# Les infos du groupe ne sont que sur sa premiere ligne : on y applique les alertes + un trait de separation
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'LEFT(${c_cycle}2,3)="Oui"'], fill=ROUGE, border=SEPARATEUR, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'${c_t0}2="Oui"'], fill=ORANGE, border=SEPARATEUR, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'LEN(${c_chemin}2)>0'], fill=JAUNE, border=SEPARATEUR, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'LEN(${c_grp}2)>0'], border=SEPARATEUR))

# ─── Feuille Legende ────────────────────────────────────────
wl = wb.create_sheet("Legende")
legende = [
    ("Couleur / colonne", "Signification"),
    ("Rouge", "Imbrication circulaire detectee (le groupe se contient lui-meme via un ou plusieurs groupes)"),
    ("Orange", "Groupe privilegie Tier 0 (Admins du domaine, Administrateurs, Operateurs, DnsAdmins, etc.)"),
    ("Jaune", "Groupe non T0 mais imbrique (directement ou non) dans un groupe privilegie : ses membres heritent des droits T0"),
    ("", ""),
    ("Disposition", "Une ligne par membre effectif. Les infos du groupe ne sont remplies que sur sa premiere ligne."),
    ("NbMembresEffectifs", "Membres finaux apres resolution recursive des groupes imbriques (groupes exclus du compte)"),
    ("MembreVia", "Direct, Groupe principal (primaryGroupID) ou chemin des groupes imbriques par lesquels le membre est herite"),
    ("AdminCount", "Oui = groupe protege par AdminSDHolder (ou l'ayant ete : l'attribut n'est jamais remis a zero)"),
    ("DerniereModifMembres", "Dernier ajout/retrait de membre (metadonnees de replication). Vide = jamais modifie. Hors groupe principal."),
    ("ReferenceNTFS", "Partages ou le groupe apparait dans les ACL NTFS ou de partage (issu de 31_Audit_NTFS). 'Non audite' si 31_ n'a pas tourne."),
    ("ReferenceGPO", "GPO ou le groupe apparait : Filtrage, Delegation, Groupes restreints, Droits utilisateur, Preferences groupes"),
    ("N/A (BUILTIN)", "Les SID S-1-5-32-* designent les groupes locaux des machines ciblees, pas le groupe du domaine : non croises"),
]
for ligne in legende:
    wl.append(ligne)
wl["A1"].font = Font(bold=True, name="Arial")
wl["B1"].font = Font(bold=True, name="Arial")
wl["A2"].fill, wl["A3"].fill, wl["A4"].fill = ROUGE, ORANGE, JAUNE
wl.column_dimensions["A"].width = 22
wl.column_dimensions["B"].width = 120

wb.save(output_file)
print(f"Fichier genere : {output_file}")
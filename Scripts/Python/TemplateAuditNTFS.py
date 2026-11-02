# TemplateAuditNTFS.py
# Version      : 2.1
# Derniere modif : + colonnes TailleOctets / Taille (v3.2 du script PS)
# Role         : Genere Template_Audit_NTFS.xlsx (feuilles NTFS et Partages)
# NB           : aucune Table pre-dimensionnee : Process_excels.py la pose a la bonne taille apres injection.
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Font, PatternFill

_script_dir  = os.path.dirname(os.path.abspath(__file__))
_root_dir    = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir   = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file  = os.path.join(output_dir, "Template_Audit_NTFS.xlsx")

ENTETE_FONT = Font(bold=True, color="FFFFFF", name="Arial")
ENTETE_FILL = PatternFill("solid", fgColor="4F81BD")
ROUGE  = PatternFill("solid", fgColor="F8D7DA")
ORANGE = PatternFill("solid", fgColor="FFE5CC")
JAUNE  = PatternFill("solid", fgColor="FFF4CC")
MAX_LIGNES = 200000


def preparer_feuille(ws, colonnes):
    """colonnes : liste de (en-tete, largeur). Les en-tetes doivent etre identiques aux colonnes du CSV."""
    for idx, (titre, largeur) in enumerate(colonnes, start=1):
        cell = ws.cell(row=1, column=idx, value=titre)
        cell.font = ENTETE_FONT
        cell.fill = ENTETE_FILL
        cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.column_dimensions[cell.column_letter].width = largeur
    ws.freeze_panes = "A2"


def lettre(colonnes, titre):
    from openpyxl.utils import get_column_letter
    return get_column_letter([c[0] for c in colonnes].index(titre) + 1)


wb = Workbook()

# ─── Feuille NTFS : une ligne par ACE et par dossier ────────
ws = wb.active
ws.title = "NTFS"
colonnes_ntfs = [
    ("Serveur", 24), ("Partage", 18), ("TypePartage", 13), ("Racine", 30), ("Dossier", 55),
    ("CheminRelatif", 40), ("Profondeur", 11), ("TailleOctets", 14), ("Taille", 12),
    ("HeritageDesactive", 18), ("Proprietaire", 26),
    ("Identite", 34), ("SID", 20), ("TypeAcces", 12), ("Droits", 26), ("DroitsBruts", 30),
    ("Herite", 9), ("AppliqueA", 34), ("Alerte", 40),
]
preparer_feuille(ws, colonnes_ntfs)
fin = len(colonnes_ntfs)
from openpyxl.utils import get_column_letter
plage = f"A2:{get_column_letter(fin)}{MAX_LIGNES}"
c_type, c_alerte, c_herit = lettre(colonnes_ntfs, "TypeAcces"), lettre(colonnes_ntfs, "Alerte"), lettre(colonnes_ntfs, "HeritageDesactive")
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'${c_type}2="Refuser"'], fill=ROUGE, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'LEN(${c_alerte}2)>0'], fill=ORANGE, stopIfTrue=True))
ws.conditional_formatting.add(plage, FormulaRule(formula=[f'${c_herit}2="Oui"'], fill=JAUNE))

# ─── Feuille Partages : droits de partage SMB ───────────────
wp = wb.create_sheet("Partages")
colonnes_partages = [
    ("Serveur", 24), ("Partage", 20), ("CheminLocal", 40), ("Identite", 34),
    ("TypeAcces", 12), ("DroitsPartage", 16), ("Alerte", 40),
]
preparer_feuille(wp, colonnes_partages)
plage_p = f"A2:{get_column_letter(len(colonnes_partages))}{MAX_LIGNES}"
wp.conditional_formatting.add(plage_p, FormulaRule(formula=[f'${lettre(colonnes_partages, "TypeAcces")}2="Refuser"'], fill=ROUGE, stopIfTrue=True))
wp.conditional_formatting.add(plage_p, FormulaRule(formula=[f'LEN(${lettre(colonnes_partages, "Alerte")}2)>0'], fill=ORANGE))

# ─── Feuille Legende ────────────────────────────────────────
wl = wb.create_sheet("Legende")
legende = [
    ("Couleur", "Signification"),
    ("Rouge", "ACE de refus (Deny)"),
    ("Orange", "Alerte : groupe large en ecriture, SID orphelin, controle total explicite, ACL illisible"),
    ("Jaune", "Heritage desactive sur le dossier"),
    ("", ""),
    ("Droits", "Controle total > Modification > Lecture et execution > Lecture ; 'Speciales' = combinaison non standard (voir DroitsBruts)"),
    ("Schema", "Voir <HOST>_Audit_NTFS_Arborescence.html (interactif) et .txt dans Temp_CSV\\NTFS"),
]
for ligne in legende:
    wl.append(ligne)
wl["A1"].font = Font(bold=True)
wl["B1"].font = Font(bold=True)
wl["A2"].fill, wl["A3"].fill, wl["A4"].fill = ROUGE, ORANGE, JAUNE
wl.column_dimensions["A"].width = 12
wl.column_dimensions["B"].width = 110

wb.save(output_file)
print(f"Fichier genere : {output_file}")
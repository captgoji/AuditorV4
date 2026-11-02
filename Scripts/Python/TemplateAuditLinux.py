# TemplateAuditLinux.py
# Version      : 1.0
# Derniere modif : Creation
# Role         : Genere Template_Audit_Linux.xlsx (feuille Linux) pour les CSV produits par
#                00_Reconnaissance.ps1 -> Audit_Linux (Temp_CSV\<HOST>\<HOST>_Audit_Linux.csv)
# NB           : aucune Table pre-dimensionnee : Process_excels.py la pose a la bonne taille apres injection.
#                Les en-tetes doivent rester identiques aux colonnes du CSV.
import os

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

_script_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir   = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir  = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, "Template_Audit_Linux.xlsx")

ENTETE_FONT = Font(bold=True, color="FFFFFF", name="Arial")
ENTETE_FILL = PatternFill("solid", fgColor="4F81BD")

colonnes = [
    ("Hostname", 24), ("IP", 16), ("OS", 34),
    ("Interfaces", 60), ("Utilisateurs", 45), ("Services", 60),
]

wb = Workbook()
ws = wb.active
ws.title = "Linux"
for idx, (titre, largeur) in enumerate(colonnes, start=1):
    cell = ws.cell(row=1, column=idx, value=titre)
    cell.font = ENTETE_FONT
    cell.fill = ENTETE_FILL
    cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.column_dimensions[get_column_letter(idx)].width = largeur
ws.freeze_panes = "B2"

wl = wb.create_sheet("Legende")
legende = [
    ("Colonne", "Signification"),
    ("Interfaces", "Sortie de 'ip addr show' (lignes interface + inet), separees par ' | '"),
    ("Utilisateurs", "Comptes avec UID >= 1000 et un shell interactif, au format nom,UID,repertoire, separes par ' | '"),
    ("Services", "30 premiers services systemd en cours d'execution, separes par ' | '"),
]
for ligne in legende:
    wl.append(ligne)
wl["A1"].font = Font(bold=True, name="Arial")
wl["B1"].font = Font(bold=True, name="Arial")
wl.column_dimensions["A"].width = 16
wl.column_dimensions["B"].width = 110

wb.save(output_file)
print(f"Fichier genere : {output_file}")
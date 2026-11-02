# TemplateAuditGPO.py
# Version      : 1.1
# Derniere modif : Colonne Delegation (droits de modification accordes hors administrateurs)
# Role         : Genere Template_Audit_GPO.xlsx
import os

# Repertoire de sortie :
#   - AUDIT_TEMPLATES_DIR si defini (appel depuis init.ps1)
#   - Sinon : dossier Templates_Excel a la racine du framework (2 niveaux au-dessus de Scripts/Python)
_script_dir   = os.path.dirname(os.path.abspath(__file__))
_root_dir     = os.path.normpath(os.path.join(_script_dir, '..', '..'))
_default_dir  = os.path.join(_root_dir, 'Templates_Excel')
output_dir    = os.environ.get('AUDIT_TEMPLATES_DIR', _default_dir)
os.makedirs(output_dir, exist_ok=True)

output_file = os.path.join(output_dir, "Template_Audit_GPO.xlsx")

# sinon dossier Templates_Excel a cote du script (execution manuelle)

# sinon ecrit dans le meme dossier que ce script (execution manuelle)
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter

wb = Workbook()
ws = wb.active
ws.title = "GPO"

# Titre fusionné ligne 1
ws.merge_cells("A1:I1")
title_cell = ws["A1"]
title_cell.value = "GPO"
title_cell.font = Font(bold=True, size=14, name="Arial")
title_cell.alignment = Alignment(horizontal="center", vertical="center")
title_cell.fill = PatternFill("solid", fgColor="C6EFCE")
ws.row_dimensions[1].height = 28

# En-têtes ligne 2 (vide - séparation visuelle)
ws.row_dimensions[2].height = 6

# En-têtes ligne 3
headers = [
    "Domaine",          # A - rempli par le script
    "Nom",              # B - rempli par le script
    "Créé par",         # C - rempli par le script
    "Date de création", # D - rempli par le script
    "OUs liées",        # E - rempli par le script
    "Activé",           # F - rempli par le script
    "Délégation",       # G - rempli par le script
    "Description",      # H - manuel
    "Utilité",          # I - manuel
]

col_widths = [20, 40, 25, 20, 50, 12, 45, 40, 15]

HEADER_FILL  = "4CAF50"   # vert foncé
HEADER_FONT  = "FFFFFF"

for col, (header, width) in enumerate(zip(headers, col_widths), start=1):
    cell = ws.cell(row=3, column=col, value=header)
    cell.font = Font(bold=True, color=HEADER_FONT, name="Arial", size=10)
    cell.fill = PatternFill("solid", fgColor=HEADER_FILL)
    cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.column_dimensions[get_column_letter(col)].width = width

ws.row_dimensions[3].height = 20

# Tableau structuré A3:I103
table = Table(displayName="Table_GPO", ref="A3:I103")
style = TableStyleInfo(
    name="TableStyleMedium7",   # vert clair, cohérent avec la capture
    showFirstColumn=False, showLastColumn=False,
    showRowStripes=True, showColumnStripes=False)
table.tableStyleInfo = style
ws.add_table(table)

# Figer ligne 3 (en-têtes)
ws.freeze_panes = "A4"

# Feuille Référentiels
ref = wb.create_sheet("Référentiels")
oui_non = ["Oui", "Non"]
ref.append(["Activé"] + oui_non)

# Liste déroulante colonne F (Activé)
dv_actif = DataValidation(type="list", formula1="Référentiels!$B$1:$C$1", allow_blank=True)
ws.add_data_validation(dv_actif)
dv_actif.add("F4:F103")

wb.save(output_file)
print(f"Fichier généré : {output_file}")
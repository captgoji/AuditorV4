# TemplateAuditCompte.py
# Version      : 1.1
# Derniere modif : Colonne DerniereConnexion (comptes AD/locaux, et LastSignInDate pour M365)
# Role         : Genere Template_Audit_Comptes.xlsx et Template_Audit_Comptes_t0.xlsx
import os

# Repertoire de sortie :
#   - AUDIT_TEMPLATES_DIR si defini (appel depuis init.ps1)
#   - Sinon : dossier Templates_Excel a la racine du framework (2 niveaux au-dessus de Scripts/Python)
_script_dir   = os.path.dirname(os.path.abspath(__file__))
_root_dir     = os.path.normpath(os.path.join(_script_dir, '..', '..'))
_default_dir  = os.path.join(_root_dir, 'Templates_Excel')
output_dir    = os.environ.get('AUDIT_TEMPLATES_DIR', _default_dir)
os.makedirs(output_dir, exist_ok=True)

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.worksheet.table import Table, TableStyleInfo


def construire_template(output_file, avec_date_creation, table_name):
    """Genere un classeur Comptes.
    avec_date_creation : True pour le template T0 (colonne DateCreation en +)."""
    wb = Workbook()
    ws = wb.active
    ws.title = "Comptes"

    if avec_date_creation:
        headers = [
            "Ordinateur", "Name", "Type", "DateCreation", "Active",
            "ReglageMdp", "DateDesactivation", "Description",
            "PasswordLastSet", "DerniereConnexion", "Groupes", "Services", "ScheduledTask",
        ]
    else:
        headers = [
            "Ordinateur", "Name", "Type", "Active",
            "ReglageMdp", "DateDesactivation", "Description",
            "PasswordLastSet", "DerniereConnexion", "Groupes", "Services", "ScheduledTask",
        ]

    for col, header in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = Font(bold=True, color="FFFFFF", name="Arial")
        cell.fill = PatternFill("solid", fgColor="4BACC6")
        cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.column_dimensions[cell.column_letter].width = 25

    last_col_letter = ws.cell(row=1, column=len(headers)).column_letter
    table = Table(displayName=table_name, ref=f"A1:{last_col_letter}200")
    style = TableStyleInfo(
        name="TableStyleMedium9", showFirstColumn=False,
        showLastColumn=False, showRowStripes=True, showColumnStripes=False)
    table.tableStyleInfo = style
    ws.add_table(table)
    ws.freeze_panes = "A2"

    ref = wb.create_sheet("Référentiels")
    yes_no        = ["Oui", "Non"]
    account_types = ["Local", "Domain", "Built-in", "gMSA", "sMSA", "Service", "Computer$", "Other"]
    reglage_mdp   = ["Standard", "N'expire jamais", "Non requis", "Ne peut pas changer", "Expire"]

    ref.append(["Enabled"]    + yes_no)
    ref.append(["Type"]       + account_types)
    ref.append(["ReglageMdp"] + reglage_mdp)

    col_active  = headers.index("Active") + 1
    col_type    = headers.index("Type") + 1
    col_reglage = headers.index("ReglageMdp") + 1

    def letter(n):
        return ws.cell(row=1, column=n).column_letter

    dv_enabled = DataValidation(type="list", formula1="Référentiels!$B$1:$C$1", allow_blank=True)
    ws.add_data_validation(dv_enabled)
    dv_enabled.add(f"{letter(col_active)}2:{letter(col_active)}200")

    dv_type = DataValidation(type="list", formula1="Référentiels!$B$2:$I$2", allow_blank=True)
    ws.add_data_validation(dv_type)
    dv_type.add(f"{letter(col_type)}2:{letter(col_type)}200")

    dv_reglage = DataValidation(type="list", formula1="Référentiels!$B$3:$F$3", allow_blank=True)
    ws.add_data_validation(dv_reglage)
    dv_reglage.add(f"{letter(col_reglage)}2:{letter(col_reglage)}200")

    wb.save(output_file)
    print(f"Fichier généré : {output_file}")


# Template standard (11_ et M365) - sans DateCreation
construire_template(
    os.path.join(output_dir, "Template_Audit_Comptes.xlsx"),
    avec_date_creation=False,
    table_name="Table_Comptes"
)

# Template T0 (10_) - avec DateCreation
construire_template(
    os.path.join(output_dir, "Template_Audit_Comptes_t0.xlsx"),
    avec_date_creation=True,
    table_name="Table_Comptes_T0"
)
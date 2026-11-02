import os

# Repertoire de sortie :
#   - AUDIT_TEMPLATES_DIR si defini (appel depuis init.ps1)
#   - Sinon : dossier Templates_Excel a la racine du framework (2 niveaux au-dessus de Scripts/Python)
_script_dir   = os.path.dirname(os.path.abspath(__file__))
_root_dir     = os.path.normpath(os.path.join(_script_dir, '..', '..'))
_default_dir  = os.path.join(_root_dir, 'Templates_Excel')
output_dir    = os.environ.get('AUDIT_TEMPLATES_DIR', _default_dir)
os.makedirs(output_dir, exist_ok=True)

output_file = os.path.join(output_dir, "Template_Audit_Workstation.xlsx")

# sinon dossier Templates_Excel a cote du script (execution manuelle)

# sinon ecrit dans le meme dossier que ce script (execution manuelle)
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.worksheet.table import Table, TableStyleInfo

# Dossier de sortie relatif au script

wb = Workbook()

# Feuille 1 : Workstations
ws = wb.active
ws.title = "Workstations"

headers = [
    "Nom poste",        # A
    "IP",               # B
    "Adresse MAC",      # C
    "S/N",              # D
    "OS",               # E
    "Roles/Services",   # F
    "Integre au domaine", # G
    "Nom de Domaine",   # H
    "Hyperviseur hote", # I
    "Type HV",          # J
    "WinRM",            # K
    "Diag HV/KVP",      # L
    "Replication",      # M
    "Dest replication", # N
    "Windows Active",   # O
    "Roles FSMO"        # P
]

for col, header in enumerate(headers, start=1):
    cell = ws.cell(row=1, column=col, value=header)
    cell.font = Font(bold=True, color="FFFFFF", name="Arial")
    cell.fill = PatternFill("solid", fgColor="4F81BD")
    cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.column_dimensions[chr(64+col)].width = 25

table = Table(displayName="Table_Workstations", ref="A1:P20")
style = TableStyleInfo(
    name="TableStyleMedium9", showFirstColumn=False,
    showLastColumn=False, showRowStripes=True, showColumnStripes=False)
table.tableStyleInfo = style
ws.add_table(table)

# Feuille 2 : Référentiels
ref = wb.create_sheet("Référentiels")

os_list        = ["Windows Server 2016", "Windows Server 2019", "Windows Server 2022",
                  "Linux Ubuntu", "Linux Debian", "Linux RHEL", "Autre"]
domain_list    = ["Oui", "Non"]
roles_list     = ["AD DS", "DNS", "DHCP", "FS", "IIS", "Hyper-V", "RDS", "RemoteAccess",
                  "AD CS", "NPAS", "WDS", "Print-Services", "ADLDS",
                  "FS-DFS-Namespace", "FS-DFS-Replication", "Web-Application-Proxy"]
hyperviseur_list = ["VMware ESXi", "Microsoft Hyper-V", "Proxmox VE", "XenServer", "Nutanix AHV", "Autre"]
WinRM_list     = ["Activé", "Désactivé"]

ref.append(["OS"]                  + os_list)
ref.append(["Intégré au domaine"]  + domain_list)
ref.append(["Rôles/Services"]      + roles_list)
ref.append(["Hyperviseur hôte"]    + hyperviseur_list)
ref.append(["WinRM"]               + WinRM_list)

# Listes déroulantes
dv_os = DataValidation(type="list", formula1="Référentiels!$B$1:$H$1", allow_blank=True)
ws.add_data_validation(dv_os)
dv_os.add("E2:E20")

dv_domain = DataValidation(type="list", formula1="Référentiels!$B$2:$C$2", allow_blank=True)
ws.add_data_validation(dv_domain)
dv_domain.add("G2:G20")

dv_roles = DataValidation(type="list", formula1="Référentiels!$B$3:$Q$3", allow_blank=True)
ws.add_data_validation(dv_roles)
dv_roles.add("F2:F20")

dv_hyperv = DataValidation(type="list", formula1="Référentiels!$B$4:$G$4", allow_blank=True)
ws.add_data_validation(dv_hyperv)
dv_hyperv.add("J2:J20")

dv_WinRM = DataValidation(type="list", formula1="Référentiels!$B$5:$C$5", allow_blank=True)
ws.add_data_validation(dv_WinRM)
dv_WinRM.add("K2:K20")

wb.save(output_file)
print("Fichier généré :", output_file)
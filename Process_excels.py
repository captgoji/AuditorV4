# Derniere modif : CSV distants (Temp_CSV/<HOST>/...) pris en compte, correspondance exacte des
#                  classeurs existants, cle optionnelle "classeur" pour regrouper volontairement
#                  plusieurs modules dans un meme Excel (comptes + comptes_T0), bilan par module,
#                  generation automatique des templates manquants (Scripts/Python/Template*.py),
#                  Excel de synthese (KPI) via Synthese_audit.py en fin d'execution (--no-synthese pour l'ignorer)
#   --force  : recopie les templates même si un Excel existe déjà
#   --ts     : ajoute un timestamp au nom des Excel créés

import os, sys, csv, glob, shutil, io, argparse, json, re, subprocess
from pathlib import Path
from datetime import datetime

try:
    from openpyxl import load_workbook
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.table import Table, TableStyleInfo
except ImportError:
    print("openpyxl manquant. Installe: python -m pip install openpyxl")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent
PYTHON_DIR = ROOT / "Scripts" / "Python"

# ─── Generation des templates manquants ─────────────────────
_generateurs_lances = {}   # generateur -> True/False (lance une seule fois par execution)

def trouver_generateur(template: Path, generateur_cfg: str = ""):
    """Generateur du template. Priorite a la cle 'generator' du module si renseignee ; sinon meme
    regle que init.ps1 : le mot-cle du script (TemplateAuditGroupes.py -> 'Groupes') doit figurer dans le
    nom du template sans les '_' (Template_Audit_Groupes -> 'TemplateAuditGroupes'). Le mot-cle le plus
    long l'emporte en cas d'ambiguite."""
    if generateur_cfg:
        g = ROOT / generateur_cfg
        return g if g.exists() else None
    nom_template = template.stem.replace("_", "").lower()
    candidats = []
    for g in PYTHON_DIR.glob("Template*.py"):
        mot_cle = re.sub(r"^Template(Audit)?", "", g.stem, flags=re.IGNORECASE).lower()
        if mot_cle and mot_cle in nom_template:
            candidats.append((len(mot_cle), g))
    if not candidats:
        return None
    return max(candidats, key=lambda c: c[0])[1]

def generer_template(name: str, template: Path, generateur_cfg: str = "") -> bool:
    """Lance le generateur du template s'il manque. Retourne True si le template existe ensuite."""
    gen = trouver_generateur(template, generateur_cfg)
    if gen is None:
        print(f"[{name}] Aucun script de generation trouve pour {template.name} dans {PYTHON_DIR.relative_to(ROOT)}")
        return False
    if gen not in _generateurs_lances:
        print(f"[{name}] Template absent -> generation via {gen.name}")
        env = dict(os.environ, AUDIT_TEMPLATES_DIR=str(template.parent))
        template.parent.mkdir(parents=True, exist_ok=True)
        try:
            r = subprocess.run([sys.executable, str(gen)], env=env, capture_output=True,
                               text=True, timeout=300, cwd=str(gen.parent))
            _generateurs_lances[gen] = (r.returncode == 0)
            if r.returncode != 0:
                print(f"[{name}] ERREUR generation ({gen.name}) : {(r.stderr or r.stdout).strip()[-500:]}")
        except Exception as e:
            _generateurs_lances[gen] = False
            print(f"[{name}] ERREUR generation ({gen.name}) : {e}")
    if template.exists():
        return True
    if _generateurs_lances.get(gen):
        print(f"[{name}] {gen.name} s'est execute mais {template.name} n'a pas ete produit")
    return False

def sniff_delimiter(sample: str, default=","):
    candidates = [";", ",", "\t", "|"]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=";,\t|")
        return dialect.delimiter
    except Exception:
        counts = {d: sample.count(d) for d in candidates}
        best = max(counts, key=counts.get)
        return best if counts[best] > 0 else default

def read_csv_file(path: Path):
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    sample = "\n".join(text.splitlines()[:30])
    delim = sniff_delimiter(sample)
    reader = csv.DictReader(io.StringIO(text), delimiter=delim)
    return list(reader)

def headers_row(ws, start_row=1):
    headers = {}
    if ws.max_row >= start_row:
        for cell in ws[start_row]:
            if cell.value:
                headers[str(cell.value).strip()] = cell.col_idx
    return headers

def write_headers(ws, header_names, start_row=1):
    for idx, h in enumerate(header_names, start=1):
        ws.cell(row=start_row, column=idx, value=h)

def append_rows(ws, rows, header_map=None, start_row=1):
    header_map = header_map or {}
    excel_headers = headers_row(ws, start_row=start_row)

    # Si aucune ligne d'entêtes détectée à start_row, on la crée à partir du 1er CSV
    if not excel_headers:
        first = rows[0] if rows else {}
        header_names = [header_map.get(k, k) for k in first.keys()]
        if header_names:
            write_headers(ws, header_names, start_row=start_row)
            excel_headers = headers_row(ws, start_row=start_row)

    for r in rows:
        out = [None] * max(1, len(excel_headers))
        for csv_key, value in r.items():
            excel_key = header_map.get(csv_key, csv_key)
            if excel_key in excel_headers:
                out[excel_headers[excel_key] - 1] = value
        # Ajoute en bas du tableau (première ligne vide après ce qui existe)
        ws.append(out)

def ensure_table(ws, table_name, start_row=1):
    # Pose une table seulement s'il y a au moins entêtes + 1 ligne
    if ws.tables:
        return
    max_row = ws.max_row
    max_col = ws.max_column
    if max_row < start_row + 1 or max_col < 1:
        return
    ref = f"A{start_row}:{get_column_letter(max_col)}{max_row}"
    t = Table(displayName=table_name, ref=ref)
    t.tableStyleInfo = TableStyleInfo(name="TableStyleMedium9", showRowStripes=True, showColumnStripes=False)
    ws.add_table(t)

# Classeurs deja crees/choisis pendant CETTE execution : un 2e module qui vise le meme classeur
# (cle "classeur") ecrit dedans au lieu de le recopier, meme avec --force.
_classeurs_execution = {}

def copy_template_if_needed(src: Path, dst: Path, force=False, timestamp=False):
    cle = os.path.normcase(str(dst))
    if cle in _classeurs_execution:
        cible = _classeurs_execution[cle]
        print(f"[MERGE] Ajout dans le classeur : {cible.relative_to(ROOT)}")
        return cible

    dst.parent.mkdir(parents=True, exist_ok=True)
    target = dst
    if timestamp:
        target = dst.with_name(dst.stem + "_" + datetime.now().strftime("%Y%m%d_%H%M%S") + dst.suffix)
    # --force => recopier toujours ; sinon, utiliser la plus recente si deja presente.
    # Correspondance EXACTE sur le nom (+ timestamp eventuel) : "X_Audit_NTFS*.xlsx" ne doit pas
    # attraper "X_Audit_NTFS_Partages.xlsx". Le regroupement voulu passe par la cle "classeur".
    motif = re.compile(re.escape(dst.stem) + r"(_\d{8}_\d{6})?" + re.escape(dst.suffix) + "$", re.IGNORECASE)
    existing = sorted((p for p in dst.parent.glob(f"{dst.stem}*{dst.suffix}") if motif.match(p.name)),
                      key=lambda p: p.stat().st_mtime, reverse=True)
    if force or not existing:
        shutil.copy2(src, target)
        print(f"[COPY] {src.name} → {target.relative_to(ROOT)}")
    else:
        target = existing[0]
        print(f"[KEEP] Utilisation du classeur existant : {target.relative_to(ROOT)}")
    _classeurs_execution[cle] = target
    return target

def hote_depuis_csv(stem: str) -> str:
    """'DC01.lab.local_Audit_comptes_T0' -> 'DC01.lab.local' (gere aussi 'DC01.lab.localAudit_GPO')."""
    m = re.match(r"(.+?)_?Audit", stem, re.IGNORECASE)
    return m.group(1) if m else stem

def nom_classeur(csv_path: Path, classeur: str) -> Path:
    """Sans cle 'classeur' : un Excel par CSV, du meme nom.
    Avec 'classeur' (ex. '{host}_Audit_Comptes') : les modules partageant la meme valeur
    ecrivent dans le meme Excel pour un hote donne."""
    if classeur:
        return ROOT / "Excel" / (classeur.format(host=hote_depuis_csv(csv_path.stem)) + ".xlsx")
    return ROOT / "Excel" / f"{csv_path.stem}.xlsx"

def expand_globs(patterns: str):
    """Liste des CSV correspondant aux motifs (separes par ';').
    Les CSV des machines auditees a distance (00_Reconnaissance) sont rapatries dans
    Temp_CSV/<HOST>/<sous-dossier>/ : pour chaque motif 'Temp_CSV/...', on cherche donc aussi
    dans 'Temp_CSV/*/...'. Les motifs avec '**' sont evalues en recursif."""
    files = []
    parts = [p.strip() for p in patterns.split(";") if p.strip()]
    for p in parts:
        motifs = [p]
        if p.startswith("Temp_CSV/") and "**" not in p:
            motifs.append("Temp_CSV/*/" + p[len("Temp_CSV/"):])
        for m in motifs:
            files.extend(glob.glob(str(ROOT / m), recursive=True))
    # Dedoublonnage en gardant l'ordre
    vus, uniques = set(), []
    for f in files:
        k = os.path.normcase(os.path.abspath(f))
        if k not in vus:
            vus.add(k)
            uniques.append(f)
    return uniques

def load_rows_from_globs(patterns: str):
    rows = []
    files = expand_globs(patterns)
    for f in files:
        try:
            rows.extend(read_csv_file(Path(f)))
        except Exception as e:
            print(f"[WARN] Lecture CSV échouée: {f} → {e}")
    return rows, files

def traiter_csv(name, csv_path, template, sheet, start_row, header_map, classeur, args):
    out_path = copy_template_if_needed(template, nom_classeur(csv_path, classeur),
                                       force=args.force, timestamp=args.ts)
    try:
        data = read_csv_file(csv_path)
    except Exception as e:
        print(f"[{name}] WARN: lecture CSV échouée: {csv_path.name} → {e}")
        return False

    try:
        wb = load_workbook(str(out_path))
    except Exception as e:
        print(f"[{name}] ERREUR: échec ouverture {out_path.name} → {e}")
        return False

    ws = wb[sheet] if sheet in wb.sheetnames else wb.create_sheet(title=sheet)

    if data:
        append_rows(ws, data, header_map=header_map, start_row=start_row)
        try:
            ensure_table(ws, table_name=f"Table_{sheet.replace(' ','_')[:20]}", start_row=start_row)
        except Exception as e:
            print(f"[{name}] WARN: table non posée ({e})")

    try:
        wb.save(str(out_path))
        print(f"[{name}] ✓ {csv_path.name} → {out_path.name} / Feuille: {sheet}")
        return True
    except Exception as e:
        print(f"[{name}] ERREUR: sauvegarde {out_path.name} → {e}")
        return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="Recopier les templates même si un Excel existe déjà")
    ap.add_argument("--ts", action="store_true", help="Ajouter un timestamp aux fichiers Excel créés")
    ap.add_argument("--config", default="modules_config.json", help="Chemin du fichier JSON de config")
    ap.add_argument("--no-synthese", action="store_true", help="Ne pas generer Excel/Synthese_Audit.xlsx")
    args = ap.parse_args()

    cfg_path = ROOT / args.config
    if not cfg_path.exists():
        print(f"Config introuvable: {cfg_path}")
        sys.exit(1)
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    modules = cfg.get("modules", [])
    bilan = []   # (module, statut) affiche en fin d'execution

    for mod in modules:
        name        = mod.get("name", "module")
        template    = ROOT / mod["template"]
        sheet       = mod.get("sheet", "Data")
        csv_glob    = mod.get("csv_glob", "")
        start_row   = int(mod.get("start_row", 1))
        header_map  = mod.get("header_map", {})
        classeur    = mod.get("classeur", "")   # optionnel : regroupement de modules dans un meme Excel

        files = expand_globs(csv_glob)
        if not files:
            print(f"[{name}] Aucun CSV trouvé pour: {csv_glob}")
            bilan.append((name, "aucun CSV"))
            continue
        print(f"[{name}] {len(files)} fichier(s) CSV trouvés.")

        # Template genere a la volee s'il manque (seulement si des CSV sont a traiter)
        if not template.exists() and not generer_template(name, template, mod.get("generator", "")):
            print(f"[{name}] Template introuvable : {template.relative_to(ROOT)}")
            bilan.append((name, f"TEMPLATE INTROUVABLE ({mod['template']}) - generation impossible"))
            continue

        ok = sum(traiter_csv(name, Path(f), template, sheet, start_row, header_map, classeur, args) for f in files)
        bilan.append((name, f"{ok}/{len(files)} CSV traite(s)" + (f" -> {classeur}" if classeur else "")))

    print("\n─── Bilan ─────────────────────────────")
    for n, statut in bilan:
        print(f"  {n:<18} {statut}")
    # Synthese KPI (lit directement les CSV de Temp_CSV). Le script est cherche a la racine puis dans
    # Scripts/Python, et lance dans un processus separe avec AUDIT_ROOT = racine du framework.
    if not args.no_synthese:
        print("\n─── Synthèse ──────────────────────────")
        candidats = [ROOT / "Synthese_audit.py", PYTHON_DIR / "Synthese_audit.py"]
        script = next((c for c in candidats if c.exists()), None)
        if script is None:
            print("[synthese] Synthese_audit.py introuvable (attendu a la racine ou dans Scripts/Python) "
                  "- synthese non generee")
        else:
            env = dict(os.environ, AUDIT_ROOT=str(ROOT), PYTHONIOENCODING="utf-8")
            try:
                r = subprocess.run([sys.executable, str(script)], env=env, cwd=str(ROOT),
                                   capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
                sortie = (r.stdout or "").strip()
                if sortie:
                    print(sortie)
                if r.returncode != 0:
                    print(f"[synthese] ERREUR (code {r.returncode}) : {(r.stderr or '').strip()[-1500:]}")
            except Exception as e:
                print(f"[synthese] ERREUR : {e}")

    print("\nTerminé. Les classeurs sont dans le dossier Excel/.")

if __name__ == "__main__":
    main()
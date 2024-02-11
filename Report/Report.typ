#import "Templates_copy_to_delete/Template_default.typ": set_config
#import "Templates_copy_to_delete/Constants.typ": document_data
#import "Templates_copy_to_delete/Util.typ": file_folder, import_csv_filter_categories, insert_code-snippet, insert_figure, to_string, todo, transpose

#show: document => set_config(
	title: smallcaps[Analyse statique de code],
	title_prefix: smallcaps[TD: ],
	authors: (document_data.author.reb, document_data.author.stan).join("\n"),
	context: "Security and privacy 3.0",
	date: datetime.today().display(),
	image_banner: align(center, image("Templates_copy_to_delete/logo_Polytech_Nice_X_UCA.png", width: 60%)),
	header_logo: align(center, image("Templates_copy_to_delete/logo_Polytech_Nice_X_UCA.png", width: 40%)),
)[#document]

#linebreak()
#outline(title: "Sommaire", indent: 1em, depth: 4) <table_of_contents>
#pagebreak()


= BANDIT <bandit>

== Installation

#insert_code-snippet(title: [Installation de `BANDIT`])[```bash
cd ex_1 && python3 -m venv .venv && source ./.venv/bin/activate
python3 -m pip install bandit
python3 -m pip freeze > requirements.txt
bandit --version # bandit 1.7.7: python version = 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
bandit-config-generator -o bandit.cfg.yml
```]

== Analyse de cinq scripts Python

#insert_code-snippet(title: [Analyse sans configuration spécifique des scripts Python dans #file_folder("ex_1/")])[```bash
mkdir -p reports
bandit --recursive . --exclude ./.venv/ --format html --output ./reports/standard.html
bandit --recursive . --exclude ./.venv/ --format txt --output ./reports/standard.txt
```]

#linebreak()

Voici les résultats d'une analyse brute des cinq fichiers #range(1, 5+1).map(n => file_folder(to_string([#n\.py]))).join(", ", last: " et "), sans config.

#align(center, table(columns: 5,
..([Fichier], [CWE], [Sévérité], [Occurences], [Signification de la CWE]),
..(file_folder("1.py"), link("https://cwe.mitre.org/data/definitions/89.html")[CWE-89],		[`MEDIUM`],	"11 lignes",
	[Improper Neutralization of Special\ Elements used in an SQL Command\ ('SQL Injection')]),
..(file_folder("2.py"), link("https://cwe.mitre.org/data/definitions/78.html")[CWE-78],		[`MEDIUM`],	"une fois",
	[Improper Neutralization of Special\ Elements used in an OS Command\ ('OS Command Injection')]),
..(file_folder("3.py"), link("https://cwe.mitre.org/data/definitions/259.html")[CWE-259],	[`LOW`],	"14 lignes",
	[Use of Hard-coded Password]),
..(file_folder("4.py"), link("https://cwe.mitre.org/data/definitions/22.html")[CWE-22],		[`MEDIUM`],	"8 lignes",
	[Improper Limitation of a Pathname\ to a Restricted Directory\ ('Path Traversal')]),
..(file_folder("5.py"), link("https://cwe.mitre.org/data/definitions/89.html")[CWE-89],		[`MEDIUM`],	"20 lignes",
	[Improper Neutralization of Special\ Elements used in an SQL Command\ ('SQL Injection')]),
))


En relançant l'analyse avec le fichier configuration par défaut (donc non configuré), la commande renvoit un code d'erreur (`1`), et on obtient le même rapport que sans configuration (surement un fallback sur une recherche de toutes les vulnérabilités).
Si par contre on active un test pour une vulnérabilité qui n'apparaît pas dans le code (par exemple `B103` : "_set bad file permissions_") en le décommentant parmi les options listées et en l'ajoutant aux tests (sous `tests`), on obtient bien un rapport d'erreur vide

#linebreak()

#insert_code-snippet(title: [Analyse avec configuration des scripts Python dans #file_folder("ex_1/")])[```bash
bandit -r . -x ./.venv/ -f html -o ./reports/specific.html --configfile bandit.cfg.yml
bandit -r . -x ./.venv/ -f txt -o ./reports/specific.txt --configfile bandit.cfg.yml
```]

#pagebreak()

Dans le fichier de configuration, voici la correspondance entre les CWE et les tests `bandit`
- `B610`, `B608` (_django_extra_used_, _hardcoded_sql_expressions_) pour la `CWE-89` (resp. #file_folder("1.py"), et #file_folder("5.py"))
- `B102` (_exec_used_) pour la `CWE-78`
- `B105`, `B106`, `B107` (_[hardcoded\_password\_]_ .._string_, .._funcarg_, .._default_) pour la `CWE-259`
- `B310` (_urllib_urlopen_) pour la `CWE-22`

On a donc décommenté tous les tests, et on a utilisé ceux-ci :
```yaml
tests: [B608, B610, B102, B105, B106, B107, B310]
```
En relançant l'analyse, on obtient bien les même résultats que lors des premières analyses sans configuration

#pagebreak()

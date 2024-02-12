#import "Templates_copy_to_delete/Template_default.typ": set_config
#import "Templates_copy_to_delete/Constants.typ": document_data, line_separator
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


= SEMGREP

== Premier usage de SEMGREP sur des exemples

=== Installation et configuration de SEMGREP

Depuis l'exercice précédent (@bandit), on change d'environnement :

#insert_code-snippet(title: [Installation de `SEMGREP`])[```bash
deactivate # Depuis l'autre Virtual Environment pour l'exerice 1
cd ../ex_2 && python3 -m venv .venv && source ./.venv/bin/activate
python3 -m pip install semgrep
python3 -m pip freeze > requirements.txt
semgrep --version # 1.60.1
```]
```bash semgrep scan --config auto``` avait donné "_```text Missed out on 656 pro rules since you aren't logged in!```_", donc nous nous sommes résolus à nous créer un compte et nous connecter avec\ ```bash semgrep login```. // 💎

Suite au login depuis le terminal :
+ Liaison avec _GitHub_ #insert_figure("Liaison de Semgrep avec GitHub", width: 60%)
+ Création d'une organisation "`security_3.0_static_analysis`"
+ Token de connexion est renvoyé dans le terminal


Nous allons #link("https://semgrep.dev/orgs/-/setup/local")[analyser le code localement], tout en étant connecté à Semgrep depuis le terminal.



#linebreak()


Pour chacun des dossiers #range(1, 4+1).map(n => file_folder(to_string([#n/]))).join(", ", last: " et "), nous allons :
+ Réaliser un scan complet avec `SEMGREP`
+ Identifier les vulnérabilités de sévérité `HIGH`
+ Corriger ces vulnérabilités
+ Vérifier que ces vulnérabilités n'apparaissent plus en refaisant un scan

#pagebreak()



=== Dossier #file_folder("1/")

```bash cd 1 && semgrep ci```

==== Problèmes détectés

#insert_figure("Problèmes trouvés par Semgrep dans le répertoire 1", width: 80%)

- #file_folder("XmlReader_Tests.cs")
	- `25┆ XmlReader reader = XmlReader.Create(stream, settings);`
		- `csharp.dotnet-core.xxe.xml-dtd-allowed.xml-dtd-allowed`
- #file_folder("test.php")
	- `12┆ $document->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);`
		- `php.lang.security.xml-external-entities-unsafe-entity-loader.xml-external-entities-unsafe-entity-loader`
		- `php.lang.security.xml-external-entities-unsafe-parser-flags.xml-external-entities-unsafe-parser-flags`
		- `php.laravel.security.laravel-unsafe-entity-loader.laravel-unsafe-entity-loader`
		- `php.laravel.security.laravel-xml-unsafe-parser-flags.laravel-xml-unsafe-parser-flags`

On va essayer de corriger toutes les vulnérabilités trouvées par ce scan par défaut, c'est-à-dire Medium et High.

Il se trouve que si on se rend sur les details d'une vulnérabilité dans l'interface Semgrep, et qu'on clique sur le bouton ci-dessous, on peut trouver des exemples de soltions.

#insert_figure("Bouton d'exemples de solutions à appliquer", width: 30%)

#pagebreak()

==== Corrections

Pour #file_folder("XmlReader_Tests.cs"), la configuration de Semgrep est telle qu'elle reconnait :
#align(center, table(columns: 3,
	..([], [_source_], [_sink_]),
	..([1], [```cs $X.DtdProcessing = DtdProcessing.Parse```], [```cs XmlReader.Create($C, $SETTINGS, ...)```]),
	..([2], [```cs $X.XmlResolver = new XmlUrlResolver()```], [```cs (XmlTextReader $R).$READ(...)```]),
))
L'idée serait de désactiver le traitement DTD et le XMLResolver ainsi :
#insert_code-snippet(title: [Correction pour #file_folder("XmlReader_Tests.cs")])[```cs
settings.DtdProcessing = DtdProcessing.Prohibit; // Désactiver le traitement DTD
settings.XmlResolver = null; // Désactiver XmlResolver
...
xmlDocument.XmlResolver = null; // Ici aussi
```]

#linebreak()

Pour #file_folder("test.php"), la vulnérabilité XXE vient de l'utilisation de ```php libxml_disable_entity_ loader(false)```.
Pour corriger le problème, on peut modifier ```php libxml_disable_entity_loader(true)```, et ajouter ```php libxml_set_external_entity_loader(static function () { return null; });```.

Bizarrement, #file_folder("test2.php") n'a pas été détecté, mais il faut aussi updater de la même façon que pour #file_folder("test.php").

En relançant le scan, on obtient un écran satisfaisant sans vulnérabilité High ni Medium trouvée :

#grid(columns: 2,
	insert_figure("Toutes les vulnérabilités précédemment trouvées ont été corrigées", width: 90%),
	insert_figure("Récapitulatif de Semgrep en ligne de commande qui indique que tout a été corrigé", width: 90%),
)

#insert_figure("Interface Web de Semgrep avec le rappel des vulnérabilités, dorénavant corrigées", width: 30%)

#pagebreak()


=== Dossier #file_folder("2/") <ex2_2>

```bash cd ../2 && semgrep ci```

==== Problèmes détectés

#insert_figure("Toujours plus de vulnérabilités dans un si petit script", width: 70%)

==== Corrections

On peut sanitiser l'input avec les solutons données dans la page d'aide, à savoir importer le module `xss` :
#insert_code-snippet(title: "Sanitizer HTML proposé par Semgrep")[```js
var xss = require("xss");
...
res.send('<h1> Hello :' + xss(a) + "</h1>");
```]


Pour protéger contre ReDoS (Regular Expression Denial of Service), il faut simplifier le pattern de la regex, pour éviter que la recherche soit exessivement longue si l'input est conçu pour faire câbler une Regex.
Dans notre cas, on peut utiliser ```js var r = /^[a-z]+$/;``` à la place de ```js var r = /^([a-z]+)+$/;```.


#insert_figure("Les résultats qui font plaisir", width: 50%)

#pagebreak()

==== Correction alternative pour sanitiser le direct-input

Ou alors on peut créer notre propre sanitizer, en utilisant une regex qui va attraper tous les caractères suspicieux et renvoyer leur équivalent sanitisé depuis un mapping issu d'un dictionnaire :
#insert_code-snippet(title: "Sanitizer HTML fait-maison")[```js
const escapeHTML = str => str.replace(/[&<>'"]/g, tag => ({
	'&': '&amp;',
	'<': '&lt;',
	'>': '&gt;',
	"'": '&#39;',
	'"': '&quot;',
}[tag]));
```]

Mais si on fait ça, il faut l'ajouter dans les règles de Semgrep, pour qu'il le reconnaisse comme un sanitizer avec quelque chose comme
#insert_code-snippet(title: "Règles à ajouter pour Semgrep")[```yaml
pattern-sanitizers:
  - patterns:
      - pattern-either:
          - pattern-inside: |
              const escapeHTML = $P => $P.replace(/[&<>'"]/g, $I => ({
                  '&': '&amp;',
                  '<': '&lt;',
                  '>': '&gt;',
                  "'": '&#39;',
                  '"': '&quot;',
              }[$I]));
              ...
      - pattern: escapeHTML(...)
```]
Mais c'était un peu trop long à setup dans l'interface en ligne, alors on a eu recourt aux propositions, telles que ```js require('xss')```.


#pagebreak()


=== Dossier #file_folder("3/")

```bash cd ../3 && semgrep ci```

==== Problèmes détectés

#insert_figure("Vulnérabilités trouvées dans le dossier 3", width: 70%)

==== Corrections

Pour `raw-html-format`, il ne faut pas renvoyer de html directement : ```js res.send('Hello :' + name);``` plutôt que ```js res.send('<h1> Hello :'+ name +"</h1>")```, ou alors utiliser DOMPurify.

Pour `direct-response-write`, on peut sanitiser avec ```js const xss = require("xss");``` puis ```js xss(name)``` comme l'exercice précédent (@ex2_2).

Pour `taint-unsafe-echo-tag`, on peut utiliser `htmlentities` ou `htmlspecialchars` de PHP pour sanitiser.
Le seul endroit où ça ne fonctionnerait pas, ce serait si le php était invoqué dans un contexte ```html <script> </script>``` dans lequel on pourrait appeler des fonctions et ainsi invoquer du code sans avoir besoin de charactères tels que `"`, `'`, `<`, `>`, etc. Mais là ce n'est que du php donc ça va, `htmlentities` fera l'affaire.

#insert_figure("Alerts gone..", width: 25%)

#pagebreak()

=== Dossier #file_folder("4/")

```bash cd ../4 && semgrep ci```

==== Problèmes détectés

#insert_figure("Vulnérabilités sur le répertoire 4", width: 60%)

==== Corrections

Il faut éviter de redigirer vers un domaine géré par l'input, donc préfixer par un domaine de confiance.
Dans notre cas, nous ne savons pas quel domaine mettre pour cette appli', donc nous allons mettre example.com, dans #file_folder("koa.js").
Pour la redirection dans #file_folder("aa.js"), on peut renvoyer une page pour demander à l'utilisateur s'il veut bien être redirigé vers une autre page (Cf #file_folder("aa.js")).

Ça a introduit une vulnérabilité low (javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag) mais on va dire qu'on va l'ignorer car on a déjà sanitisé l'input.

#insert_figure("Après quelques essais-erreurs, on arrive à une correction satisfaisante")

#linebreak()
#line_separator
#linebreak()

#insert_figure("Récapitulatif des corrections", width: 60%)

#pagebreak()

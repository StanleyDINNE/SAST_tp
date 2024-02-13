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
#align(center)[Le code #link("https://github.com/StanleyDINNE/SAST_tp")[StanleyDINNE/SAST_tp] est sur GitHub.]

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
#insert_figure("Liaison de Semgrep avec GitHub", width: 40%)
+ Liaison avec _GitHub_
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

Ça a introduit une vulnérabilité medium (javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag) mais avec une faible confiance donc on va dire qu'on va l'ignorer car on a déjà sanitisé l'input.

#insert_figure("Après quelques essais-erreurs, on arrive à une correction satisfaisante")

#linebreak()
#line_separator
#linebreak()

#insert_figure("Récapitulatif des corrections", width: 60%)

#pagebreak()

== Audit d'une application complète avec SEMGREP

=== Réinstalltion dans un environnement propre

On réinstalle juste Semgrep dans un autre Virtual Environment pour avoir une installation propre (même si on aurait pu réutiliser celle de #file_folder("ex_2/")).

#insert_code-snippet(title: "Réinstallation de semgrep dans un environnement clean pour l'exercice 3")[```bash
deactivate && cd ../../ex_3 && python3 -m venv .venv && source ./.venv/bin/activate
python3 -m pip install pyotp flask qrcode # Utilisés à plusieurs endroits, mais tous les trois en même temps dans "mod_mfa.py"
python3 -m pip install semgrep
python3 -m pip freeze > requirements.txt
```]

`$ ````bash semgrep ci```

#insert_figure("Uh oh...", width: 40%, border: false)

#insert_figure("Extrait des vulnérabilités (HIgh) trouvées dans ex_3", width: 60%)


Dans un à plusieurs fichiers pour chacune, on a

#[
	#show text: t => align(left)[#t]
	#show enum: e => align(left)[#e]

	#let vulns = (
		high: (`sqlalchemy-execute-raw-query`, `avoid_hardcoded_config_SECRET_KEY`),
		medium: (`django-no-csrf-token`, `formatted-sql-query`, `avoid_using_app_run_directly`, `debug-enabled`, `missing-integrity`),
		low: (`request-with-http`,)
	)

	#align(center, table(columns: 3,
		..([Sévérité],	[Nombre de vulnérabilités],	[Vulnérabilités]						),
		..([HIGH],		[#vulns.high.len()],		vulns.high.map(v => [+ #v])		.join[]	),
		..([MEDIUM],	[#vulns.medium.len()],		vulns.medium.map(v => [+ #v])	.join[]	),
		..([LOW],		[#vulns.low.len()],			vulns.low.map(v => [+ #v])		.join[]	),
	))
]

=== Analyse et correction des problèmes trouvés <vulns_app_complete_semgrep>

+ `avoid_hardcoded_config_SECRET_KEY` nécessite que l'on n'hardcode pas les secret dans l'application, ni même dans un fichier d'envionnement visible dans le dépôt GitHub. Les secrets doivent être dans des variables d'environnement, seulement en local.
	Ainsi, on peut faire les modifications nécessaires dans les fichiers #file_folder("vulpy*.py") : ```python
import os
...
app.config['SECRET_KEY'] = os.environ['VULPY_SECRET_KEY']
```
	Si on utilise `bash` par exemple, il faudrait définir ```bash export VULPY_SECRET_KEY='aaaaaaa'``` dans #file_folder("~/.bashrc").

+ `sqlalchemy-execute-raw-query` nécessite que l'on sanitize les input utilisateur qui pourraient entrer dans une query SQL, pour éviter les risques de SQL injections, comme les bases de données sont des éléments critiques. Selon #link("https://stackoverflow.com/a/14372802")[ce commentaire sur le sujet des SQL injections sur Stack Overflow].
	Ainsi, on modifie les fichiers #file_folder("db.py"),  #file_folder("db_init.py")  en utilisant des requêtes préparées / paramétrées, notamment en remplaçant ```python for ...: Connection.execute``` par ```python Connection.executemany``` pour les deux premiers fichiers, et par exemple ```python c.execute("UPDATE users SET password = ? WHERE username = ?", (password, username))``` pour une des lignes du troisième.

+ `django-no-csrf-token` indique que la méthode de django pour éviter les CSRF n'a pas été utilisée. On peur s'aider de #link("https://docs.djangoproject.com/en/4.2/howto/csrf/")[la documentation sur leur site à ce sujet], pour ainsi corriger les problèmes dans les fichiers dans #file_folder("templates/") que sont
	#file_folder("mfa.enable.html"),
	#file_folder("posts.view.html"),
	#file_folder("user.chpasswd.html"),
	#file_folder("user.create.html"),
	#file_folder("user.login.html"),
	#file_folder("user.login.mfa.html") et
	#file_folder("welcome.html").
	En somme, tous les fichiers utilisant un ```html <form method="POST">...</form>``` à remplacer avec ```html <form method="POST">{% csrf_token %} ...</form>```.
	#insert_figure("Conseil de la doc de django sur les CSRF")

	#linebreak()

	#insert_figure("Point sur la progression sur la correction des problèmes détectés", width: 70%)

	#(linebreak()*2)
	#line_separator
	#(linebreak()*2)



+ `missing-integrity` dans le fichier #file_folder("templates/csp.html") est soulevée par Semgrep car il faudrait ajouter un paramètre `integrity` avec le hash du script à importer dans la balise ```html <script/>```.
	Pour cela, je commence par télécharger le script en local en allant à l'URL, (ici https://apis.google.com/js/platform.js), je le hash avec ```bash sha256sum``` en local et je modifie la balise ainsi : ```html <script ...
integrity="sha256-0bcb6531cb0967359e17b655d4142b55d1eac2aed3fe5340f8ce930a7000e5d3">
</script>``` (on aurait aussi pu utiliser ```bash openssl sha256 platform.js``` pour donner un équivalent à ```sha256sum platform.js```).


+ `avoid_using_app_run_directly` (pour les fichiers #file_folder("vulpy-ssl.py") et #file_folder("vulpy.py")), problème de Broken Access Control, pour lequel il faut mettre les appels à ```python app.run()``` derrière "une garde" (comme une fonction, ou un ```python if __name__ == '__name__': ...```).
	Nous avons décidé d'utiliser ```python if __name__ == '__name__': ...```, comme c'est une best-practice en Python, qui permet notamment d'indiquer que le fichier est un script exécutable et non juste une librairie.


+ `debug-enabled`, toujours avec les deux même fichiers #file_folder("vulpy-ssl.py") et #file_folder("vulpy.py"), indique que ```python debug=True``` en tant que paramètre de ```python app.run``` est problématique : si l'app' est lancée en production avec cette configuration, des info' sensibles peuvent potentiellement leak dans les logs.
	Il vaut mieux préférer set cette valeur avec des variables d'environnement, en la définissant par défaut à ```python False``` si non définie. Par exemple avec ```python
DEBUG = (_.lower() == 'true') if (_ := os.environ.get("VULPY_DEBUG", None)) is not None else False
app.run(..., debug = DEBUG, ...)
```
	En fait, ```python os.environ``` va load les variables d'environnement en tant que string par défaut, et toute string non vide est considérée comme True.
	On va donc utiliser cette expression ternaire créée de toute pièce va vérifier que la variable d'environnement est bien définie à `'true'`, ou `'True'`, etc.
		- Si oui, on vérifie que sa version minuscule correspond bien à ```python 'true'```, auquel cas on renvoit ```python True```
		- Si non, on renvoie simplement ```python False```, la valeur par défaut.
	Nous avions déjà importé ```python os``` lors du patch sur les secrets précédemment, donc pas besoin de le réimporter.
	Évidemment, il faut aussi définir la variable d'environnement (comme pour les secrets avant) en local.

+ La dernière `request-with-http` trouvée dans les fichiers #file_folder("api_list.py") et #file_folder("api_post.py") est explicite d'elle-même. Le problème pour la corriger est que si on fait un appel à un site qui ne supporte pas `HTTPS` mais juste `HTTP`, on ne peut pas faire grand chose de plus (à notre connaissance). Là c'est une requête vers la loopback (`127.0.0.1`) donc on peut mettre https si on setup correctement en local avec les certificats, et tout.
On va modifier en supposant que les admin' de la machine du serveur auraient fait les bonnes config' et générations de certificats.

#insert_figure("Toutes les vulnérabilités trouvées par Semgrep ont été corrigées", width: 25%)

#pagebreak()


== Création d'application avec vulnérabilité non détectée par SEMGREP

```bash
cd ../ex_4/
```

=== Premières idées <premières_idées>

La première idée que nous avons eu était de berner Semgrep. C'est-à-dire écrire du code vulnérable, mais en le camouflant, afin qu'une analyse statique avec des patterns ne puisse pas la détecter.

Un exemple tout bête : si une règle détecte l'usage de la fonction d'exécution de code sous forme de string dans Pythnon ```python exec```, il suffit de l'invoquer sans utiliser son nom.
On peut la récupérer du dictionnaire des variables globales et l'appeler :
#insert_code-snippet(title: [Exemple simple d'un appel à ```python exec(...)``` non détecté par un SAST])[```python
getattr(
	globals()['__builtins__'],
	'e' + 'xQc'.replace('Q', 'e')
)('''
arbitrary = lambda: print("Exécution de code issu d'une string")
arbitrary()
''')
```]
On a passé le modules des builtins présent dans l'environnement global dans la fonction `getattr` qui va récupérer la fonction associée `'exec'` (string obfusquée aux regard des SAST) puis passer le paramètre qui est le code à exécuter, sous forme de string (qui peut venir un input non sanitisé).


=== Application vulnérable

Nous avons utilisé #link("https://www.zaproxy.org/")[Zap] comme DAST et nous nous sommes inspirés du #link("https://github.com/AchrafEL-BACH/SAST_Lab/blob/main/ex_4/vuln.py")[code d'Achraf & Sarah] : les fichiers de l'application _Flask_ sont dans #file_folder("ex_4/"), que l'on lance simplement avec ```bash python3 vulnerable.py```.


Même en sanitisant l'input, Semgrep trouve toujours à tord qu'il y a une vulnérabilité `directly-returned-format-string`, de sévérité medium.
Par contre, ce qu'il ne voit pas et que Zap voit (Cf @zap), c'est l'absence de token pour prévenir les CSRF.

#insert_figure("Zap trouve l'absence de token CSRF", width: 70%) <zap>

#insert_figure("Semgrep donne des faux positifs, et met en faux négatif le CSRF", width: 60%)

Le problème ici n'est pas que Semgrep n'est pas capable de détecter l'absence de ce token, puisqu'il l'a fait pour `django-no-csrf-token` dans le @vulns_app_complete_semgrep, mais plutôt comment Semgrep fonctionne.
De ce que nous avons compris, il utilise un ensemble de fichiers de règles pour trouver des patterns, et à l'aide notamment de logique de source et sink, il va pouvoir déterminer si tel morceau de code correspond à un pattern (ils essayent d'être exhaustifs) de vulnérabilité connu.

Sauf que là, la vulnérabilité et dans une string renvoyée, qui n'est pas vérifiée par Semgrep.
Et on voit même que, pour une vulnérabilité différente (`directly-returned-format-string`), Semgrep va toujours s'alarmer alors que l'input est sanitisé.

Pour les deux cas, il faudrait lui rajouter des règles, d'une part pour vérifier plus de choses, d'autres part, pour ajouter des sanitizers.

=== Conclusion

Cela n'était qu'un exemple, mais on peut aussi avoir des config' qui ne sont pas vérifiées par un SAST, ou alors des obfuscations qui sortent des patterns comme l'exemple théorique dans le @premières_idées.

# fr — Français · notes

Catalog: `internal/webui/i18n/catalogs/fr.json` · golden: `internal/webui/testdata/golden/fr.txt`

## 1. Audience and register

Francophone security practitioners (France, Belgium, Switzerland, Québec,
francophone Africa): vulnerability management, SOC/CSIRT, patch teams,
researchers. They read CERT-FR *avis*, *alertes* and *bulletins d'actualité*,
the Canadian Cyber Centre's French advisories, CCB (Belgium) and vendor
*bulletins de sécurité*.

- Register of a CERT-FR avis: concise, impersonal, factual. No "nous" (the
  English "we don't give one" becomes "nday n'en publie donc pas"), no
  exclamation marks. The reader is addressed only through imperatives in the
  *vous* form ("Saisissez…", "Élargissez…", "Réessayez…").
- Status paragraphs use **nominal sentences** ("Inscription au KEV 5 jours
  après la divulgation.", "Aucun correctif recensé à ce jour.") — the style of
  French bulletins and, above all, a way to avoid gender agreement with an
  implicit subject.
- Labels are lower case like the English CLI style; headings are sentence
  case ("Journal des événements", "Comment lire les données"), never Title
  Case. Accented capitals are written (É, À: "Étape actuelle", "À propos").
- Standard international French only: no France-only slang, no Québec-only
  terms; "courriel"-type purism avoided where the community uses the
  anglicism (PoC, commit, exploit code is "code d'exploitation").
- Navigation keeps the bare path (`~/hot`, `~/vuln`, `~/stats`, `~/src`) like
  English: French IT readers parse it, and a word would overflow at 390px.
- Home list: "Derniers mouvements" (latest moves) — says that something just
  changed, without implying popularity ("tendances") or a calque of "hot".

## 2. Terminology

Sources fetched 2026-11-13 (CERT-FR pages with curl; quotes are verbatim).

| Concept | Wording | Source / why |
| --- | --- | --- |
| vulnerability | vulnérabilité | everywhere in CERT-FR |
| DIS disclosure | divulgation; "publication de la fiche CVE" for the proxy | "divulgation coordonnée des vulnérabilités" is the established term (CCB Belgium, *Politique de divulgation coordonnée des vulnérabilités*, https://ccb.belgium.be/sites/default/files/2024-12/Brochure_CVDP_FR_1.pdf — title via search, not fetched). CERT-FR's own tables use "Date de publication" for the CVE date (https://www.cert.ssi.gouv.fr/actualite/CERTFR-2026-ACT-047/), hence the T- wording "avant la publication de la fiche CVE". |
| CVE record | fiche CVE (officielle) | practitioner usage; "enregistrement CVE" is a calque. nday's own empty stub is "enregistrement vide" to keep it distinct. |
| PAT patch | correctif; "version corrigée" for fixed version | CERT-FR: "Le CERT-FR recommande l'application des correctifs dans les plus brefs délais" (https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-010/) |
| advisory | avis (de sécurité); vendor *bulletin de sécurité* | CERT-FR: "Metabase a publié un avis de sécurité" (ALE-010); "Alpine a publié un bulletin de sécurité" (ALE-015) |
| vendor | éditeur | CERT-FR bulletin table header "Editeur Produit Identifiant CVE CVSS (source)" (ACT-047) |
| POC public PoC | preuve de concept publique (prose), PoC publique (tight labels) | CERT-FR: "Le CERT-FR a également connaissance d'une preuve de concept publique" (https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-011/); column "Exploitabilité (Preuve de concept publique)" (ACT-047). Exploit-DB entries: "code d'exploitation public". |
| ITW exploited in the wild | exploitation active; "activement exploitée"; "exploitation active signalée" | CERT-FR: "La CISA indique que cette vulnérabilité est activement exploitée" (ALE-011); "Ivanti indique que les vulnérabilités … sont activement exploitées" (ALE-013). "exploitée dans la nature" is a calque CERT-FR does not use. |
| KEV | catalogue des vulnérabilités exploitées connues (KEV) de la CISA; short "KEV", "inscription au KEV" | Canadian Centre for Cyber Security AL26-015: "Cette vulnérabilité a été ajoutée au catalogue des vulnérabilités exploitées connues (KEV) de la Cybersecurity and Infrastructure Security Agency (CISA)" (https://cyber.gc.ca/fr/alertes-avis/al26-015-vulnerabilite-critique-touchant-microsoft-sharepoint-server-cve-2026-45659 — quote from search result; the site returns 403 to scripts). "la CISA" is feminine as in CERT-FR ("La CISA indique…"). |
| due date | date limite de remédiation | ANSSI uses "remédiation": "L'ANSSI publie un corpus de guides dédiés à la remédiation d'incidents cyber" (https://cyber.gouv.fr/actualites/lanssi-publie-un-corpus-de-guides-dedies-la-remediation-dincidents-cyber — title via search). "date limite" is plain French for a deadline. |
| forensic triage | recherche de compromission | CERT-FR section heading "Recherche de compromission" (ALE-010) — what CISA asks for, in CERT-FR's own words; "triage forensique" is a calque. |
| ransomware | rançongiciel | CERT-FR: "LockBit est un rançongiciel fonctionnant sous le modèle économique du Ransomware-as-a-Service"; report title "État de la menace rançongiciels à l'encontre des entreprises et institutions" (https://www.cert.ssi.gouv.fr/cti/page/6/) |
| CVSS severity | gravité critique / élevée / moyenne / faible / nulle | CERT-FR "vulnérabilités critiques" (ACT-047); scale names Faible / Moyenne / Élevé / Critique (Trend Micro FR, https://www.trendmicro.com/fr_fr/what-is/attack-surface/cvss-common-vulnerability-scoring-system.html: "niveaux de gravité qualitatifs : Faible Moyenne Élevé Critique"). Written as agreeing with *gravité* (feminine) so the adjective is always right; NONE = "nulle". |
| CVSS score decimal | point (9.8) | CERT-FR prints "9.9 (NVD)" in its bulletin tables (ACT-047); the score is a token anyway. |
| not specified by source | non spécifié | CERT-FR avis: "Non spécifié par l'éditeur" (https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1525/) |
| update (status line) | màj | CERT-FR's own abbreviation: "[Màj] Multiples vulnérabilités dans PHP" (ACT-045) |
| affected versions | vulnérable (column), produits / paquets affectés | CERT-FR "Systèmes affectés" (AVI-1525) |
| CNA | "Fiche CVE publiée par {assigner}" | the CNA short name speaks for itself; no gloss needed |
| SSVC | "Évaluation SSVC de la CISA : exploitation au niveau « active »." | value tokens `active` / `poc` kept, quoted as values |
| bulk import / live | importé en masse / observé en direct | plain description of the data path |
| backfill | rattrapage (status line "à rattraper") | data-engineering usage ("rattrapage de l'historique") |
| collectors | collecteurs | matches the CLI |
| GHSA template / Nuclei | modèle de détection | French for template; "template" left to the tool's own name |
| endpoint | point de terminaison | Microsoft French usage |
| CWE | Faiblesses (CWE) | MITRE's "weakness" |

- 2026-11-14 (`rsch.`, `veil.`, `discussed.`, `nav.discussed`) : « Échanges entre chercheurs » pour la section des publications sur X, « Ce dont parlent les chercheurs » pour `/discussed` ; « publication » pour *post*. Pas de deux-points ni de point-virgule dans ces messages (espace insécable évitée).

## 3. Honesty vocabulary

| Idea | Wording | Where |
| --- | --- | --- |
| unknown | "date inconnue" (all times), "Date de divulgation inconnue.", "Utilisation par des rançongiciels : inconnue." | never "aucune date" for an unknown value except to say what the *source* did ("la source ne donne aucune date") |
| inferred | "déduite (du KEV)", "étape déduite", "déduite, sans source directe", "source de la déduction : …" | feminine because it is only used for the exploitation (ITW) entry or *étape* / *date* |
| not later than | `≤ {date}` + "au plus tard" ("on sait seulement qu'elle a commencé au plus tard à cette date", "date au plus tard uniquement") | "au plus tard" is reserved for this; the KEV deadline uses "date limite … fixée au" to avoid confusion |
| not listed | "non recensée" (PoC panel), "ne figure dans aucune des trois sources de PoC", "Aucune inscription au catalogue KEV de la CISA à ce jour." | "à ce jour" = as of now, says nothing about safety |
| no record yet | "aucune donnée" (values), "Aucune donnée à ce jour.", "Aucun correctif recensé à ce jour." | never "pas de correctif" / "non corrigée" |

## 4. Typography

- No-break spaces are typed as characters: U+00A0 before `:` and inside
  `« »`; U+202F (fine) before `;` `?` `!` (also in `strip.sep`). The catalog is
  generated from plain text by a script that applies these rules, so they are
  consistent everywhere.
- Typographic apostrophe `’` everywhere (CERT-FR mixes `'` and `’`; we use one).
- « guillemets » around upstream titles and quoted UI terms; parentheses
  around the Metasploit/Nuclei titles keep the guillemets inside.
- Lists: "a, b et c" — no serial comma (`list.and.end` = "{a} et {b}").
- `sentence.joiner` is a space. Weekdays "lun. mar. mer. jeu. ven. sam. dim."
  (CLDR abbreviations) and placed before the date ("lun. 2026-11-09"), the
  French order.
- Numbers come from the registry: U+202F grouping, grouping from 1 000
  (`min_group_digits` 1, CLDR fr). Plural rule: 0 and 1 singular ("0 jour",
  "0 résultat").
- Sentences never start with a digit where it can be avoided ("Il reste {n}
  anciennes CVE…", "Identifiants en attente de rattrapage : {n}.").
- Times with a possibly-unknown value are placed after a label and a colon
  ("Divulgation : {time}.", "Inscription au catalogue KEV de la CISA :
  {date}.") so "date inconnue" fits as well as an ISO time.

## 5. Agreement and elision around placeholders

- No placeholder follows *de / le / à* where it could need elision; source
  names and versions are the subject or after a colon ("{source} a signalé…",
  "Versions corrigées : {versions}.").
- Stage names (`stage.name`) are nouns; anything said about them uses an
  invariant noun ("{stage} : étape franchie", "étape déduite du KEV").
- Plural-sensitive messages vary per form: `status.patch.fixed`,
  `status.patch.fixed_many`, `ev.ghsa.fixed`, `ev.ghsa.fixed_many`
  ("une autre" / "{more} autres"), `status.poc.some` ("une seule des 3" /
  "2 des 3"), `search.truncated`, `hot.side.backlog_text`, `src.backfill.p1`,
  `tplus.title.*`, `status.lead.*`, `products.count`, `sbar.*`,
  `chart.mark.more`, `chart.unknown.fixed_many`.
- Participles agree with an implicit noun that is fixed by the context:
  `ev.obs.*` "importé / observé" (événement), `chart.mark.implied` /
  `chart.unknown.implied` / `ev.implied.note` "déduite" (exploitation),
  `marker.known` / `marker.hollow` "franchie" (étape), `vuln.poc.listed` /
  `not_listed` "recensée" (vulnérabilité), `precision.short.exact` "exacte"
  (heure), `vuln.rejected.replaced_by` "Remplacé" (identifiant),
  `collector.never_run` "jamais lancé" (collecteur), `js.copied_id`
  "{id} copié" (identifiant).

## 6. Open doubts

- Gender of **PoC**: French practitioners say both "un PoC" and "une PoC".
  This catalog follows the expanded term CERT-FR uses (*une preuve de concept*)
  and writes "PoC publique" in tight labels (`stage.name.POC`,
  `legend.stage.poc`, `src.*.produces`, `feed.summary.change.POC`). A native
  editor may prefer the masculine; change those keys together.
- `vuln.fix.commits` (16 cols): "commits" alone; "commits de correction"
  does not fit. The panel context ("Versions et correctifs") carries the rest.
- `help.o` (48 cols): "(page de vuln.)" abbreviated.
- `fact.tplus_note_unknown` (24 cols): "DIS : date inconnue" uses the code
  because "date de divulgation inconnue" is 28 columns.
- `statusline.vulns`: "vulns" (jargon) — "vulnérabilités" does not fit 14
  columns.
- `chart.now`: "auj." (aujourd'hui) for the present-time line.
- `hot.empty`: "sur {window}" with the token (`24h`, `7d`) — "sur 7d" mixes a
  French preposition and an English unit token; acceptable as a CLI token.
- `stats.lede_at`: the ISO time can wrap at its hyphen on mobile
  ("2026-11-" / "13T02:06Z"); a template/CSS matter (no-wrap on time tokens),
  not wording.
- CVSS severity in the facts row is shown by the template as the upstream
  token (`8.1 HIGH v3.1`), while the event text says "gravité élevée" — fine
  for practitioners, but a localised token would be more consistent.
- "fiche CVE" vs "enregistrement CVE": chosen for naturalness; the CVE
  Program has no official French term.

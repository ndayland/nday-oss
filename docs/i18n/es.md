# es — Español · notas

Catálogo: `internal/webui/i18n/catalogs/es.json` · golden: `internal/webui/testdata/golden/es.txt`

## 1. Público y registro

Profesionales de seguridad y TI de España y Latinoamérica: gestión de
vulnerabilidades y parches, SOC/respuesta a incidentes, equipos azules,
investigadores. Leen a diario los avisos de INCIBE-CERT, las alertas de
CCN-CERT y de los CSIRT nacionales (p. ej. las «Alertas integradas de
seguridad digital» del CNSD de Perú), los boletines de los fabricantes y el
catálogo KEV de CISA (casi siempre en inglés).

- Español neutro internacional: sin voseo, sin «ordenador/computadora», sin
  «días naturales» (España) ni «días calendario/corridos» (América): se
  escribe «días transcurridos, por fecha UTC». «Presionada» (no «pulsada»),
  «notificó» (no «reportó» ni «informó de»).
- Registro de aviso técnico: frases impersonales con «se» o nominales
  («Fecha de divulgación: …»), sin tú ni usted. Las instrucciones van en
  infinitivo, como el apartado «Solución» de los avisos de INCIBE-CERT
  («Actualizar a 4.37.0F…»): `hot.empty`, `err.timeout.message`.
- Etiquetas de interfaz en minúscula, como en la versión inglesa
  (`etapa`, `divulgación`, `cvss`); títulos en mayúscula solo inicial
  («Fuentes de datos», «Cómo leer los datos»), nunca Title Case.
- Navegación: solo la ruta (`~/hot`, `~/vuln`…), sin glosa: el lector
  técnico hispanohablante la entiende y así no se desborda la cabecera a
  390 px.
- La portada se llama «Cambios recientes» (como «Cambios recientes» de los
  wikis): neutro, no sugiere popularidad («tendencias», «lo más caliente»)
  ni calca «Just moved».

## 2. Terminología

| Concepto | Término elegido | Fuente / por qué |
| --- | --- | --- |
| vulnerability | vulnerabilidad | uso universal (INCIBE-CERT, CNSD Perú) |
| DIS / disclosure | divulgación | INCIBE-CERT: «realiza la divulgación pública de la nueva vulnerabilidad» (política CVD, https://www.incibe.es/incibe-cert/sobre-incibe-cert/politica-reporte-vulnerabilidades). «Publicación» queda para el registro CVE («se publicó el registro CVE»). |
| PAT / patch | parche; «parche registrado» como etapa | INCIBE-CERT: «el parche que corrige la vulnerabilidad ya ha sido desplegado» (feed de avisos, https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed, 12/11/2026). Se evita «parche publicado» porque nday no conoce la fecha de publicación del parche (solo la del aviso). |
| fixed version | versión corregida | INCIBE-CERT: «Migrar las ramas fuera de soporte a una versión corregida» (aviso Arista EOS, mismo feed). CNSD Perú usa «versiones parcheadas». |
| affected | afectado/a; «versiones afectadas» | INCIBE-CERT: sección «Recursos afectados»; «También están afectadas las versiones 2.0.8 a 2.0.42» (aviso Apache HTTP Server, mismo feed). |
| advisory | aviso (boletín para los mensuales de fabricante) | INCIBE-CERT titula «Aviso» cada entrada y «Boletín de seguridad de Microsoft de noviembre de 2026» los mensuales (mismo feed). |
| vendor | fabricante | INCIBE-CERT: campo «Fabricante» (mismo feed). |
| POC | PoC pública / prueba de concepto | CNSD Perú: «No hay evidencia de que exista una prueba de concepto pública» (Alerta integrada 124-2025, https://cdn.www.gob.pe/uploads/document/file/8142595/6819398-alerta-integrada-de-seguridad-digital-124-2025-cnsd.pdf); «los PoC públicos» (Alerta 040-2026). Se usa en femenino (*la* prueba de concepto). |
| exploit (Exploit-DB) | exploit público | INCIBE-CERT (fichas de vulnerabilidades): «El exploit ha sido divulgado al público y puede utilizarse»; CNSD: «El exploit se ha hecho público». Préstamo asentado. |
| ITW / exploited in the wild | explotación activa; «se está explotando activamente» | INCIBE-CERT: «una de severidad media en Outlook que se está explotando activamente» y «Microsoft confirma explotación activa» (boletín Microsoft nov. 2026, mismo feed); CNSD Perú: «Investigadores… han reportado la explotación activa». Nunca «en la naturaleza / en lo salvaje». |
| KEV | catálogo de vulnerabilidades explotadas conocidas (KEV) de CISA; «el KEV» en frases cortas | NinjaOne (es): «El catálogo de vulnerabilidades explotadas conocidas (KEV) de la CISA identifica vulnerabilidades que se están explotando activamente» (https://www.ninjaone.com/es/blog/gestion-vulnerabilidades-cisa-kev/); Malwarebytes (es): «catálogo de Vulnerabilidades Explotadas Conocidas (KEV, por sus siglas en inglés)». No hay nombre oficial en español: duda abierta. |
| added to KEV | inclusión en el KEV / «se incluyó en el KEV» | verbo habitual en la prensa técnica («CISA agregó/añadió… a su catálogo»); «incluir» evita la dicotomía agregar (América) / añadir (España). |
| due date | fecha límite de corrección | Malwarebytes (es): «junto con las fechas límite para su corrección». |
| forensic triage | triaje forense | término de respuesta a incidentes; no encontré uso de INCIBE/CCN-CERT (no verificado): duda abierta. |
| ransomware | ransomware; «uso conocido en campañas de ransomware» | préstamo universal; refleja el campo KEV «Known Ransomware Campaign Use». |
| CVSS severity | severidad crítica / alta / media / baja / ninguna | INCIBE-CERT: «3 vulnerabilidades, 1 de severidad crítica, 1 alta y 1 baja» (aviso Apache); CNSD: «de severidad crítica». Se prefiere «severidad» a «gravedad» por INCIBE. |
| authentication bypass | omisión de autenticación | uso de INCIBE-CERT en títulos de avisos (no se pudo citar un aviso concreto en esta sesión: no verificado). No aparece en el catálogo; los títulos son upstream. |
| CVE ID | identificador CVE (prosa), ID (etiquetas cortas) | INCIBE-CERT: campo «Identificador» / «Identificador CVE». |
| CNA | «{assigner} publicó el registro CVE» | nombre corto tal cual (`GitHub_M`). |
| SSVC | «La evaluación SSVC de CISA asigna a la explotación el valor active» | `active`/`poc` se mantienen como tokens. |
| collectors | recolectores | coherente con la CLI (`nday collect`). |
| backfill | carga histórica | término de ingeniería de datos (carga histórica vs. incremental); más natural que «relleno» o «backfill». |
| bulk import / live | importación masiva / observado en tiempo real | «en tiempo real» es neutro en ambos lados del Atlántico (frente a «en vivo/en directo»). |
| raw | en bruto («JSON en bruto», «registros en bruto») | «datos en bruto» es la expresión habitual. |
| stage | etapa (del ciclo de vida) | |
| timeline | cronología | |
| CWE / weakness | debilidades (CWE) | |

- 2026-11-14 (`rsch.`, `veil.`, `discussed.`, `nav.discussed`): «Debate de investigadores» para la sección de publicaciones en X y para `/discussed` (el título largo superaba 40 columnas); «publicación» para *post* de X.

## 3. Vocabulario de honestidad (fijo)

| Idea | Redacción |
| --- | --- |
| desconocido | valor: «se desconoce» (`time.unknown`); en frases: «se desconoce la fecha de divulgación», «fecha desconocida» (columna del gráfico, leyendas), «Uso en campañas de ransomware: desconocido.» Nunca «sin fecha» ni «ninguno». |
| inferido | «inferida de KEV» (fila ITW), «inferido, sin fuente directa» (entrada del registro de eventos), «se infiere de KEV» (lector de pantalla), «fundamento: …» |
| no posterior a | `≤ {date}` + «solo se conoce un límite superior» |
| no figura | «figura» / «no figura» (fuentes de PoC), «No figura en el KEV de CISA.» (no dice nada de seguridad) |
| sin registro aún | «sin registro aún», «Aún no hay ningún parche registrado.» (nunca «no hay parche»), «Hay constancia de…» para lo que sí consta |
| sin indicar | `value.not_given`: la fuente existe pero no da el valor |
| importación masiva vs. tiempo real | «importación masiva, no observado en tiempo real» / «observado en tiempo real» |

## 4. Tipografía

- Comillas latinas «…» para títulos upstream y términos citados de la
  interfaz (recomendación de la Ortografía de la RAE, 2010; las
  latinoamericanas “…” también serían válidas, pero se elige una sola).
- Signos de apertura ¿ ¡: el catálogo no contiene preguntas ni
  exclamaciones.
- Números: agrupación con punto y sin agrupar los de cuatro cifras (`1779`,
  `45.965`), según la RAE y CLDR (`min_group_digits: 2` en el registro, sin
  cambios).
- Decimales de CVSS: `{score}` es un token y sale tal cual («CVSS 9.8»). Es lo
  que hace INCIBE-CERT («8.8 | CVSS:4.0/…», mismo feed), aunque la norma
  hispana sería coma decimal y algunos medios escriben «9,8». Duda abierta.
- Listas: «a, b y c» (sin coma de Oxford). No se aplica el cambio y→e porque
  los elementos son tokens (nombres de fuentes, paquetes).
- `sentence.joiner` = espacio; `strip.sep` = «; »; la etiqueta del lector de
  pantalla va entre paréntesis («Ciclo de vida (divulgación: ocurrió; …)») para
  no encadenar dos pares de dos puntos.
- Días de la semana abreviados en minúscula: lun mar mié jue vie sáb dom.

## 5. Concordancia con marcadores

Para que el género/número nunca dependa del valor insertado:

- etiqueta + dos puntos: `strip.slot` («{stage}: ocurrió»), `status.disclosed_at`
  y `status.kev.at` («Fecha de…: {time}.», que admite también «se desconoce»),
  `status.patch.fixed*`, `ev.ghsa.fixed*`, `feed.summary.change`.
- verbos impersonales o invariables: `strip.slot[implied]` «se infiere de KEV»,
  `hot.empty` (el código de etapa es token; la ventana va entre paréntesis
  para no concordar «las últimas 24h / los últimos 7d»).
- plural real donde lo exige el número: `status.poc.some` («La recoge 1…» /
  «La recogen 2…»), `hot.side.backlog_text`, `src.backfill.p1`,
  `search.truncated`, `search.too_short`, `products.count`, `sbar.*`.
- concordancia fija conocida: `chart.mark.implied`, `chart.unknown.implied`
  («inferida», siempre la fila ITW = explotación); `ev.kev.added` («la
  incluyó» = la vulnerabilidad); `stage.short` (participios en femenino que
  concuerdan con «vulnerabilidad»: divulgada, parcheada…);
  `vuln.rejected.replaced_by` «Sustituido por {ids}» (concuerda con «este
  identificador», no con la lista).

## 6. Dudas abiertas

- `time.unknown` (máx. 16 col.): lo natural sería «fecha desconocida» (17).
  Se usa «se desconoce», invariable y correcto como valor, pero la columna
  del gráfico (`chart.col.unknown`) sí dice «fecha desconocida».
- `fact.tplus_note_unknown` (máx. 24): «fecha de DIS desconocida» usa el
  código; «fecha de divulgación desconocida» no cabe.
- `statusline.updated_unknown` (máx. 20): «act.: se desconoce», abreviado.
- `vuln.fix.commits` (máx. 16): «commits» a secas; «commits de corrección»
  no cabe (el título del panel ya da el contexto).
- `vuln.fix.col.eco` «ecosist.» abreviado (máx. 10).
- `src.col.last_run` «última ejec.» abreviado (máx. 14).
- Nombre en español del catálogo KEV: no hay traducción oficial de CISA;
  se usa la de la prensa técnica.
- «triaje forense»: sin fuente de CERT hispano verificada.
- Coma decimal en CVSS (ver §4).
- `status.patch.no_version` repite «parche» tras un lead PAT («Hay constancia
  de un parche el mismo día… Hay un parche registrado, pero…»): efecto de
  la división en frases; igual en inglés.
- La hora ISO puede partirse por el guion en pantallas estrechas
  («2026-11-␤13T02:06Z» en `stats.lede_at`): es del token, no del texto.

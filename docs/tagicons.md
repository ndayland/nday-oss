# Tag icons

Product tags and ecosystem tags show the brand mark of what they name in
front of their label, wherever a tag chip is drawn: the vulnerability page
(the tag block and "why these tags"), `/tags`, the heading of a tag page,
and the tag filter chips of the hot list, the catalogue and search. The
marks come from [Simple Icons](https://simpleicons.org) and are bundled
into the site, so a reader's browser never contacts a third party for them.

Code: `internal/tags/icons.go` (the mapping), `tools/tagicons` (the
generator), `internal/webui/tagicons.go` (lookup and the rendering switch),
the `tagicon` template in `internal/webui/templates/parts.tmpl`, and the
`.tgi` rules in `internal/webui/static/app.css`. Generated files:
`internal/webui/static/tagicons.svg` and `tagicons.css`. Licence notes:
`internal/webui/static/tagicons.NOTICE`.

## Rendering

The icon is decorative (`aria-hidden`); the label stays the accessible
name. It's monochrome (`currentColor`), about one cap height square, and
follows the chip's colour in both themes and on hover. A tag without an
icon renders exactly as it did before.

There are two renderings, chosen by the constant `TagIconMode` in
`internal/webui/tagicons.go`:

- `TagIconUse` (the default): `<svg class="tgi"><use href="/static/tagicons.<hash>.svg#php"/></svg>`.
  Each chip carries only that reference; the sprite is one immutable,
  cached file.
- `TagIconMask`: an empty `<span class="tgi" data-i="php">`, drawn by a CSS
  mask whose image is a `data:` URL in `tagicons.css`. `base.tmpl` links
  that stylesheet only in this mode. It needs no external reference, in
  case a browser refuses `<use>` of the sprite under the page's CSP.

Tests render both.

## On the share card

The vulnerability's link card (`/og/vuln/{id}.png`, `internal/ogcard`)
carries the same mark as a large, faint watermark behind the text: the mark
of the first tag, in the page's tag order, that has an icon (`cardMark` in
`internal/webui/ogcard.go`); no such tag, no watermark. The path data is
read from the embedded `tagicons.svg` (`tagIconPaths`), so the sprite stays
the only copy, and rasterised by the card's own small path parser
(`internal/ogcard/svgpath.go`, `mark.go`). Size, position and opacity are
the `mark*` constants in `mark.go`. The mark's slug is part of the card's
key, so a different mark is a different card URL. `TestTagIconPathsRasterise`
checks that every symbol of the sprite parses and draws something.

Without an icon the card uses the product's name as the watermark instead,
big faint bold text in the bottom right corner, behind the lifecycle
strip and clear of the id and the title, one line of at most the name's
first two words (`cardWordmark`,
`ogcard.Card.Wordmark`, `internal/ogcard/wordmark.go`): the short
name of the first product tag (`tags.ShortName`: the name in common use
where the label is long, `internal/tags/shortnames.go`, else the label), else the first affected product with a usable name (or
its vendor when the product is a placeholder). Placeholders ("n/a",
"unknown", ...) and names with no Latin letter or digit are skipped; no
name, plain card. The name is part of the key.

## Which tags have an icon

Only tags of the product and ecosystem dimensions. The rule is "never
guess": a tag gets a mark only when it's the brand of the tag.

1. The product's (or ecosystem's) own mark, if the set has it.
2. Otherwise the mark of the vendor that makes the product, if the set has
   it (FortiOS uses Fortinet's, PAN-OS Palo Alto Networks', ESXi VMware's).
   Several tags can share one vendor mark.
3. Otherwise no icon. No generic symbol, no merely similar mark, no other
   company's logo, no mark of a different product of the same company.

`internal/tags/icons.go` is the list; its comments split own marks from
vendor marks. As of Simple Icons 16.38.0, 128 of the 202 product tags and
11 of the 12 ecosystem tags have an icon (112 distinct marks).

Without an icon:

- The brand isn't in Simple Icons. Microsoft: windows, windows-server,
  edge, internet-explorer, sql-server, exchange, sharepoint, outlook, teams,
  office, visual-studio, vscode, dynamics-365, microsoft-defender,
  remote-desktop-client. Oracle: solaris, oracle-database, oracle-ebs,
  peoplesoft, jd-edwards, siebel, weblogic. IBM: ibm-i, aix, db2, powervm,
  websphere, maximo, qradar, ibm-verify-access. Adobe: acrobat, aem,
  coldfusion, magento. Others: arista-eos, arubaos, axis-os,
  check-point-quantum, fireware, sophos-firewall, ivanti-connect-secure,
  ivanti-epm, codesys, zephyr, xen, liferay, concrete-cms, xwiki, zimbra,
  foxit-pdf, pdf-xchange, wso2-identity-server, suricata, zabbix, nagios,
  solarwinds-platform, cacti, glpi, freerdp, screenconnect, open-webui,
  anything-llm, flowise, openclaw, imagemagick, libxml2, netty, wolfssl,
  bouncy-castle.
- A related mark exists, but it isn't this tag's brand: netscaler (only the
  Citrix mark; NetScaler is now a brand of its own), mediawiki (only the
  Wikimedia Foundation's mark), openharmony (HarmonyOS is a different
  product), java-se (OpenJDK is a different project's mark).
- The mark is over the generator's size cap (12 KiB of path data): glibc
  (GNU, 14.7 KiB), the composer ecosystem (Composer, 39.6 KiB).

## Adding or changing an icon

1. Find the brand in the Simple Icons data file (`data/simple-icons.json`
   of the package): check that its `title` is the brand you mean and look
   at its `license`. If it names a licence other than CC0-1.0, add a line to
   `tagicons.NOTICE`.
2. Add `"<tag slug>": "<simple icons slug>"` to `Icons` in
   `internal/tags/icons.go`, under own marks or vendor marks.
3. Regenerate (below) and commit the mapping and both generated files.
   Tests fail if a mapping target has no symbol, if a symbol is unused, or
   if a tag outside the product and ecosystem dimensions has an icon.

Wide wordmarks (macOS, OpenSSL, VMware, Siemens and others) are tiny at
chip size. They're the brand's own mark, so they're kept; remove the line
if one doesn't read well.

Wide wordmarks are left out: at the chip's size (about 13px square) a mark
whose shorter side comes out under about 4.5px is an unreadable line. Checked
in a browser on 2026-11-17, these were dropped for that reason: hcl, vmware,
sonicwall, siemens, qnap, openssl, zoom, macos, amd, synology,
junipernetworks, splunk. Look at a new icon at chip size before adding it.

Licences: an icon is used only when the data file gives it no licence (CC0)
or an open one (CC-BY, CC-BY-SA, Apache-2.0), with its attribution in
`internal/webui/static/tagicons.NOTICE`. An icon whose licence is "custom"
(a trademark policy only) is not used; keycloak and webex were dropped for
that reason on 2026-11-17 (the owner's decision).

## Regenerating

Download a Simple Icons release from npm by hand into an empty scratch
directory and unpack it there (never into the repository), then:

```sh
go run ./tools/tagicons -icons "$DIR/package/icons" -data "$DIR/package/data/simple-icons.json"
```

The generator reads only the icons the mapping names. Each file has to be
exactly the shape Simple Icons ships (24×24 viewBox, a title and one
`<path>`); only the path's `d` is kept, after a strict check against the
path-data characters and the size cap. Oversized icons are reported and
skipped (remove their mapping lines). Output is sorted and deterministic.
With `-data`, it also prints each icon's title and any non-CC0 licence for
review. Update the version and checksum in `tagicons.NOTICE`.

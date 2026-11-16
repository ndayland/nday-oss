# ja — 日本語 · notes

Catalog: `internal/webui/i18n/catalogs/ja.json` · golden: `internal/webui/testdata/golden/ja.txt`

## 1. Audience and register

Readers: Japanese security practitioners (PSIRT/CSIRT, SOC, vulnerability
management, infrastructure operators) who read JPCERT/CC 注意喚起, IPA 重要な
セキュリティ情報, JVN / JVN iPedia and vendor advisories every day. The text is
written from each message's intent, in the vocabulary of those publications,
not rendered from the English or Chinese text.

| Text type | Register | Example |
| --- | --- | --- |
| Explanatory prose (ledes, about, sources page, help text, errors) | です・ます体, as in JPCERT/CC and IPA advisories | 「コレクターは 1 時間ごとに実行されます。」 |
| Status paragraph (under the title, meta description) | です・ます体 (it is read as prose and quoted by search engines) | 「公開から 5 日後に CISA KEV に追加されました。」 |
| Event log text (`ev.*`) | 体言止め / short plain style, like a log or a JVN iPedia history entry | 「CVSS 基本値 9.8（緊急）。」「ランサムウェア攻撃での悪用：不明。」 |
| Labels, table headers, status lines, legends | 体言止め, no final punctuation | 「最終変化日」「レコード未取得 27,925」 |

- The reader is never addressed as あなた / お客様. Polite request forms appear only where an action is asked of the reader (「再表示してください」「再度お試しください」).
- No exclamation marks, no sales tone.
- Navigation keeps the path token and adds a two-character gloss (`~/hot 動向`, `~/vuln 検索`, `~/stats 統計`, `~/src ソース`): Japanese readers parse `~/hot` but the gloss costs little and helps.
- The home list is 「最近動いた脆弱性」 ("vulnerabilities that recently moved"). It was chosen over 「注目」/「トレンド」 (popularity, which nday does not measure) and over 「急上昇」 (a ranking connotation). In the nav it is shortened to 「動向」.

## 2. Terminology

Sources were checked on 2026-11-13.

| Concept | Wording | Source / why |
| --- | --- | --- |
| vulnerability | 脆弱性 | Universal (JPCERT/CC, IPA, JVN). |
| DIS: disclosure | 公開, 公開日時; 「CVE レコード公開」 when the CVE record is meant | IPA alert pages: 「公開日：2025年12月8日」 (https://www.ipa.go.jp/security/security-alert/2025/20251208.html). JPCERT/CC: 「2026-10-22（公開）」 (https://www.jpcert.or.jp/at/2026/at260033.html). 公表 (JVN 「公表日」) was rejected for the stage name because nday's DIS is the CVE-record publication time, not a vendor announcement. 公表 is used once, in `stats.tte.p1`, for "the real public disclosure". |
| PAT: patch / fixed version | 修正版 (stage, short labels); 修正済みバージョン (the version number); 修正 (short code) | JPCERT/CC: 「修正済みバージョンを適用してください」 (at260033). IPA: 「本脆弱性を修正した次のバージョンをリリースしています」 (20251208). パッチ is common in speech but rare in advisories. セキュリティ更新プログラム is Microsoft-specific (IPA 1014-ms: 「セキュリティ更新プログラムを適用してください」), so it is not used. |
| ANA: technical analysis | 技術解析 (short 解析) | Japanese practitioners speak of 解析 for vulnerability and malware write-ups. 分析 suggests a statistical or threat-intel report. |
| POC: public PoC | PoC 公開 (stage); PoC (prose); 攻撃コード for Exploit-DB entries; 検知テンプレート for nuclei | JPCERT/CC: 「本脆弱性を悪用できると主張する実証コードが多数公開されている」 (at260033). Exploit-DB entries are full exploits, so 攻撃コード (IPA/media usage) fits them better than 実証コード. The stage keeps the community abbreviation PoC. |
| ITW: exploited in the wild | 悪用確認 (stage); 「悪用が確認されています」 (prose); short 悪用 | JPCERT/CC: 「すでに悪用が確認されていることから」 (https://www.jpcert.or.jp/at/2026/at260029.html). IPA 1014-ms: 「悪用の事実を確認済み」. 「在野で悪用」 (a calque of "in the wild") is not used in Japan. |
| KEV | CISA KEV; 「既知の悪用された脆弱性（KEV）カタログ」 in full; KEV 掲載 (stage); 「KEV カタログに追加」 (event) | Japanese practitioner media: 「既知の悪用された脆弱性(KEV)カタログに追加した」 (eSecurity Planet ja, Nov 2026, seen in a search snippet); 「Known Exploited Vulnerabilities (KEV) カタログに登録した」 (https://iototsecnews.jp/tag/cisa-kev). JPCERT/CC alerts do not name KEV, and no official Japanese name from CISA was found. 掲載 (being listed) is used for the state, 追加 (being added) for the act. |
| due date | 対応期限 | iototsecnews: 「…までに対応を完了しなければならない」. 修正期限 was rejected because KEV remediation may also mean mitigation or decommissioning. |
| forensic triage | 侵害有無の調査（フォレンジックトリアージ） | JPCERT/CC: 「侵害有無の調査を実施してください」 (at260033) and the heading 「V. 侵害調査」 (at260029). The original term follows in parentheses. |
| CVSS severity | 緊急 / 重要 / 警告 / 注意 / なし, written as 「CVSS 基本値 9.8（緊急）」 | IPA CVSS v3 overview: 緊急 9.0～10.0, 重要 7.0～8.9, 警告 4.0～6.9, 注意 0.1～3.9, なし 0 (https://www.ipa.go.jp/security/vuln/CVSSv3.html). 基本値 is the JVN iPedia term for the base score. The 「基本値: 9.8 (緊急)」 line format is from memory; the JVN pages could not be fetched (unverified). |
| affected versions | 影響範囲 (column header); 「影響を受ける製品 / パッケージ」 (prose) | IPA heading 「影響を受けるシステム」 (20251208). JPCERT/CC uses 「対象」. 影響範囲 fits a 10-column header. |
| advisory | アドバイザリ | Used for GitHub/vendor security advisories. 注意喚起 is reserved for JPCERT/CC-style alerts, which nday does not ingest. The JIS-style spelling without the long vowel (アドバイザリ) is the usual one in Japanese security writing. |
| ransomware | ランサムウェア攻撃での悪用：確認済み / 不明 | iototsecnews: 「Qilin ランサムウェア」. The KEV field is a known/unknown flag, so it is shown as a label plus a value, and 不明 never becomes なし. |
| CNA | 「{assigner} が CVE レコードを公開」 | The CNA's short name is shown as is. No Japanese gloss was needed because the sentence says who published the record. |
| SSVC | 「CISA の SSVC 評価では悪用状況（Exploitation）が active」 | Value tokens are kept. The decision-point name is given in Japanese plus the original. |
| REJECTED | 取り下げ（REJECTED） | Japanese news says a CVE was 「取り下げられた」. 却下 sounds like a refused application, and 拒否 is a calque. |
| collectors | コレクター | Matches the CLI (`nday collect`). 収集器 is not idiomatic. The long-vowel form follows current usage (Microsoft's 2008 move to ベンダー / サーバー; from memory, unverified). |
| vendor | ベンダー | Same long-vowel rule. JVN still writes ベンダ, and a native editor may prefer that. |
| backfill | 補完, 「レコード補完中」, 「補完待ち」; status bar 「レコード未取得」 | バックフィル is data-engineering jargon. 補完 says what happens: missing records are filled in. |
| bulk import | 一括取り込み（リアルタイム観測ではない） | |
| observed live | リアルタイム観測 / 「リアルタイムで観測」 | |
| source (of an event) | ソース; 出典 as the label in front of a source name in the event log | |
| raw data | 生データ / 生の JSON | Common usage (生ログ, 生データ). |
| CWE | 脆弱性タイプ（CWE） | JVN iPedia heading 「CWEによる脆弱性タイプ一覧」 (from memory, unverified). |
| summary | 概要 | The JVN / JPCERT/CC section name (IPA alerts: 「概要」). |

- 2026-11-14（`rsch.`、`veil.`、`discussed.`、`nav.discussed`）：X の投稿の欄は「研究者の投稿」、`/discussed` は「研究者の話題」。「言及」は X で投稿して触れたこと。プレースホルダー下の文はスクリーンリーダーが読む唯一の文でもある。

## 3. Honesty vocabulary

| Idea | Fixed wording |
| --- | --- |
| unknown | 「日時不明」 (all time cells), 「公開日時は不明です。」, 「ランサムウェア攻撃での悪用：不明。」, 「KEV 掲載日も不明」 |
| inferred | 「推定」: 「KEV 掲載から推定」, 「推定（直接の出典なし）」 |
| not later than | `≤ {date}` + 「判明しているのは上限のみ」 / 「上限のみ判明」; in prose 「≤ KEV 掲載日」（KEV 掲載日以前） |
| not listed | 「未掲載」 (PoC sources), 「CISA KEV には現時点で未掲載です。」 (現時点で makes clear that this is not a safety claim) |
| no record yet | 「記録なし」, 「記録はまだありません。」, 「nday には修正版の記録がまだありません。」 (never 修正版なし / 未修正) |
| not given by the source | 「記載なし」 (`value.not_given`, 「ソースに…の記載なし」) |
| bulk import vs live | 「一括取り込み（リアルタイム観測ではない）」 vs 「リアルタイムで観測」 |

`vuln.fix.unfixed` 「未修正」 is used only for the advisory's own "no fixed version" cell. It is the advisory's statement, not nday's.

## 4. Typography

- Full-width 、。：（）「」 in Japanese text. Half-width alphanumerics.
- **Spacing rule:** one half-width space between Japanese text and Latin letters, digits or a placeholder (「公開から 5 日後」「CVE レコード」「{n} 件」), and no space next to full-width punctuation or brackets (「（{edb}）」「「{query}」」). This follows the style of IPA pages (「Microsoft 社では悪用の事実を確認済み」, 1014-ms). JPCERT/CC titles use no spaces, but with nday's monospaced tokens the space keeps the tokens readable.
- Particles touching a placeholder that holds a stage name (`strip.slot` 「{stage}は発生済み」) have no space, because the stage name is itself Japanese.
- Upstream titles are quoted with 「」 (Exploit-DB, Metasploit and nuclei titles, the search query).
- Lists use 「、」 for both prose and compact lists (`list.and.*` and `list.seq.*`). `sentence.joiner` is empty. `strip.sep` is 「、」.
- Dates stay ISO. The weekday is added as 「2026-11-09（月）」, the usual Japanese calendar and log form.
- Numbers use the registry's `45,965`. Counters: 件 for records, sources and events; 製品 for products; 日 for days.

## 5. Registry entry

Reviewed and left unchanged: `plural: none`, grouping `,` with `min_group_digits: 1`, fonts Hiragino Sans → Hiragino Kaku Gothic ProN → Yu Gothic / YuGothic → Meiryo → Noto Sans CJK JP / Source Han Sans JP / Noto Sans JP (macOS first, then Windows, then open fonts; JP-region glyphs throughout), `sentence_final` 。！？, `fullwidth_punct`. Weekday names live in the catalog (`weekday.short`: 月 火 水 木 金 土 日).

## 6. Open doubts

- `vuln.fix.col.eco` 「種別」: エコシステム (12 columns) does not fit the 10-column limit, and 「種別」 is vague. The values next to it (pip, npm) make it readable. A native editor may prefer the bare token `eco`.
- `js.copied_id` 「コピー済み：{id}」: 「{id} をコピーしました」 is more natural but exceeds 12 columns.
- `status.lead.after.*` with 1 day: 「公開から 1 日後」 is correct but 「公開翌日」 would be more natural. With the plural rule `none`, one cannot be special-cased. The same applies to `tplus.title.after` with 0: 「公開から 0 日後」.
- `status.lead.*` uses 「確認されています」 for PAT/ANA/POC/ITW. This is honest (it means "is on record"), but for PAT the advisory time is not the release time, so the wording leans on 確認 rather than リリース.
- `ev.cve.ssvc_*`: the English decision-point name (Exploitation) is kept in parentheses, which a native editor may find redundant.
- `precision.short.exact` 「ソース時刻」 is a coinage. 「正確」 alone was rejected as unclear next to a timestamp.
- The vendor spelling (ベンダー vs JVN's ベンダ) and アドバイザリ vs アドバイザリー should be confirmed against the editor's house style.
- The JVN iPedia field names (「基本値」, 「CWEによる脆弱性タイプ一覧」) are written from memory, because jvndb.jvn.jp entry pages returned 404 or 403 to the fetch tool.

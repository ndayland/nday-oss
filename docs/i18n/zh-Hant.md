# zh-Hant — 繁體中文 · 筆記

Catalog: `internal/webui/i18n/catalogs/zh-Hant.json` · golden: `internal/webui/testdata/golden/zh-Hant.txt`

## 1. 讀者與語氣

以臺灣資安從業人員為主（弱點管理、事件應變、SOC、藍隊、資安研究、IT 維運），
香港、澳門讀者也能順暢閱讀。他們每天看的是 TWCERT/CC 漏洞通報與 KEV 週報、
國家資通安全研究院（資安院）警訊、HKCERT 保安公告、iThome 資安新聞、原廠安全公告。

- 依技術通報的語氣寫：簡潔、陳述句、不加「您」、不用驚嘆號、不用行銷語氣。
- 不是簡體版的轉換：用詞（揭露、修補、紀錄、蒐集、即時、批次匯入、游標、範本、套件、
  列／欄）、句型（「揭露 5 天後列入 CISA KEV」「已於 gpustack 2.2.0 修補」）與標點（「」）
  都依臺灣習慣另寫。
- 主語：資料面的陳述以「nday」為主語（「nday 尚無修補紀錄」）；只有網站行為（Cookie）用「本站」。
- 首頁名稱「最新異動」：「異動」是臺灣資訊系統常用語（資料異動），指漏洞剛進入更後面的階段，
  不暗示熱門排行。導覽列為「路徑 + 中文詞」（`~/hot 異動`）。

## 2. 術語

| 概念 | 用詞 | 依據 |
| --- | --- | --- |
| vulnerability | 漏洞；CWE 類別用「弱點類型」 | TWCERT/CC 通報標題「存在5個漏洞」（https://www.twcert.org.tw/tw/lp-132-1.html）；HKCERT「多個漏洞」（https://www.hkcert.org/tc/security-bulletin）。「弱點」在資安院警訊中也用（「此弱點遭廣泛利用」），本站保留給 CWE（weakness）以免混用。 |
| disclosure (DIS) | 揭露 | TWCERT/CC TVN 欄位「漏洞通報者」「公開日期」；iThome「此事故為卡巴斯基於5月初揭露」（https://www.ithome.com.tw/news/179855）。不用「披露」。 |
| patch (PAT) | 修補、修補紀錄、修補版本、「已於 X 修補」 | 資安院警訊「請儘速確認並進行修補」「官方已針對漏洞釋出修復更新」（https://cc.csmu.edu.tw/p/406-1028-73074,r12.php?Lang=zh-tw）；HKCERT「安裝供應商提供的修補程式」。不用「補丁」。 |
| patch release time | 修補的釋出時間 | 「釋出」是臺灣軟體發布的慣用動詞（資安院「釋出修復更新」）。 |
| advisory | 安全公告、公告 | iThome「Ivanti於6月9日發布安全公告」（https://www.ithome.com.tw/news/150381） |
| proof of concept | 公開 PoC；Exploit-DB 條目為「漏洞利用程式碼」 | iThome「CVE-2026-55040概念驗證程式碼（PoC）公布後」（https://www.ithome.com.tw/news/178276）；TWCERT「已有攻擊利用程式碼流通」（https://www.twcert.org.tw/tw/lp-104-1.html）。PoC 保留英文，與代碼 POC 對應。 |
| exploited in the wild (ITW) | 實際遭利用、遭到利用 | TWCERT KEV 週報「已遭駭客利用之漏洞」（https://www.twcert.org.tw/tw/cp-168-11175-7c21d-1.html）；iThome「遭積極利用的證據」。臺灣機關少用「在野利用」（簡體版用語），故不採。 |
| CISA KEV | CISA KEV、已知遭利用漏洞目錄、列入 KEV | TWCERT 週報直接寫「Known Exploited Vulnerabilities Catalog(KEV)」；iThome「已遭利用的漏洞名單（KEV）」。目錄全名取「已知遭利用漏洞目錄」，對應 CISA 原名。動詞用「列入」（iThome「列入已遭利用的漏洞名單」）。 |
| remediation due date | 修補期限 | iThome「修補的期限都是8月21日」「依照規定的期限完成修補」（https://www.ithome.com.tw/news/178276） |
| forensic triage | 初步鑑識 | 臺灣用「數位鑑識」；triage 是第一輪篩查，故作「初步鑑識」。（未找到機關對 KEV 此欄位的正式譯法，見第 5 節） |
| ransomware | 勒索軟體 | iThome「勒索軟體駭客組織ShinyHunters」（https://www.ithome.com.tw/news/179150）。不用「勒索軟件」（港式）或「勒索病毒」。 |
| authentication | 身分驗證 | iThome「SharePoint身分驗證繞過漏洞」（https://www.ithome.com.tw/news/178276）；機關公文常作「身分鑑別」（資安院「未經身分鑑別之遠端攻擊者」），本站讀者面向業界，取「身分驗證」。 |
| affected | 受影響 | TWCERT「影響產品」；HKCERT「受影響之系統或技術」 |
| CVSS severity | 重大／高風險／中風險／低風險／無 | iThome「這些漏洞皆為重大等級」；「重大風險等級漏洞」（https://www.ithome.com.tw/news/150381）；HKCERT 用「中度風險／高度風險／極高度風險」（港式），本站依臺灣用法。 |
| package / ecosystem | 套件／生態系 | iThome「TanStack的NPM套件」 |
| collector | 蒐集器 | 臺灣「情資蒐集」用「蒐」；不用「採集器」 |
| backfill | 回補 | 臺灣資料處理常用「資料回補」；不用「回填」 |
| bulk import | 批次匯入 | 臺灣「批次」「匯入」；不用「批量導入」 |
| observed live | 即時觀測 | 臺灣「即時」；不用「實時」 |
| template / module | 範本／模組 | 臺灣 Microsoft 用語；不用「模板」 |
| metadata | 中繼資料 | 臺灣通行譯名；不用「元數據」 |
| keyboard shortcut | 鍵盤快速鍵 | Microsoft 臺灣支援文件用語；不用「快捷鍵」 |
| cursor | 游標 | 不用「光標」 |
| row / column | 列／欄 | 臺灣：row＝列、column＝欄（與中國大陸相反） |
| rejected (CVE) | 駁回（保留 REJECTED 記號） | 「駁回」是臺灣對申請遭拒的慣用說法 |
| CNA | 「CVE 紀錄由 {assigner} 發布」 | 名稱原樣保留，不另譯 |
| materialized state | 具體化狀態 | 對應 Microsoft 臺灣「具體化檢視」 |
| liveness | 存活檢查 | |
| zero-day（未使用） | 零時差 | 參考：iThome「先前未知的零時差漏洞」 |

- 2026-11-14（`rsch.`、`veil.`、`discussed.`、`nav.discussed`）：X 貼文區稱「研究員討論」，`/discussed` 稱「研究員熱議」；評論沿用「留言」，貼文量詞用「則」。

## 3. 誠實用語（固定寫法）

| 含義 | 用詞 |
| --- | --- |
| 不知道（unknown） | 「時間不明」「揭露時間不明」「列入日期不明」「是否被用於勒索軟體攻擊：不明。」——一律用「不明」，不用「未知」「無」 |
| 推斷（inferred） | 「由 KEV 推斷」「推斷，無直接來源」「推斷而來的階段」——一律用「推斷」 |
| 不晚於（≤） | `≤ {date}` 加「只知上限」「只能給出時間上限」 |
| 未收錄（not listed） | PoC 來源「未收錄」；KEV「目前未列入 CISA KEV。」（「目前」表示以最近一次抓取為準，不暗示安全） |
| 尚無紀錄（no record yet） | 「尚無紀錄」「nday 尚無修補紀錄。」——不寫「沒有修補」 |
| 來源未給值 | 「來源未提供」 |
| 批次匯入 vs 即時觀測 | 「nday 於 {time} 批次匯入，非即時觀測」／「nday 於 {time} 即時觀測」 |

## 4. 排版

- 全形標點（，。：；（）「」『』、／）；句末「。」。
- 漢字與拉丁字母、數字、占位符之間加一個半形空格（「揭露 5 天後列入 CISA KEV」）；
  全形標點兩側不加空格。這不是臺灣媒體的普遍做法（iThome、TWCERT 不加空格），但本站大量
  夾雜代碼、時間戳與版本號，加空格較易辨識；全站一致。
- `strip.slot` 把狀態放在全形括號內（「公開 PoC（已發生）」），避開「{stage}」結尾是拉丁字或漢字時空格無法一致的問題。
- 引號用「」；上游標題（Exploit-DB）也用「」。
- 清單：`list.seq.*` 全用頓號「、」；`list.and.*` 用「、」並以「與」連接最後兩項（「exploitdb、metasploit 與 nuclei」）。
- `sentence.joiner` 為空字串；`strip.sep` 為「；」。
- 日期分組：「2026-11-09（週一）」；星期用「週」不用「周」。
- 數字分組 `45,965`（登錄檔原設定）。紀錄（名詞）用「紀錄」，動詞用「記錄」（教育部用法）；「占」不作「佔」。

## 5. 待確認事項

- `ev.kev.added` 的 forensic triage 譯作「初步鑑識」：未找到 TWCERT/資安院對 KEV 此欄位的正式譯法，請母語編輯確認。
- `ev.cve.cvss` 的 NONE 寫「嚴重程度為「無」」，略顯生硬，但「無風險」會誤導。
- `tplus.title.after` 在 T+0d 時會出現「揭露後 0 天」：中文應說「揭露當天」，但此鍵無法依數字選擇變體（plural 規則為 none），建議程式在 0 天時改用另一個鍵。
- `status.lead.same_day.PAT` 後接 `status.patch.no_version` 時讀作「揭露當天即有修補紀錄。已有修補紀錄，但來源未提供修補版本。」——兩句重複「修補紀錄」，是句子拆分造成的。
- `status.poc.some` 的 {total} 為阿拉伯數字（「4 個 PoC 來源中有 2 個收錄」），而 `status.poc.none/all` 寫「四個」；兩者同段出現機率低，暫可接受。
- `ev.implied.basis` + `ev.implied.basis_ssvc`：為避免「kev 與 cvelist 中的 CISA 評估」被讀成兩者皆修飾，改寫為「CISA 評估（cvelist）」。
- 香港讀者：用詞依臺灣（軟體、程式碼、網路、修補），HKCERT 用「保安」「修補程式」「中度風險」，本站不採港式用語；字型堆疊未加入 PingFang HK（香港字形標準），見登錄檔說明。
- `hot.date_group` 使用全形括號，在等寬字型區塊中兩側留白稍大，視覺上可接受。

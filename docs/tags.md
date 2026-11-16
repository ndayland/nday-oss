# CVE tags

Tags are **nday's own derivation**. A fixed vocabulary (defined once, in Go) and fixed rules assign tags to each CVE automatically, using data already in the database.
Every tag stores its basis and where it came from. The site and the API both say plainly that nday derived the tags, and **never say "from NVD"**: NVD's terms don't allow attributing modified
content to NVD (see `docs/nvd.md` §7). When NVD shows up in a basis, it only means "NVD's analysts supplied this CWE id / CVSS vector".

Code: `internal/tags` (vocabulary `vocab.go`, product registry and matching `products.go`, derivation `derive.go`, loading `load.go`, incremental and full runs `run.go`,
read API `read.go`), `internal/cli/tags.go` (commands and the incremental pass after collection), `internal/site/tags.go` (list filters, counts, `/api/tags`),
`internal/webui/tagview.go` (pages), migrations `migrations/0011_tags.sql` and `migrations/0013_affected_tags.sql`.

## 1. Vocabulary (rule version 2)

Six dimensions, 285 tags in total: `type` 37, `access` 7, `exploit` 4, `product` 202, `product-type` 23, `ecosystem` 12
(in display order). The `product` and `product-type` dimensions are described in §1.1 and §2. A slug is lowercase ASCII plus hyphens and
**never changes** (URLs, the API and database rows all use it). To rename a tag, add a new slug and retire the old one. Display names: product names and technical terms (XSS, SQL injection,
use-after-free, Metasploit, npm...) stay in English in every language. Only descriptive tag names (attack paths and "ransomware use"),
dimension names, each tag's one-line description and the page text are written per language. Catalog keys: `tag.name`, `tag.desc` (selected by slug), `tag.dim`, `tag.dim_desc` (selected by dimension).
`internal/webui/tags_test.go` checks that the selector values in `keys.json` and the English catalog match the Go vocabulary exactly.

| slug | dimension | en | zh-Hans | rule |
|---|---|---|---|---|
| `command-injection` | type | command injection | command injection | CWE-77, CWE-78, CWE-88 |
| `code-injection` | type | code injection | code injection | CWE-94, CWE-95, CWE-96, CWE-97, CWE-917 |
| `sql-injection` | type | SQL injection | SQL injection | CWE-89, CWE-564 |
| `deserialization` | type | deserialization of untrusted data | deserialization of untrusted data | CWE-502 |
| `template-injection` | type | template injection | template injection | CWE-1336 |
| `file-upload` | type | unrestricted file upload | unrestricted file upload | CWE-434 |
| `file-inclusion` | type | file inclusion | file inclusion | CWE-98 |
| `path-traversal` | type | path traversal | path traversal | CWE-22, CWE-23, CWE-24 … CWE-40, CWE-73 |
| `ssrf` | type | SSRF | SSRF | CWE-918 |
| `xxe` | type | XXE | XXE | CWE-611, CWE-827 |
| `auth-bypass` | type | authentication bypass | authentication bypass | CWE-287, CWE-288, CWE-289, CWE-290, CWE-291, CWE-294, CWE-302, CWE-303, CWE-304, CWE-305, CWE-306, CWE-603, CWE-620, CWE-640, CWE-1390 |
| `broken-access-control` | type | broken access control | broken access control | CWE-276, CWE-280, CWE-281, CWE-282, CWE-283, CWE-284, CWE-285, CWE-425, CWE-566, CWE-639, CWE-732, CWE-862, CWE-863, CWE-1220 |
| `privilege-management` | type | improper privilege management | improper privilege management | CWE-250, CWE-266 … CWE-274, CWE-648 |
| `hardcoded-credentials` | type | hard-coded credentials | hard-coded credentials | CWE-259, CWE-321, CWE-798, CWE-1392 |
| `buffer-overflow` | type | buffer overflow / out-of-bounds write | buffer overflow / out-of-bounds write | CWE-119, CWE-120, CWE-121, CWE-122, CWE-123, CWE-124, CWE-131, CWE-680, CWE-787, CWE-788, CWE-805, CWE-806 |
| `use-after-free` | type | use-after-free | use-after-free | CWE-416, CWE-825 |
| `double-free` | type | double free | double free | CWE-415, CWE-1341 |
| `out-of-bounds-read` | type | out-of-bounds read | out-of-bounds read | CWE-125, CWE-126, CWE-127 |
| `type-confusion` | type | type confusion | type confusion | CWE-843 |
| `integer-overflow` | type | integer overflow | integer overflow | CWE-128, CWE-190, CWE-191, CWE-680 |
| `format-string` | type | format string | format string | CWE-134 |
| `uninitialized-memory` | type | use of uninitialized memory | use of uninitialized memory | CWE-457, CWE-824, CWE-908, CWE-909 |
| `null-dereference` | type | NULL pointer dereference | NULL pointer dereference | CWE-476, CWE-690 |
| `race-condition` | type | race condition | race condition | CWE-362, CWE-364, CWE-366, CWE-367, CWE-368, CWE-662, CWE-667, CWE-820, CWE-821, CWE-1223 |
| `xss` | type | XSS | XSS | CWE-79, CWE-80, CWE-81, CWE-83, CWE-84, CWE-85, CWE-86, CWE-87 |
| `csrf` | type | CSRF | CSRF | CWE-352 |
| `prototype-pollution` | type | prototype pollution | prototype pollution | CWE-1321 |
| `request-smuggling` | type | HTTP request smuggling | HTTP request smuggling | CWE-444 |
| `crlf-injection` | type | CRLF injection | CRLF injection | CWE-93, CWE-113, CWE-117 |
| `open-redirect` | type | open redirect | open redirect | CWE-601 |
| `ui-spoofing` | type | UI spoofing / clickjacking | UI spoofing / clickjacking | CWE-451, CWE-1007, CWE-1021 |
| `search-path` | type | uncontrolled search path | uncontrolled search path | CWE-426, CWE-427, CWE-428 |
| `link-following` | type | link following | link following | CWE-59, CWE-61, CWE-62, CWE-64, CWE-65, CWE-1386 |
| `session-management` | type | session management flaw | session management flaw | CWE-384, CWE-613 |
| `crypto-failure` | type | cryptographic failure | cryptographic failure | CWE-256, CWE-257, CWE-260, CWE-261, CWE-295, CWE-296, CWE-297, CWE-298, CWE-299, CWE-310, CWE-311, CWE-312, CWE-319, CWE-322, CWE-323, CWE-324, CWE-325, CWE-326, CWE-327, CWE-328, CWE-329, CWE-330, CWE-331, CWE-335, CWE-336, CWE-337, CWE-338, CWE-340, CWE-347, CWE-522, CWE-523, CWE-757, CWE-759, CWE-760, CWE-780, CWE-916 |
| `info-disclosure` | type | information disclosure | information disclosure | CWE-200, CWE-201, CWE-203, CWE-204, CWE-208, CWE-209, CWE-210, CWE-211, CWE-213, CWE-215, CWE-359, CWE-497, CWE-532, CWE-538, CWE-548, CWE-552, CWE-922 |
| `resource-exhaustion` | type | resource exhaustion | resource exhaustion | CWE-400, CWE-401, CWE-404, CWE-405, CWE-407, CWE-409, CWE-674, CWE-770, CWE-771, CWE-772, CWE-773, CWE-775, CWE-776, CWE-789, CWE-834, CWE-835, CWE-920, CWE-1333 |
| `remote-unauth` | access | remote, unauthenticated | 远程未授权 | Best v4.0/v3.x vector has AV:N, PR:N and UI:N together; **never** assigned from CVSS 2.0 |
| `network` | access | network | 网络 | Best vector has AV:N |
| `adjacent` | access | adjacent network | 相邻网络 | Best vector has AV:A |
| `local` | access | local | 本地 | Best vector has AV:L |
| `physical` | access | physical | 物理接触 | Best v4.0/v3.x vector has AV:P (v2 has no such value) |
| `no-auth` | access | no authentication required | 无需认证 | Best vector has PR:N (v2: Au:N) |
| `no-interaction` | access | no user interaction | 无需用户交互 | Best v4.0/v3.x vector has UI:N; **never** assigned from CVSS 2.0 (v2 has no user-interaction metric) |
| `ransomware` | exploit | ransomware use | 勒索软件利用 | A `kev_added` event from source `kev` with `detail.known_ransomware_campaign_use` = `Known` (case-insensitive) |
| `metasploit` | exploit | Metasploit | Metasploit | A `poc_published` event from source `metasploit` |
| `exploit-db` | exploit | Exploit-DB | Exploit-DB | A `poc_published` event from source `exploitdb` |
| `nuclei` | exploit | nuclei | nuclei | A `poc_published` event from source `nuclei` |
| `npm` | ecosystem | npm | npm | The GitHub advisory's ecosystem is `npm` |
| `pypi` | ecosystem | PyPI | PyPI | ecosystem is `pip` |
| `maven` | ecosystem | Maven | Maven | `maven` |
| `go` | ecosystem | Go | Go | `go` |
| `nuget` | ecosystem | NuGet | NuGet | `nuget` |
| `rubygems` | ecosystem | RubyGems | RubyGems | `rubygems` |
| `composer` | ecosystem | Composer | Composer | `composer` |
| `crates-io` | ecosystem | crates.io | crates.io | `rust` |
| `hex` | ecosystem | Hex | Hex | `erlang` |
| `pub` | ecosystem | pub | pub | `pub` |
| `swift` | ecosystem | Swift | Swift | `swift` |
| `github-actions` | ecosystem | GitHub Actions | GitHub Actions | `actions` |

(The "rule" for `type` rows: any source (the CNA/ADP containers of the CVE record, the NVD primary/secondary entries, GitHub advisories) gives one of these CWEs in `vuln_cwe`.
The full id lists live in `internal/tags/vocab.go`; the `…` in the table above stands for a consecutive range of ids.)

Lifecycle stages themselves (has a PoC, is in KEV) are **not** tags. The existing stage filters stay as they are.

### 1.1 Products and product types (rule version 2)

**Product types** (`product-type`, 23 of them, slugs never change). The names are descriptive, so like attack paths they're written per language (`tag.name` / `tag.desc`;
en and zh-Hans are written, the other languages are waiting for translation per `docs/i18n/README.md` and show English):

| slug | en | zh-Hans |
|---|---|---|
| `operating-system` | operating system | 操作系统 |
| `browser` | browser | 浏览器 |
| `chipset-firmware` | chipset / firmware | 芯片/固件 |
| `network-device` | router / switch | 路由器/交换机 |
| `firewall-vpn` | firewall / VPN / security gateway | 防火墙/VPN/安全网关 |
| `nas-storage` | NAS / storage | NAS/存储 |
| `iot-camera` | camera / IoT device | 摄像头/IoT 设备 |
| `ics` | ICS / OT | 工控 ICS/OT |
| `printer` | printer | 打印机 |
| `virtualization` | virtualization / containers | 虚拟化/容器 |
| `database` | database | 数据库 |
| `web-server` | web / application server | Web/应用服务器 |
| `cms` | CMS and plugins | CMS 及插件 |
| `mail-collab` | mail / collaboration | 邮件/协作 |
| `office-pdf` | office / document software | 办公/文档软件 |
| `devops` | developer / CI tooling | 开发/CI 工具 |
| `enterprise-app` | enterprise application (ERP/CRM) | 企业应用 ERP/CRM |
| `identity` | identity / access management | 身份/访问管理 |
| `security-software` | endpoint security / antivirus | 终端安全/杀毒软件 |
| `monitoring` | monitoring / logging / IT management | 监控/日志/运维管理 |
| `remote-access` | remote desktop / remote access | 远程桌面/远控 |
| `ai-ml` | AI / ML | AI/ML |
| `library` | open-source library / framework | 开源库/框架 |

**Products** (`product`, 202 well-known product families, `Products` in `internal/tags/products.go`). All spellings and versions of one family collapse into **one** tag
(`microsoft | windows 10 version 1809`, `microsoft corporation | windows kernel` and the CPE `o:microsoft:windows_10` are all `windows`).
Product names are English in every language: the name is the `Label` in Go and doesn't go into `tag.name`. The description is one catalog message with a parameter,
`tag.desc_product` ("CVEs whose affected products include {name}..."), so product slugs are not selector values of `tag.name` / `tag.desc`
(`internal/webui/tags_test.go` still checks the selector values against the vocabulary strictly for the other dimensions). Each product carries one or more product types, and a product match also adds the type tags.
Grouped by (first) type:

| type | products (slug name) |
|---|---|
| `operating-system` | `windows` Windows；`windows-server` Windows Server；`linux-kernel` Linux kernel；`macos` macOS；`ios-ipados` iOS / iPadOS；`watchos` watchOS；`tvos` tvOS；`visionos` visionOS；`android` Android；`harmonyos` HarmonyOS；`emui` EMUI；`openharmony` OpenHarmony；`freebsd` FreeBSD；`solaris` Solaris；`ibm-i` IBM i；`aix` AIX；`zephyr` Zephyr RTOS |
| `browser` | `chrome` Chrome；`firefox` Firefox；`safari` Safari；`edge` Microsoft Edge；`internet-explorer` Internet Explorer |
| `chipset-firmware` | `snapdragon` Qualcomm Snapdragon；`amd-ryzen` AMD Ryzen；`amd-epyc` AMD EPYC；`nvidia-gpu-driver` NVIDIA GPU driver |
| `network-device` | `junos` Junos OS；`cisco-ios-xe` Cisco IOS XE；`cisco-ios` Cisco IOS；`cisco-ios-xr` Cisco IOS XR；`cisco-nx-os` Cisco NX-OS；`cisco-rv-routers` Cisco Small Business RV routers；`arubaos` ArubaOS；`arista-eos` Arista EOS；`routeros` MikroTik RouterOS；`big-ip` F5 BIG-IP |
| `firewall-vpn` | `fortios` FortiOS；`fortiproxy` FortiProxy；`fortiweb` FortiWeb；`pan-os` PAN-OS；`globalprotect` GlobalProtect；`cisco-asa` Cisco ASA；`cisco-ftd` Cisco Firepower Threat Defense；`cisco-fmc` Cisco Firepower Management Center；`anyconnect` Cisco AnyConnect / Secure Client；`netscaler` NetScaler ADC / Gateway (+network-device)；`ivanti-connect-secure` Ivanti Connect Secure；`sonicos` SonicOS；`sonicwall-sma` SonicWall SMA；`fireware` WatchGuard Fireware；`check-point-quantum` Check Point Quantum；`sophos-firewall` Sophos Firewall |
| `monitoring` | `fortimanager` FortiManager；`fortianalyzer` FortiAnalyzer；`splunk` Splunk；`kibana` Kibana；`grafana` Grafana；`zabbix` Zabbix；`nagios` Nagios；`solarwinds-platform` SolarWinds Platform (Orion)；`cacti` Cacti；`glpi` GLPI；`ivanti-epm` Ivanti Endpoint Manager；`qradar` IBM QRadar；`wireshark` Wireshark |
| `nas-storage` | `qnap-qts` QNAP QTS / QuTS hero；`synology-dsm` Synology DSM；`powerscale-onefs` Dell PowerScale OneFS |
| `iot-camera` | `axis-os` AXIS OS |
| `ics` | `simatic` Siemens SIMATIC；`scalance` Siemens SCALANCE (+network-device)；`codesys` CODESYS；`modicon` Schneider Modicon |
| `virtualization` | `esxi` VMware ESXi；`vcenter` VMware vCenter Server；`vmware-workstation` VMware Workstation / Fusion；`virtualbox` VirtualBox；`xen` Xen；`qemu` QEMU；`kubernetes` Kubernetes；`docker` Docker / Moby；`powervm` IBM PowerVM；`rancher` Rancher；`openshift` OpenShift |
| `database` | `mysql` MySQL；`mariadb` MariaDB；`postgresql` PostgreSQL；`sql-server` SQL Server；`oracle-database` Oracle Database；`mongodb` MongoDB；`redis` Redis；`sqlite` SQLite (+library)；`db2` Db2；`elasticsearch` Elasticsearch |
| `web-server` | `apache-http-server` Apache HTTP Server；`tomcat` Apache Tomcat；`nginx` NGINX；`weblogic` WebLogic Server；`websphere` WebSphere Application Server；`jboss-eap` JBoss EAP；`coldfusion` Adobe ColdFusion；`envoy` Envoy；`traefik` Traefik；`apache-traffic-server` Apache Traffic Server |
| `library` | `nodejs` Node.js；`php` PHP；`openssl` OpenSSL；`imagemagick` ImageMagick；`curl` curl；`ffmpeg` FFmpeg；`libxml2` libxml2；`glibc` glibc；`spring-framework` Spring Framework；`log4j` Apache Log4j；`struts` Apache Struts；`django` Django；`rails` Ruby on Rails；`symfony` Symfony；`nextjs` Next.js；`netty` Netty；`wolfssl` wolfSSL；`bouncy-castle` Bouncy Castle；`electron` Electron；`cpython` Python (CPython)；`java-se` Java SE；`dotnet` .NET |
| `cms` | `wordpress` WordPress；`drupal` Drupal；`joomla` Joomla!；`typo3` TYPO3；`magento` Adobe Commerce / Magento；`aem` Adobe Experience Manager；`liferay` Liferay Portal / DXP；`prestashop` PrestaShop；`craft-cms` Craft CMS；`concrete-cms` Concrete CMS；`grav` Grav；`ghost` Ghost；`mediawiki` MediaWiki；`xwiki` XWiki |
| `mail-collab` | `exchange` Exchange Server；`sharepoint` SharePoint；`outlook` Outlook；`teams` Microsoft Teams；`thunderbird` Thunderbird；`zimbra` Zimbra；`roundcube` Roundcube；`confluence` Confluence；`mattermost` Mattermost；`nextcloud` Nextcloud；`discourse` Discourse；`fortimail` FortiMail；`zoom` Zoom；`webex` Webex；`cisco-ucm` Cisco Unified Communications Manager；`hcl-domino` HCL Domino / Notes |
| `office-pdf` | `office` Microsoft Office；`acrobat` Adobe Acrobat / Reader；`foxit-pdf` Foxit PDF Reader / Editor；`pdf-xchange` PDF-XChange；`libreoffice` LibreOffice |
| `devops` | `gitlab` GitLab；`jenkins` Jenkins；`teamcity` TeamCity；`github-enterprise-server` GitHub Enterprise Server；`gitea` Gitea；`jira` Jira；`artifactory` JFrog Artifactory；`visual-studio` Visual Studio；`vscode` Visual Studio Code；`airflow` Apache Airflow；`n8n` n8n；`ansible` Ansible；`vim` Vim |
| `enterprise-app` | `sap-netweaver` SAP NetWeaver；`sap-businessobjects` SAP BusinessObjects；`oracle-ebs` Oracle E-Business Suite；`peoplesoft` PeopleSoft；`jd-edwards` JD Edwards；`siebel` Siebel CRM；`dynamics-365` Microsoft Dynamics；`erpnext` ERPNext / Frappe；`maximo` IBM Maximo |
| `identity` | `keycloak` Keycloak；`cisco-ise` Cisco Identity Services Engine；`ibm-verify-access` IBM Security Verify Access；`wso2-identity-server` WSO2 Identity Server；`vault` HashiCorp Vault |
| `security-software` | `microsoft-defender` Microsoft Defender；`trend-micro-apex-one` Trend Micro Apex One；`suricata` Suricata |
| `remote-access` | `freerdp` FreeRDP；`remote-desktop-client` Microsoft Remote Desktop client；`screenconnect` ConnectWise ScreenConnect |
| `ai-ml` | `tensorflow` TensorFlow (+library)；`vllm` vLLM；`langflow` Langflow；`open-webui` Open WebUI；`mlflow` MLflow；`anything-llm` AnythingLLM；`flowise` Flowise；`openclaw` OpenClaw |

Long-tail products get no product tag. **Deliberately left out**: Linux distributions (RHEL, Debian, Ubuntu, SUSE, Fedora: Red Hat's CNA and NVD both list the distribution as an affected product for
almost every package CVE, so including them would tag a curl bug as "operating system"); Adobe creative software, Autodesk and Siemens CAD (no fitting
type). Rejected CVEs never get tags.

**Type rules** (`TypeRules`) give a type only, not a product. A vendor-level rule is added only when the data shows the vendor's products are **overwhelmingly** one type
(checked against every `affected` row in a full database). Wording rules that apply to any vendor use only words that are unambiguous for every vendor:

| id | type | basis |
|---|---|---|
| `vendor:tenda`, `vendor:totolink`, `vendor:wavlink`, `vendor:netgear` (excluding ReadyNAS), `vendor:linksys` | `network-device` | The listed products are all routers, extenders, APs, Orbi and gateway models |
| `d-link:router` / `d-link:nas` / `d-link:camera` | `network-device` / `nas-storage` / `iot-camera` | D-Link model prefixes: DIR-, DSL-, DAP-, DWR-, DGS-...; DNS-, DNR-; DCS- |
| `tp-link:network` / `tp-link:iot` | `network-device` / `iot-camera` | Archer, Deco, Omada, TL-WR...; Tapo, VIGI, Kasa, TL-IPC |
| `zyxel:firewall` | `firewall-vpn` | USG, USG FLEX, ATP, VPN and ZyWALL series |
| `vendor:qualcomm`, `vendor:mediatek`, `vendor:unisoc` | `chipset-firmware` | Chipset lists plus their firmware and closed-source components |
| `vendor:hikvision`, `vendor:dahua` | `iot-camera` | Cameras, NVRs and their management platforms |
| `vendor:rockwell`, `vendor:schneider-electric`, `vendor:abb`, `vendor:delta-electronics`, `vendor:phoenix-contact`, `vendor:codesys`, `vendor:iconics`, `mitsubishi:automation` | `ics` | PLCs, HMIs, SCADA, industrial switches; for Mitsubishi Electric only the automation lines MELSEC/MELFA/GOT/GX Works/CNC and similar count |
| `mitsubishi:appliance` | `iot-camera` | Mitsubishi Electric's connected air conditioners and refrigerators, and their Wi-Fi/HEMS adapters |
| `vendor:lexmark` | `printer` | Printer/MFP firmware models and print drivers |
| `vendor:qnap` | `nas-storage` | QTS/QuTS hero and the NAS apps that run on it |
| `vendor:jenkins`, `vendor:jetbrains` | `devops` | Jenkins and its plugins; JetBrains IDEs, TeamCity, YouTrack |
| `vendor:sap` | `enterprise-app` | NetWeaver, S/4HANA, BusinessObjects and so on |
| `vendor:trend-micro`, `vendor:eset`, `vendor:mcafee-trellix`, `vendor:bitdefender`, `vendor:sophos`, `gen-digital:antivirus` | `security-software` | Security vendors' products; for Gen Digital only the antivirus suites (not CCleaner and the like) |
| `words:wordpress-plugin` | `cms` | Any vendor: the product name contains wordpress, woocommerce, elementor, for joomla or drupal (plugins, themes, extensions) |
| `words:printer` | `printer` | Any vendor: printer(s), laserjet, officejet, deskjet, designjet, pagewide, multifunction printer(s), mfps, e-studio, imagerunner, bizhub (**not** a bare mfp: Siemens S7-1500 has "MFP" CPUs) |
| `words:ip-camera` | `iot-camera` | Any vendor: ip camera(s), network camera, network video recorder, dvr, nvr |
| `words:router` | `network-device` | Any vendor: wireless/wifi/wi-fi/vpn router, range extender, wireless access point (**not** a bare router: vue-router and the like are libraries) |

A CVE whose type can't be determined gets **no** product-type tag (there's no "other" slug; adding one means one vocabulary entry plus one line in `deriveProducts`).

## 2. Rule details and edge cases

- **Type**: a CVE can have several type tags (for example CWE-79 + CWE-89 gives `sql-injection` and `xss`; CWE-680 belongs to both
  `buffer-overflow` and `integer-overflow`). Tags follow the CWE hierarchy: close relatives merge into one tag
  (121/122/119/120/787 → `buffer-overflow`; 862/863/284/285/639 → `broken-access-control`; 287/288/290/306 → `auth-bypass`...). Catch-all ids that only say "something went wrong" get no tag
  (§3). The basis records every matching CWE id and **all** the sources that gave it (ordered by `classify.Precedence`).
- **Attack path (access)**: reads one vector only. Among v4.0, v3.1 and v3.0 (for each version, take the one `classify.BestCVSS` picks), choose the source with the highest priority
  (`cve-cna` > `cve-adp` > `nvd-primary` > `nvd-secondary` > `ghsa`, same priority ordered by `source_org` byte order), and within one source the newer version. Only when there is no v3/v4 at all is the best v2.0 used.
  Why: the CNA is the authority, which matches the priority in the classification layer; v2 lacks the UI metric and has been superseded by v3.
  AV yields exactly one of `network`/`adjacent`/`local`/`physical`; v2 can only yield `network`/`adjacent`/`local` and `no-auth` (Au:N),
  and **not** `no-interaction` or `remote-unauth` (the page shows a note about this when the basis is v2; catalog key `tag.vuln.v2_note`).
  The basis records the vector, version, source and the metric values that mattered (such as `["AV:N","PR:N","UI:N"]`). Invalid vectors (failing `classify.ValidVector`) are skipped.
- **Exploit**: reads only events from the public sources `kev`, `exploitdb`, `metasploit` and `nuclei`; it **never** reads the non-public `xposts`
  (`social_post` events don't even enter the queue). The basis records the source, event type, item keys (EDB ids, full module names, template ids; sorted, at most 10) and the total count.
  For ransomware it records the raw value of the KEV field.
- **Ecosystem**: the GitHub advisory's ecosystem lives in the raw record (`raw_record.payload.vulnerabilities[].package.ecosystem`);
  an event's detail only has `packages` for advisories that carry a fixed version, so events aren't used. It reads **the version the classification layer read**: the CVE's (non-withdrawn) `ghsa` row in `vuln_classify_input`
  gives `source_key` + `content_hash`, and `raw_record` is fetched by those two. The basis records the advisory id, the raw ecosystem value and
  the package names (at most 10). An ecosystem that isn't in the vocabulary (such as `other`) gets no tag.
- **Rejected (REJECTED) CVEs get no tags**. A CVE counts as rejected when the CVE record's state (the latest `disclosed` event from `cvelist`, written exactly the same way as `rej` in `vuln_state`)
  is REJECTED, or when the `cvelist` / `nvd` input in the classification layer's `vuln_classify_input` is marked rejected. A GHSA withdrawal
  only affects that advisory's own row; it doesn't make the CVE rejected.
- **Suppressed** rule tags are not derived, not shown and can't be filtered on (§4).
- **Product (`product`) and product type (`product-type`)**: two sources. A match in either one adds the tag, with one row per tag, and the basis lists the two kinds of evidence separately:
  1. The `affected` table (free-text vendor and product from the CVE record). Matching normalizes first: lowercase, trim, collapse runs of whitespace to one space. A rule =
     a set of vendor spellings (exact) + a product pattern: exact, prefix (ending at a word boundary) or whole-word containment (the phrase is surrounded by string edges or non-alphanumeric characters), optionally with exclusion words.
     **A product rule must restrict both vendor and product** (`TestProductRegistry` checks this: there are no rules that look only at the product text, and no product rules that look only at the vendor);
     rules on vendor alone or wording alone are only used for type rules (§1.1). Example: `windows` = vendor `microsoft`/`microsoft corporation` + a product starting with
     `windows` and not containing `server`, `defender`, `admin center` and so on (Windows Server is a separate family, the rest are different products);
     `appleple inc.` is not Apple.
  2. NVD's CPE: reads **the version of the NVD record the classification layer read** (the `nvd` row in `vuln_classify_input`, not marked rejected; `raw_record` fetched by `source_key` +
     `content_hash`; the payload is the `cve` object from the feed). It takes the `criteria` of entries with `vulnerable = true` in `configurations[].nodes[].cpeMatch[]`;
     `vulnerable = false` entries are "running on/with" platforms (otherwise every application on Windows would get
     `windows`), and nodes with `negate = true` aren't read either. CPE 2.3 strings are split on unescaped colons (backslash escapes like `\:` and `\!` are undone), and only
     part, vendor and product are used; the version fields are ignored. A CPE rule = exact CPE vendor + exact or prefix product match (a CPE product is a single token, such as
     `windows_10_1809`), optionally with an exclusion prefix. A few type rules also have a CPE form (such as the `netgear` vendor and D-Link model prefixes).
     The CPE `part` is **not** used to infer a type: in the local sample, 61.6% of the vulnerable `o` entries are `*_firmware` (router, chip and PLC firmware),
     so `o` doesn't mean operating system.
  - Basis: a product tag records the `affected` rows that matched (vendor and product **verbatim**, sorted and de-duplicated, at most 10; `affected_count` is the total) and the CPEs that matched
    (`part`/`vendor`/`product`, sorted and de-duplicated, at most 10; `cpe_count`). A type tag records the same two kinds of evidence plus the product slugs that produced it
    (`products`) and the type rule ids (`type_rules`). On the page, the CPE evidence reads "CPE names NVD's analysts give as vulnerable". As with CWE/CVSS,
    NVD is only the party that supplied the fact; the tag is nday's derivation and never says "from NVD". Upstream strings (vendor, product, CPE fields) are always escaped, have bidirectional control characters replaced
    and are wrapped in `<bdi>`.
  - CPE coverage depends on whether the full NVD baseline has been imported (`nday import-nvd-baseline` + `classify --all`); for years that haven't been imported, `affected` is the only source.

## 3. CWE ids deliberately not mapped

| id | reason |
|---|---|
| CWE-20 | Improper Input Validation: a catch-all that doesn't say which kind of weakness |
| CWE-74, CWE-707, CWE-116 | Generic injection/neutralization classes; the specific subclasses (79, 89, 78...) match on their own when given |
| CWE-664, 682, 691, 693, 697, 703, 710, 435 | CWE pillars and very broad classes (resource control, computation, protection mechanism failure...) |
| CWE-16, 17, 18, 19, 189, 254, 255, 264, 275, 399, 840 | CWE **categories** used by old NVD records (such as 264 Permissions, Privileges, and Access Controls and 399 Resource Management Errors): too broad |
| CWE-668, 669, 610, 441 | Resource exposure/transfer across spheres: abstract parents of several mapped classes |
| CWE-345, 346 | Insufficient verification of data authenticity/origin: too broad (signatures, CORS, postMessage...) |
| CWE-129, 193, 822, 1284, 1285 | Index/quantity validation, off-by-one, untrusted pointer: you can't tell whether it's a read or a write |
| CWE-248, 369, 617, 754, 755 | Uncaught exception, divide by zero, reachable assertion, exception handling: you only know it crashes, not the category |
| CWE-665, 602 | Improper initialization (abstract parent of 908/909), client-side enforcement of server-side security: too broad |
| CWE-184, 829, 494, 749, 1188, 915, 1236, 307, 521, 90, 91, 643, 943 | Specific but rare or ambiguous; left for a later rule version |

(`UnmappedCWEs` in `vocab.go`. A test makes sure they don't overlap the mapping table, and that each of the 50 most-used ids in a full database is either mapped or listed here.)
Placeholder values such as NVD's `NVD-CWE-noinfo` and `NVD-CWE-Other` and the CVE record's `CWE-noinfo` are never stored by the classification layer, so they naturally produce no tag.

In the local full database (§8), 212,810 of the 238,968 CVEs that have a CWE (89.1%) have at least one type tag. The main reason for having no type tag is that only
catch-all ids were given: CWE-20 (6,269), 693, 74, 346 and 264.

## 4. Storage (`migrations/0011_tags.sql`, additive only)

- `vuln_tag(cve_id → vuln ON DELETE CASCADE, tag, origin CHECK IN ('rule','staff'), basis jsonb, rule_version int, created_at)`,
  primary key `(cve_id, tag, origin)`; a `rule` row must have `rule_version`. Index `vuln_tag_tag_idx (tag, cve_id, origin)`: fetching CVEs by tag
  (filters, counts) scans only the index (`origin` is in the index, so the view's condition below needs no table lookup). Currently only `origin='rule'` is written.
- `vuln_tag_suppress(cve_id → vuln, tag, reason, created_at, created_by → users ON DELETE SET NULL)`, primary key `(cve_id, tag)`:
  meant for a future admin UI. Nothing writes it today, but the semantics are implemented and tested: a suppressed rule tag is **not shown** (all reads go through the view), **can't be filtered on**
  and **isn't added back by a recompute** (excluded during derivation); a recompute does add it back after the suppression is lifted; `staff` rows are unaffected.
- The view `vuln_tag_visible` = staff rows + rule rows that aren't suppressed: the only definition the site, the API and the counts use (same approach as `event_effective`).
- `vuln_tag_count(tag, n)`, `tag_run` (one row: the rule version and time of the last full `--all` run, and the counts refresh time) and `tag_queue` (§5).

Example bases for products and product types (values actually stored in a local database):

```json
{"cpe": [{"part": "o", "vendor": "microsoft", "product": "windows_10_1607"}, …, {"part": "o", "vendor": "microsoft", "product": "windows_rt_8.1"}], "cpe_count": 7,
 "affected": [{"vendor": "Microsoft", "product": "Windows"}, {"vendor": "Microsoft", "product": "Windows 10"}, …], "affected_count": 6}
{"affected": [{"vendor": "D-Link", "product": "DAP-1325"}], "affected_count": 1, "type_rules": ["d-link:router"]}
```

(The first is `windows` for `CVE-2018-8174`; its `operating-system` additionally has `"products": ["windows", "windows-server"]`. The second is `network-device` for
`CVE-2023-44406`.)

Example bases for the other dimensions (values actually stored in a local database; the first four are `deserialization`, `remote-unauth`, `ransomware` and `exploit-db` for `CVE-2021-44228`,
and the last is `maven` for `CVE-2025-53648`):

```json
{"cwe": [{"id": "CWE-502", "sources": [{"source": "cve-cna", "source_org": "apache"}]}]}
{"cvss": {"source": "cve-adp", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "metrics": ["AV:N", "PR:N", "UI:N"], "version": "3.1", "source_org": "CISA-ADP"}}
{"events": [{"type": "kev_added", "count": 1, "source": "kev", "known_ransomware_campaign_use": "Known"}]}
{"events": [{"keys": ["50590", "50592", "51183"], "type": "poc_published", "count": 3, "source": "exploitdb"}]}
{"advisories": [{"id": "GHSA-7ph3-grqh-pv9v", "packages": ["org.apache.gravitino:catalog-jdbc-common"], "ecosystem": "maven"}]}
```

## 5. Recomputation: how nothing gets missed

**Mechanism: a queue plus statement-level triggers** (the same discipline as `classify_queue`). The migration creates `AFTER INSERT / UPDATE / DELETE … FOR EACH
STATEMENT` triggers on the tables below (with transition tables: one `INSERT … SELECT DISTINCT` per statement, so even when the classification layer COPYs thousands of rows in one go it adds just one statement),
and in the **same transaction** they append the affected CVEs to `tag_queue`:

| table | changes covered |
|---|---|
| `vuln_cwe`, `vuln_cvss` | Classification rows changed (the classification layer deletes + inserts only when the derived result differs) |
| `vuln_classify_input` | The rejected flag changed; a GHSA advisory got a new version (`content_hash` changed; the ecosystem tag reads this version); an advisory was re-pointed at another CVE |
| `event` (only `kev_added`, `poc_published`, `disclosed`) | Exploit evidence added, removed or changed; the CVE record's state became or stopped being REJECTED |
| `vuln_tag_suppress` | Suppressing or un-suppressing |
| `affected` (migration 0013) | Affected-product rows added, removed or changed (the only writer is `INSERT … ON CONFLICT DO NOTHING` in `internal/pipeline`, which every collector and `import-cve-baseline` go through; plus the cascade delete when a `vuln` is deleted); statements that hit a conflict and wrote nothing don't enqueue |

NVD's CPE needs no new trigger: when a new version of an NVD record arrives, the classification layer rewrites that CVE's `vuln_classify_input` row (new `content_hash`), and the 0011 triggers
already enqueue it (`TestNeverMissedNVDCPE`: a new version that changes only the CPE, with CWE and CVSS unchanged, changes the tags after `Pending`).

`tags.Pending` (runs automatically after every successful `nday collect <any source>`, after classification, at most 500,000 queue rows; also `nday tags --pending`) first reads a batch of
queue rows, **then** reads the inputs (the writes behind the queue rows it read have necessarily committed and are visible), compares, writes, and deletes **exactly** the queue rows it read, all in one transaction.
Writes committed while the batch runs leave their own queue rows for the next batch. A rule version change isn't a database write: when you change the rules, bump `tags.RuleVersion` and run
`nday tags --all` after deploying. Until then, every post-collection incremental run logs a `rows may be stale` warning (it compares `tag_run.all_rule_version`).

A CVE's rule rows are **replaced as a whole**: if the derived set of (tag, canonical basis, rule_version) equals what's in the database, nothing is written; if it differs, all of that CVE's
`rule` rows are deleted and re-inserted in the batch transaction. `staff` rows are never read or written. Nothing is written besides `vuln_tag`, `vuln_tag_count`, `tag_run` and `tag_queue` (tests compare fingerprints of `event`,
`vuln`, `vuln_state`, `vuln_state_mat`, `raw_record`, `vuln_cwe` and `vuln_cvss`).

Concurrency: every run that writes tags shares one session-level advisory lock (`'ndtg'` + the oid of `tag_queue`). `nday tags` waits for the lock; the automatic run after collection skips
(`deferred`) if it can't get it, and the run holding the lock, or the next one, handles the rest, so it never blocks a collector.

Tests (`internal/tags/run_test.go`): classification changes (a new CVE record version changes the CWE), event insert/update/delete, rejection (NVD Rejected and the CVE record's state,
each in both directions), a GHSA advisory switching ecosystem, a rule version upgrade (only `--all` rewrites), suppression, concurrent writes while a batch is running, the lock, and `social_post` not being enqueued.
Mutation checks (remove the trigger and the matching test fails): removing `event_tag_upd` makes `TestNeverMissedEvent` and `TestNeverMissedRejected` fail; removing the three
`vuln_classify_input_tag_*` makes `TestNeverMissedAdvisory` fail, and `TestNeverMissedNVDCPE` too; removing the three `affected_tag_*` from 0013 makes `TestNeverMissedAffected` and `TestTriggerCoverageAffected` fail.
Tests for products and product types: `TestNeverMissedAffected` (insert, a conflicting insert not enqueued, update, delete, cascade delete), `TestNeverMissedNVDCPE` (a new NVD version with different CPEs,
platform CPEs not counted, NVD rejection), `TestTriggerCoverageAffected` (each of the three write kinds has a statement-level enqueue trigger), and in `products_test.go` the registry's shape,
CPE parsing, whole-word matching and the derivation/basis tests.

## 6. Counts and staleness

`vuln_tag_count` is rebuilt as a whole in one transaction at the end of every run that **changed tags** (and every `--all`): `count(DISTINCT cve_id)` over
`vuln_tag_visible` GROUP BY tag (about 0.2 s locally for 885k rows). The pages and `/api/tags` only read this small table. So counts **lag by at most one tag run**,
that is, one collection; a suppression or un-suppression shows up in the counts after the next tag run (the next collection, or a manual `nday tags --pending`). The page says "Counts as of …".
The lists themselves (hot, search, tag pages) query `vuln_tag_visible` directly and aren't affected by count staleness; on top of that there's the site's own 30 s process cache and a 60 s HTTP cache.

## 7. Site and API

- **Vulnerability page**: the tag block sits right under the status sentence, before `curl` and the key facts. Why: the status sentence answers "how far along the lifecycle is it", and the tags answer "what kind of bug is it,
  and where can it be reached from"; together they're the first screen you need for triage. The block takes only a line or two, so it doesn't push the lifecycle chart down. Tags are grouped by dimension, with `remote-unauth` in bold and
  `ransomware` in KEV red. Below it is a `<details>` that needs no JS, "why these tags": first one sentence ("nday derives these tags by fixed rules from the facts below; NVD, the CNA and other sources do not assign them"),
  then each tag's basis (CWE ids and the sources that gave them, vector and source, KEV field, item keys, advisory and package names); when the basis is
  CVSS 2.0, the v2 note is added. Upstream strings (CNA names, module names, package names) are always escaped, have bidirectional control characters replaced with U+FFFD and are wrapped in `<bdi>`.
- **Lists** (`/`, `/tag/<slug>`, `/vuln`): `?tag=<slug>` can repeat and the tags are intersected, combined with the existing filters; unknown slugs are ignored and left out of the canonical link; at most 5.
  Selected tags show as removable chips (one `--tag` line). Each row shows at most 3 tags, in this order: `remote-unauth` (the strongest reachability signal), `ransomware`
  (a consequence signal the lifecycle bar doesn't express), and the first type tag (what kind of bug; by vocabulary order). The other access tags, Metasploit/Exploit-DB/nuclei
  (the row already has POC n/3) and the ecosystem stay on the vulnerability page. The tag block goes before the vendor on the second line; the table already scrolls horizontally on narrow screens, and the row layout is unchanged at 375 px.
- `/tags`: lists all tags by dimension with slug, count and a one-line description. Dimensions with more than 20 tags (type, product, product type) are sorted by count, highest first, and only the first 20 are shown;
  the rest go in a `<details>` that needs no JS ("N more tags", catalog key `tag.page.more`). Dimensions with 20 tags or fewer keep vocabulary order and show everything. `/tag/<slug>`: description, count, the CWE list for type tags, the reused hot-list view (same
  `since` / `min_stage` / `include_rejected` / `tag` parameters), and that tag's RSS (`/feed.xml?tag=<slug>`, also in the page header as `<link rel=alternate>`).
  They exist under every language prefix, are indexed normally, and `hreflang` is the same as on other pages. An uppercase slug gets a 301 to lowercase; an unknown slug gets a 404.
- **Feed**: `/feed.xml?tag=…` (same validation), titled "nday · hot · <tag name>", with the tag parameter in `id`/`self`.
- **API** (`docs/api.md`): `/api/hot` and `/api/search` (and `/v1/…`) accept a repeatable `tag`; an unknown slug or more than 5 is a 400. Rows get a
  `tags` field (array of slugs); the vulnerability JSON gets `tags: [{slug, dimension, origin, basis, rule_version}]`; and there's `GET /api/tags` (`/v1/tags`).
  Existing fields are unchanged (`internal/web/classification_test.go` compares against a saved earlier snapshot).

Cache keys: the hot `HotParams.CacheKey` includes the tags; the search key includes the tags; the feed key includes the tags; the `/api/tags` key is `tags`.

Performance (local full database, see §8; execution time from `EXPLAIN (ANALYZE, BUFFERS)`): hot 7d with 1 or 2 tags 0.8–1.1 ms; 30d `ransomware` 2.2 ms;
366d with two tags 2.3–20 ms; 366d across all stages (the worst case) `ransomware` 3.0 ms, `remote-unauth`+`xss` 15 ms. For common tags the planner walks the hot index backwards,
and for rare tags it starts from `vuln_tag_tag_idx`. `/vuln?tag=network` with a tag and no query term (sorting 189k CVEs and taking the first 51) takes about 120 ms,
`xss`+`remote-unauth` about 116 ms; the text search itself (`microsoft`, 137 ms) takes 180 ms with a tag added.

## 8. Local measurements (dev machine, Docker PostgreSQL 16)

Database: a copy of `nday_fullimport` (424,972 vulns, the full CVE record set), migrated to 0011, then the three NVD sample files (2010, 2018, recent) imported and
`classify --all` run (46 s).

| step | result | time |
|---|---|---|
| `nday tags --all` (first run) | 424,972 CVEs, 281,324 with tags, 884,886 rows, 19,170 rejected | 19.5 s |
| `nday tags --all` again | 0 changes | 13.7 s |
| count rebuild | 57 tags have counts | 0.2 s |

`vuln_tag` with indexes is 298 MB (table about 207 MB, primary key 45 MB, tag index 46 MB; basis averages 166 B).

Coverage: of the 251,441 CVEs that have CVSS, 251,440 have access tags; `remote-unauth` 69,456, `ransomware` 361 (matches KEV's 361).

**Extrapolation to a full deployment (an estimate, not a measurement)**: a deployment's CVE count is close to the local full database. With the full NVD baseline imported, CWE/CVSS coverage for older years goes from single digits to about 90%/100%,
at about 3 access tags per CVE that has CVSS, so `vuln_tag` is estimated at about 1.2–1.6 M rows and 0.45–0.6 GB; the first `tags --all` takes about 30–40 s (the local rate is about
22k CVEs/s, scaled by row count).

### 8.1 Rule version 2 (products and product types)

Database: `nday_ptags_dev`, a copy of `nday_tags_dev` (same as above, with only three NVD sample files), migrated to 0013:

| step | result | time |
|---|---|---|
| `nday tags --all` (rule version 1 → 2) | 424,972 CVEs, 303,966 rewritten, 884,886 rows deleted and 1,101,127 inserted, 19,170 rejected | 51.9 s |
| `nday tags --all` again | 0 changes | 23 s |

`vuln_tag` has 1,101,136 rows (products 105,798, product types 110,452), 384 MB with indexes (after VACUUM FULL). Of the 244,448 CVEs that have `affected` rows,
34.3% have a product tag and 41.8% have a product-type tag; of all 405,802 non-rejected CVEs, 106,254 (26.2%) have a product-type tag. Coming only from `affected`
/ only from CPE / from both: products 80,552 / 3,937 / 2,773 CVEs, product types 98,726 / 4,252 / 3,276 CVEs (only 21,246 CVEs in the sample
have an NVD vulnerable CPE). The CVEs without a type are mostly Linux distribution entries (deliberately excluded), small PHP projects such as `sourcecodester`, and long-tail products from IBM/Oracle/Adobe.

## 9. Future admin features (not implemented)

- **Manual add/remove**: an admin UI writes `origin='staff'` rows (already allowed; `rule_version` is nullable) and, when needed, `ALTER TABLE vuln_tag ADD COLUMN created_by uuid`
  (a nullable column, so PG doesn't rewrite the table); suppression writes `vuln_tag_suppress` (the table, triggers and read/write semantics are all in place), and auditing goes through `admin_audit`.
- **Aliases** (such as "Heartbleed", "Log4Shell"): a new dimension (such as `alias`) added to the Go vocabulary (new slugs, new catalog selector values); manual rows use `staff`,
  and anything a rule can derive uses `rule` plus a new `RuleVersion`; `vuln_tag.tag` only checks the shape, so no table change is needed. Products and product types already exist (§1.1);
  possible extensions: staff-assigned `staff` product tags for long-tail products, an "other" type (not decided yet), and more product families (add them to `Products` and bump
  `RuleVersion` once).
- An admin list/edit page would read the raw `vuln_tag` table (which shows suppressed rule rows), while public pages keep reading only `vuln_tag_visible`.

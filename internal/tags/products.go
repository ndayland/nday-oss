package tags

import (
	"sort"
	"strings"
	"unicode"
)

// Product and product-type tags (docs/tags.md §1, §2): a curated registry of
// well-known product families, matched with high precision against two
// sources:
//
//   - the CVE's affected rows (table affected: vendor and product as the CVE
//     record states them, free text), normalized (lower case, trimmed,
//     whitespace collapsed);
//   - the CPE 2.3 names NVD's analysts give in the classified NVD record
//     (configurations[].nodes[].cpeMatch[] with vulnerable = true; the
//     "running on / with" platform entries are vulnerable = false and never
//     read).
//
// Every spelling and version of a family collapses into one product tag;
// a product carries its product type(s), so a product match also assigns
// the product-type tag. A few type rules (TypeRules) assign a product type
// without a product: a vendor whose products the data shows to be
// overwhelmingly of one type, or product wording that names the type for
// any vendor. Long-tail products get no product tag; a CVE whose product
// type cannot be determined gets no product-type tag (there is no "other"
// slug; adding one later is one vocabulary entry plus one line in
// deriveProducts).

// Product types (slugs, permanent). Display names are descriptive and
// localised (tag.name / tag.desc), like access tags.
const (
	PTOperatingSystem = "operating-system"
	PTBrowser         = "browser"
	PTChipset         = "chipset-firmware"
	PTNetworkDevice   = "network-device"
	PTFirewallVPN     = "firewall-vpn"
	PTNAS             = "nas-storage"
	PTIoTCamera       = "iot-camera"
	PTICS             = "ics"
	PTPrinter         = "printer"
	PTVirtualization  = "virtualization"
	PTDatabase        = "database"
	PTWebServer       = "web-server"
	PTCMS             = "cms"
	PTMailCollab      = "mail-collab"
	PTOffice          = "office-pdf"
	PTDevOps          = "devops"
	PTEnterpriseApp   = "enterprise-app"
	PTIdentity        = "identity"
	PTSecurity        = "security-software"
	PTMonitoring      = "monitoring"
	PTRemoteAccess    = "remote-access"
	PTAI              = "ai-ml"
	PTLibrary         = "library"
)

// productTypeTags are the product-type vocabulary entries, in display order.
var productTypeTags = []Tag{
	ptTag(PTOperatingSystem, "operating system"),
	ptTag(PTBrowser, "browser"),
	ptTag(PTChipset, "chipset / firmware"),
	ptTag(PTNetworkDevice, "router / switch"),
	ptTag(PTFirewallVPN, "firewall / VPN / security gateway"),
	ptTag(PTNAS, "NAS / storage"),
	ptTag(PTIoTCamera, "camera / IoT device"),
	ptTag(PTICS, "ICS / OT"),
	ptTag(PTPrinter, "printer"),
	ptTag(PTVirtualization, "virtualization / containers"),
	ptTag(PTDatabase, "database"),
	ptTag(PTWebServer, "web / application server"),
	ptTag(PTCMS, "CMS and plugins"),
	ptTag(PTMailCollab, "mail / collaboration"),
	ptTag(PTOffice, "office / document software"),
	ptTag(PTDevOps, "developer / CI tooling"),
	ptTag(PTEnterpriseApp, "enterprise application (ERP/CRM)"),
	ptTag(PTIdentity, "identity / access management"),
	ptTag(PTSecurity, "endpoint security / antivirus"),
	ptTag(PTMonitoring, "monitoring / logging / IT management"),
	ptTag(PTRemoteAccess, "remote desktop / remote access"),
	ptTag(PTAI, "AI / ML"),
	ptTag(PTLibrary, "open-source library / framework"),
}

func ptTag(slug, label string) Tag {
	return Tag{Slug: slug, Dim: DimProductType, Label: label,
		Rule: "A product of this type is matched in the CVE's affected products (CVE record) or in the vulnerable CPE names NVD's analysts give, " +
			"by nday's product registry; or a type rule of the registry matches an affected product."}
}

// Match is a rule over one normalized affected row (vendor, product).
//
//   - Vendors: exact normalized vendor spellings; nil means any vendor
//     (allowed only where the product wording is unambiguous for every
//     vendor; each such rule says why in a comment).
//   - Exact / Prefix / Words: the product matches if it equals an Exact
//     string, starts with a Prefix at a word boundary, or contains a Words
//     phrase delimited by word boundaries (a boundary is the string's start
//     or end or any character that is not a letter or digit). With none of
//     the three, any product of the vendors matches (vendor-only: type rules
//     only, enforced by a test).
//   - Not: whole-word phrases that veto a match.
type Match struct {
	Vendors []string
	Exact   []string
	Prefix  []string
	Words   []string
	Not     []string
}

// CPEMatch is a rule over the vendor and product of a CPE 2.3 name
// (unescaped, lower case): Vendors exact; the product equals an Exact token
// or starts with a Prefix (plain string prefix: CPE products are single
// tokens such as windows_10_1809); Not lists product prefixes that veto.
type CPEMatch struct {
	Vendors []string
	Exact   []string
	Prefix  []string
	Not     []string
}

// Product is one product family of the registry.
type Product struct {
	Slug  string
	Label string   // English in every locale (house rule for product names)
	Types []string // product-type slugs
	Aff   []Match
	CPE   []CPEMatch
}

// TypeRule assigns a product type without a product tag.
type TypeRule struct {
	// ID is stored in the basis (stable; "vendor:<name>" or "words:<name>").
	ID    string
	Type  string
	Match Match
	// CPE: the same rule over NVD CPE vendor names (optional).
	CPE []CPEMatch
	// Why: what the data showed (docs/tags.md lists the rules).
	Why string
}

func aff(vendors []string, m Match) Match { m.Vendors = vendors; return m }

func vs(v ...string) []string { return v }
func ss(v ...string) []string { return v }

// Vendor spellings seen in the affected table (2026-11-14 full import).
var (
	vMicrosoft = vs("microsoft", "microsoft corporation", "microsoft, inc")
	vGoogle    = vs("google", "google inc.", "google llc")
	vApple     = vs("apple", "apple inc.", "apple inc") // never "appleple inc." (a different company)
	vOracle    = vs("oracle corporation", "oracle")
	vMozilla   = vs("mozilla", "mozilla foundation", "mozilla corporation")
	vAdobe     = vs("adobe", "adobe systems incorporated", "adobe inc.")
	vCisco     = vs("cisco", "cisco systems, inc.", "cisco systems")
	vFortinet  = vs("fortinet", "fortinet, inc.")
	vPaloAlto  = vs("palo alto networks", "palo alto")
	vJuniper   = vs("juniper networks", "juniper", "juniper networks, inc.")
	vF5        = vs("f5", "f5 networks, inc.", "f5 networks", "f5, inc.")
	vVMware    = vs("vmware", "vmware by broadcom", "broadcom", "vmware, inc.")
	vQNAP      = vs("qnap systems inc.", "qnap", "qnap systems", "qnap systems, inc.")
	vSynology  = vs("synology", "synology inc.", "synology, inc.")
	vIBM       = vs("ibm", "ibm corporation")
	vRedHat    = vs("red hat", "red hat, inc.", "redhat", "redhat.com", "[red hat]")
	vApache    = vs("apache software foundation", "apache", "the apache software foundation")
	vHuawei    = vs("huawei", "huawei technologies co., ltd.", "huawei technologies", "www.huawei.com")
	vQualcomm  = vs("qualcomm, inc.", "qualcomm", "qualcomm technologies, inc.", "qualcomm technologies inc.")
	vNVIDIA    = vs("nvidia", "nvidia corporation")
	vSiemens   = vs("siemens", "siemens ag")
	vSchneider = vs("schneider electric", "schneider electric se")
	vHPE       = vs("hewlett packard enterprise (hpe)", "hewlett packard enterprise", "aruba networks", "arubanetworks", "hpe aruba networking")
	vAtlassian = vs("atlassian")
	vElastic   = vs("elastic")
	vSplunk    = vs("splunk", "splunk, inc", "splunk inc.", "splunk inc")
	vTrend     = vs("trend micro", "trend micro, inc.", "trend micro incorporated")
	vIvanti    = vs("ivanti")
	vSonicWall = vs("sonicwall", "sonicwall inc.")
	vCitrix    = vs("citrix", "citrix netscaler", "cloud software group", "netscaler", "netsclaer", "citirx", "citrix systems, inc.")
	vJenkins   = vs("jenkins project", "jenkins")
	vSAP       = vs("sap se", "sap_se", "sap")
	vMySQL     = vs("oracle corporation", "oracle", "mysql")
	vMongoDB   = vs("mongodb", "mongodb inc", "mongodb inc.", "mongodb, inc.")
	vDLink     = vs("d-link", "d-link corporation", "d-link japan k.k.", "d-link systems, inc.")
	vTPLink    = vs("tp-link systems inc.", "tp-link", "tp-link systems inc", "tp-link system inc.", "tp-link corporation limited", "tp-link technologies")
	vZoom      = vs("zoom video communications, inc.", "zoom video communications inc", "zoom communications, inc",
		"zoom communications inc.", "zoom communications", "zoom communications, inc.")
)

// Products is the registry, in display order (grouped by type). Slugs are
// permanent and never collide with other vocabulary slugs (init panics).
var Products = []Product{
	// ---- operating systems ----
	{Slug: "windows", Label: "Windows", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vMicrosoft, Match{Prefix: ss("windows", "microsoft windows"),
			// Windows Server is its own family; the rest are separate products named "Windows ..."
			Not: ss("server", "admin center", "defender", "terminal", "app client", "app for mac", "sdk", "adk", "hlk",
				"sysinternals", "sysmon", "azure pack", "intune", "malicious software removal tool", "secureconnector",
				"update assistant", "upgrade assistant", "remote help", "security app", "live", "media player for mac",
				"phone", "mobile", "embedded opentype")}),
			// combined product strings such as "windows server 2008 sp2 and r2 sp1, windows 7 sp1, windows 8.1, ..."
			aff(vMicrosoft, Match{Words: ss("windows 7 sp1", "windows 8.1", "windows xp", "windows vista"),
				Not: ss("on windows", "for windows", "edge", "internet explorer", "defender")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("windows"),
			Not: ss("windows_server", "windows_2000_server", "windows_2003_server", "windows_nt_server", "windows_admin_center",
				"windows_defender", "windows_terminal", "windows_sdk", "windows_live", "windows_phone", "windows_mobile",
				"windows_app", "windows_malicious_software_removal_tool", "windows_subsystem_for_android", "windows_azure_pack",
				"windows_host_compute_service_shim", "windows_media_encoder", "windows_virtual_pc")}}},
	{Slug: "windows-server", Label: "Windows Server", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vMicrosoft, Match{Prefix: ss("windows server", "microsoft windows server")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("windows_server", "windows_2000_server", "windows_2003_server", "windows_nt_server")}}},
	{Slug: "linux-kernel", Label: "Linux kernel", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vs("linux", "linux kernel", "the linux kernel organization", "linux kernel organization, inc."),
			Match{Exact: ss("linux", "kernel", "linux kernel")})},
		CPE: []CPEMatch{{Vendors: vs("linux"), Exact: ss("linux_kernel")}}},
	{Slug: "macos", Label: "macOS", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vApple, Match{Prefix: ss("macos", "mac os x", "os x", "mac os")})},
		CPE: []CPEMatch{{Vendors: vs("apple"), Exact: ss("macos", "mac_os_x", "mac_os_x_server", "mac_os", "os_x", "macos_server")}}},
	{Slug: "ios-ipados", Label: "iOS / iPadOS", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vApple, Match{Prefix: ss("ios", "ipados", "iphone os")})},
		CPE: []CPEMatch{{Vendors: vs("apple"), Exact: ss("iphone_os", "ipados", "ios")}}},
	{Slug: "watchos", Label: "watchOS", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vApple, Match{Prefix: ss("watchos")})},
		CPE: []CPEMatch{{Vendors: vs("apple"), Exact: ss("watchos")}}},
	{Slug: "tvos", Label: "tvOS", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vApple, Match{Prefix: ss("tvos")})},
		CPE: []CPEMatch{{Vendors: vs("apple"), Exact: ss("tvos")}}},
	{Slug: "visionos", Label: "visionOS", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vApple, Match{Prefix: ss("visionos")})},
		CPE: []CPEMatch{{Vendors: vs("apple"), Exact: ss("visionos")}}},
	{Slug: "android", Label: "Android", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(append(append([]string(nil), vGoogle...), "android", "android open source project"),
			Match{Exact: ss("android", "android kernel", "android os", "framework", "pixel", "kernel", "runtime"),
				Prefix: ss("android"), Not: ss("google search app", "play core")})},
		CPE: []CPEMatch{{Vendors: vs("google"), Exact: ss("android")}}},
	{Slug: "harmonyos", Label: "HarmonyOS", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vHuawei, Match{Prefix: ss("harmonyos")})},
		CPE: []CPEMatch{{Vendors: vs("huawei"), Exact: ss("harmonyos")}}},
	{Slug: "emui", Label: "EMUI", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vHuawei, Match{Prefix: ss("emui")})},
		CPE: []CPEMatch{{Vendors: vs("huawei"), Exact: ss("emui")}}},
	{Slug: "openharmony", Label: "OpenHarmony", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vs("openharmony"), Match{Exact: ss("openharmony")})},
		CPE: []CPEMatch{{Vendors: vs("openatom"), Exact: ss("openharmony")}}},
	{Slug: "freebsd", Label: "FreeBSD", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vs("freebsd", "the freebsd project"), Match{Exact: ss("freebsd")})},
		CPE: []CPEMatch{{Vendors: vs("freebsd"), Exact: ss("freebsd")}}},
	{Slug: "solaris", Label: "Solaris", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vOracle, Match{Prefix: ss("solaris", "oracle solaris")})},
		CPE: []CPEMatch{{Vendors: vs("oracle", "sun"), Exact: ss("solaris", "sunos")}}},
	{Slug: "ibm-i", Label: "IBM i", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vIBM, Match{Exact: ss("i", "ibm i")})},
		CPE: []CPEMatch{{Vendors: vs("ibm"), Exact: ss("i")}}},
	{Slug: "aix", Label: "AIX", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vIBM, Match{Exact: ss("aix")})},
		CPE: []CPEMatch{{Vendors: vs("ibm"), Exact: ss("aix")}}},
	{Slug: "zephyr", Label: "Zephyr RTOS", Types: ss(PTOperatingSystem),
		Aff: []Match{aff(vs("zephyrproject", "zephyrproject-rtos"), Match{Exact: ss("zephyr")})},
		CPE: []CPEMatch{{Vendors: vs("zephyrproject"), Exact: ss("zephyr")}}},

	// ---- browsers ----
	{Slug: "chrome", Label: "Chrome", Types: ss(PTBrowser),
		Aff: []Match{aff(vGoogle, Match{Exact: ss("chrome", "google chrome"), Prefix: ss("chrome for")})},
		CPE: []CPEMatch{{Vendors: vs("google"), Exact: ss("chrome")}}},
	{Slug: "firefox", Label: "Firefox", Types: ss(PTBrowser),
		Aff: []Match{aff(vMozilla, Match{Prefix: ss("firefox")})},
		CPE: []CPEMatch{{Vendors: vs("mozilla"), Exact: ss("firefox", "firefox_esr", "firefox_focus")}}},
	{Slug: "safari", Label: "Safari", Types: ss(PTBrowser),
		Aff: []Match{aff(vApple, Match{Prefix: ss("safari")})},
		CPE: []CPEMatch{{Vendors: vs("apple"), Exact: ss("safari")}}},
	{Slug: "edge", Label: "Microsoft Edge", Types: ss(PTBrowser),
		Aff: []Match{aff(vMicrosoft, Match{Prefix: ss("microsoft edge", "edge")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Exact: ss("edge", "edge_chromium")}}},
	{Slug: "internet-explorer", Label: "Internet Explorer", Types: ss(PTBrowser),
		Aff: []Match{aff(vMicrosoft, Match{Prefix: ss("internet explorer", "microsoft internet explorer")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Exact: ss("internet_explorer", "ie")}}},

	// ---- chipsets / firmware ----
	{Slug: "snapdragon", Label: "Qualcomm Snapdragon", Types: ss(PTChipset),
		Aff: []Match{aff(vQualcomm, Match{Words: ss("snapdragon")})},
		// NVD names Snapdragon chips' firmware by model (sd_835_firmware, mdm9607_firmware, ...)
		CPE: []CPEMatch{{Vendors: vs("qualcomm"), Prefix: ss("sd_", "sd1", "sd2", "sd4", "sd6", "sd7", "sd8", "sdm", "sda", "sdx", "sm4", "sm6", "sm7", "sm8", "sxr", "msm", "mdm", "apq", "snapdragon")}}},
	{Slug: "amd-ryzen", Label: "AMD Ryzen", Types: ss(PTChipset),
		Aff: []Match{aff(vs("amd"), Match{Words: ss("ryzen")})},
		CPE: []CPEMatch{{Vendors: vs("amd"), Prefix: ss("ryzen")}}},
	{Slug: "amd-epyc", Label: "AMD EPYC", Types: ss(PTChipset),
		Aff: []Match{aff(vs("amd"), Match{Words: ss("epyc")})},
		CPE: []CPEMatch{{Vendors: vs("amd"), Prefix: ss("epyc")}}},
	{Slug: "nvidia-gpu-driver", Label: "NVIDIA GPU driver", Types: ss(PTChipset),
		Aff: []Match{aff(vNVIDIA, Match{Words: ss("gpu display driver", "geforce", "quadro", "virtual gpu", "vgpu", "guest driver", "rtx", "tesla"),
			Not: ss("geforce experience", "geforce now", "dgx")})},
		CPE: []CPEMatch{{Vendors: vs("nvidia"), Prefix: ss("gpu_driver", "geforce", "quadro", "virtual_gpu", "vgpu", "tesla", "gpu_display_driver"),
			Not: ss("geforce_experience", "geforce_now")}}},

	// ---- network devices ----
	{Slug: "junos", Label: "Junos OS", Types: ss(PTNetworkDevice),
		Aff: []Match{aff(vJuniper, Match{Prefix: ss("junos os", "junos"), Not: ss("space", "snapshot administrator", "jsnapy")})},
		CPE: []CPEMatch{{Vendors: vs("juniper"), Exact: ss("junos", "junos_os_evolved")}}},
	{Slug: "cisco-ios-xe", Label: "Cisco IOS XE", Types: ss(PTNetworkDevice),
		Aff: []Match{aff(vCisco, Match{Words: ss("ios xe")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Exact: ss("ios_xe")}}},
	{Slug: "cisco-ios", Label: "Cisco IOS", Types: ss(PTNetworkDevice),
		Aff: []Match{aff(vCisco, Match{Exact: ss("ios", "cisco ios", "cisco ios software", "ios and ios xe")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Exact: ss("ios")}}},
	{Slug: "cisco-ios-xr", Label: "Cisco IOS XR", Types: ss(PTNetworkDevice),
		Aff: []Match{aff(vCisco, Match{Words: ss("ios xr")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Exact: ss("ios_xr")}}},
	{Slug: "cisco-nx-os", Label: "Cisco NX-OS", Types: ss(PTNetworkDevice),
		Aff: []Match{aff(vCisco, Match{Words: ss("nx-os")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Exact: ss("nx-os")}}},
	{Slug: "cisco-rv-routers", Label: "Cisco Small Business RV routers", Types: ss(PTNetworkDevice),
		Aff: []Match{aff(vCisco, Match{Words: ss("small business rv", "rv series")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Prefix: ss("rv0", "rv1", "rv2", "rv3", "rv4", "small_business_rv")}}},
	{Slug: "arubaos", Label: "ArubaOS", Types: ss(PTNetworkDevice),
		Aff: []Match{aff(vHPE, Match{Words: ss("arubaos", "aos-cx", "aos-8", "aos-10")})},
		CPE: []CPEMatch{{Vendors: vs("arubanetworks", "hp", "hpe"), Prefix: ss("arubaos")}}},
	{Slug: "arista-eos", Label: "Arista EOS", Types: ss(PTNetworkDevice),
		Aff: []Match{aff(vs("arista networks", "arista"), Match{Exact: ss("eos", "arista eos")})},
		CPE: []CPEMatch{{Vendors: vs("arista"), Exact: ss("eos")}}},
	{Slug: "routeros", Label: "MikroTik RouterOS", Types: ss(PTNetworkDevice),
		Aff: []Match{aff(vs("mikrotik"), Match{Prefix: ss("routeros")})},
		CPE: []CPEMatch{{Vendors: vs("mikrotik"), Exact: ss("routeros")}}},
	{Slug: "big-ip", Label: "F5 BIG-IP", Types: ss(PTNetworkDevice),
		Aff: []Match{aff(append(append([]string(nil), vF5...), "big-ip"), Match{Words: ss("big-ip")})},
		CPE: []CPEMatch{{Vendors: vs("f5"), Prefix: ss("big-ip")}}},

	// ---- firewalls / VPN / security gateways ----
	{Slug: "fortios", Label: "FortiOS", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vFortinet, Match{Prefix: ss("fortios", "fortigate")})},
		CPE: []CPEMatch{{Vendors: vs("fortinet"), Prefix: ss("fortios", "fortigate")}}},
	{Slug: "fortiproxy", Label: "FortiProxy", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vFortinet, Match{Prefix: ss("fortiproxy")})},
		CPE: []CPEMatch{{Vendors: vs("fortinet"), Prefix: ss("fortiproxy")}}},
	{Slug: "fortiweb", Label: "FortiWeb", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vFortinet, Match{Prefix: ss("fortiweb")})},
		CPE: []CPEMatch{{Vendors: vs("fortinet"), Prefix: ss("fortiweb")}}},
	{Slug: "fortimanager", Label: "FortiManager", Types: ss(PTMonitoring),
		Aff: []Match{aff(vFortinet, Match{Prefix: ss("fortimanager")})},
		CPE: []CPEMatch{{Vendors: vs("fortinet"), Prefix: ss("fortimanager")}}},
	{Slug: "fortianalyzer", Label: "FortiAnalyzer", Types: ss(PTMonitoring),
		Aff: []Match{aff(vFortinet, Match{Prefix: ss("fortianalyzer")})},
		CPE: []CPEMatch{{Vendors: vs("fortinet"), Prefix: ss("fortianalyzer")}}},
	{Slug: "pan-os", Label: "PAN-OS", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vPaloAlto, Match{Words: ss("pan-os")})},
		CPE: []CPEMatch{{Vendors: vs("paloaltonetworks"), Exact: ss("pan-os")}}},
	{Slug: "globalprotect", Label: "GlobalProtect", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vPaloAlto, Match{Words: ss("globalprotect")})},
		CPE: []CPEMatch{{Vendors: vs("paloaltonetworks"), Prefix: ss("globalprotect")}}},
	{Slug: "cisco-asa", Label: "Cisco ASA", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vCisco, Match{Words: ss("adaptive security appliance")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Prefix: ss("adaptive_security_appliance", "asa_55", "5500_series_adaptive_security_appliance")}}},
	{Slug: "cisco-ftd", Label: "Cisco Firepower Threat Defense", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vCisco, Match{Words: ss("firepower threat defense", "firewall threat defense")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Exact: ss("firepower_threat_defense", "secure_firewall_threat_defense")}}},
	{Slug: "cisco-fmc", Label: "Cisco Firepower Management Center", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vCisco, Match{Words: ss("firepower management center", "firewall management center")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Prefix: ss("firepower_management_center", "secure_firewall_management_center")}}},
	{Slug: "anyconnect", Label: "Cisco AnyConnect / Secure Client", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vCisco, Match{Words: ss("anyconnect", "secure client")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Prefix: ss("anyconnect", "secure_client")}}},
	{Slug: "netscaler", Label: "NetScaler ADC / Gateway", Types: ss(PTFirewallVPN, PTNetworkDevice),
		Aff: []Match{aff(vCitrix, Match{Words: ss("netscaler", "citrix adc", "citrix gateway", "application delivery controller")})},
		CPE: []CPEMatch{{Vendors: vs("citrix"), Prefix: ss("netscaler", "application_delivery_controller", "gateway")}}},
	{Slug: "ivanti-connect-secure", Label: "Ivanti Connect Secure", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vIvanti, Match{Words: ss("connect secure")}),
			aff(vs("pulse secure"), Match{Words: ss("pulse connect secure")})},
		CPE: []CPEMatch{{Vendors: vs("ivanti"), Exact: ss("connect_secure")}, {Vendors: vs("pulsesecure"), Exact: ss("pulse_connect_secure")}}},
	{Slug: "sonicos", Label: "SonicOS", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vSonicWall, Match{Words: ss("sonicos")})},
		CPE: []CPEMatch{{Vendors: vs("sonicwall"), Exact: ss("sonicos")}}},
	{Slug: "sonicwall-sma", Label: "SonicWall SMA", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vSonicWall, Match{Words: ss("sma", "secure mobile access", "sma100", "sma1000")})},
		CPE: []CPEMatch{{Vendors: vs("sonicwall"), Prefix: ss("sma_", "sma1", "secure_mobile_access")}}},
	{Slug: "fireware", Label: "WatchGuard Fireware", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vs("watchguard"), Match{Words: ss("fireware")})},
		CPE: []CPEMatch{{Vendors: vs("watchguard"), Prefix: ss("fireware")}}},
	{Slug: "check-point-quantum", Label: "Check Point Quantum", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vs("checkpoint", "check point", "check point software technologies ltd."),
			Match{Words: ss("quantum security gateway", "quantum", "security gateway", "gaia", "spark firewalls", "mobile access")})},
		CPE: []CPEMatch{{Vendors: vs("checkpoint"), Prefix: ss("quantum", "gaia", "security_gateway")}}},
	{Slug: "sophos-firewall", Label: "Sophos Firewall", Types: ss(PTFirewallVPN),
		Aff: []Match{aff(vs("sophos"), Match{Words: ss("firewall", "utm", "sg utm", "xg firewall", "cyberoamos")})},
		CPE: []CPEMatch{{Vendors: vs("sophos"), Prefix: ss("sfos", "xg_firewall", "firewall", "unified_threat_management")}}},

	// ---- NAS / storage ----
	{Slug: "qnap-qts", Label: "QNAP QTS / QuTS hero", Types: ss(PTNAS),
		Aff: []Match{aff(vQNAP, Match{Prefix: ss("qts", "quts hero", "qutscloud")})},
		CPE: []CPEMatch{{Vendors: vs("qnap"), Prefix: ss("qts", "quts_hero", "qutscloud")}}},
	{Slug: "synology-dsm", Label: "Synology DSM", Types: ss(PTNAS),
		Aff: []Match{aff(vSynology, Match{Words: ss("diskstation manager", "dsm")})},
		CPE: []CPEMatch{{Vendors: vs("synology"), Prefix: ss("diskstation_manager")}}},

	{Slug: "powerscale-onefs", Label: "Dell PowerScale OneFS", Types: ss(PTNAS),
		Aff: []Match{aff(vs("dell", "dell emc", "dell inc."), Match{Words: ss("onefs")})},
		CPE: []CPEMatch{{Vendors: vs("dell", "dellemc"), Prefix: ss("powerscale_onefs", "emc_isilon_onefs", "isilon_onefs", "onefs")}}},

	// ---- cameras / IoT ----
	{Slug: "axis-os", Label: "AXIS OS", Types: ss(PTIoTCamera),
		Aff: []Match{aff(vs("axis communications ab", "axis communications", "axis"), Match{Exact: ss("axis os", "axis os 2022", "axis os 2024")})},
		CPE: []CPEMatch{{Vendors: vs("axis"), Exact: ss("axis_os")}}},

	// ---- ICS / OT ----
	{Slug: "simatic", Label: "Siemens SIMATIC", Types: ss(PTICS),
		Aff: []Match{aff(vSiemens, Match{Words: ss("simatic")})},
		CPE: []CPEMatch{{Vendors: vs("siemens"), Prefix: ss("simatic")}}},
	{Slug: "scalance", Label: "Siemens SCALANCE", Types: ss(PTICS, PTNetworkDevice),
		Aff: []Match{aff(vSiemens, Match{Words: ss("scalance")})},
		CPE: []CPEMatch{{Vendors: vs("siemens"), Prefix: ss("scalance")}}},
	{Slug: "codesys", Label: "CODESYS", Types: ss(PTICS),
		Aff: []Match{aff(vs("codesys", "codesys gmbh", "3s-smart software solutions gmbh", "3s-smart software solutions"), Match{Words: ss("codesys")})},
		CPE: []CPEMatch{{Vendors: vs("codesys"), Prefix: ss("")}}},
	{Slug: "modicon", Label: "Schneider Modicon", Types: ss(PTICS),
		Aff: []Match{aff(vSchneider, Match{Words: ss("modicon")})},
		CPE: []CPEMatch{{Vendors: vs("schneider-electric"), Prefix: ss("modicon")}}},

	// ---- virtualization / containers ----
	{Slug: "esxi", Label: "VMware ESXi", Types: ss(PTVirtualization),
		Aff: []Match{aff(vVMware, Match{Words: ss("esxi"), Not: ss("hosts using amd")})},
		CPE: []CPEMatch{{Vendors: vs("vmware"), Exact: ss("esxi", "esx")}}},
	{Slug: "vcenter", Label: "VMware vCenter Server", Types: ss(PTVirtualization),
		Aff: []Match{aff(vVMware, Match{Words: ss("vcenter server", "vmware vcenter"), Not: ss("plug-in", "plugin")})},
		CPE: []CPEMatch{{Vendors: vs("vmware"), Exact: ss("vcenter_server")}}},
	{Slug: "vmware-workstation", Label: "VMware Workstation / Fusion", Types: ss(PTVirtualization),
		Aff: []Match{aff(vVMware, Match{Exact: ss("workstation", "fusion", "vmware workstation", "vmware fusion", "workstation pro", "workstation player"),
			Prefix: ss("vmware workstation", "vmware fusion", "workstation pro", "fusion pro")})},
		CPE: []CPEMatch{{Vendors: vs("vmware"), Exact: ss("workstation", "fusion", "workstation_pro", "workstation_player", "player")}}},
	{Slug: "virtualbox", Label: "VirtualBox", Types: ss(PTVirtualization),
		Aff: []Match{aff(vOracle, Match{Words: ss("virtualbox")})},
		CPE: []CPEMatch{{Vendors: vs("oracle"), Exact: ss("vm_virtualbox", "virtualbox")}}},
	{Slug: "xen", Label: "Xen", Types: ss(PTVirtualization),
		Aff: []Match{aff(vs("xen", "xen project"), Match{Exact: ss("xen")})},
		CPE: []CPEMatch{{Vendors: vs("xen"), Exact: ss("xen")}}},
	{Slug: "qemu", Label: "QEMU", Types: ss(PTVirtualization),
		Aff: []Match{aff(vs("qemu", "the qemu project"), Match{Exact: ss("qemu")})},
		CPE: []CPEMatch{{Vendors: vs("qemu"), Exact: ss("qemu")}}},
	{Slug: "kubernetes", Label: "Kubernetes", Types: ss(PTVirtualization),
		Aff: []Match{aff(vs("kubernetes"), Match{Exact: ss("kubernetes", "kubelet", "kube-apiserver", "kube-proxy", "kubectl")})},
		CPE: []CPEMatch{{Vendors: vs("kubernetes"), Exact: ss("kubernetes", "kubelet", "kube-apiserver")}}},
	{Slug: "docker", Label: "Docker / Moby", Types: ss(PTVirtualization),
		Aff: []Match{aff(vs("docker", "docker inc.", "docker, inc."), Match{Exact: ss("docker", "docker desktop", "docker engine", "docker cli", "docker compose")}),
			aff(vs("moby", "mobyproject"), Match{Exact: ss("moby")})},
		CPE: []CPEMatch{{Vendors: vs("docker"), Exact: ss("docker", "desktop", "engine", "docker_desktop")}, {Vendors: vs("mobyproject"), Exact: ss("moby")}}},
	{Slug: "powervm", Label: "IBM PowerVM", Types: ss(PTVirtualization),
		Aff: []Match{aff(vIBM, Match{Words: ss("powervm")})},
		CPE: []CPEMatch{{Vendors: vs("ibm"), Prefix: ss("powervm")}}},
	{Slug: "rancher", Label: "Rancher", Types: ss(PTVirtualization),
		Aff: []Match{aff(vs("suse", "rancher", "rancher labs"), Match{Exact: ss("rancher")})},
		CPE: []CPEMatch{{Vendors: vs("suse", "rancher"), Exact: ss("rancher")}}},
	{Slug: "openshift", Label: "OpenShift", Types: ss(PTVirtualization),
		Aff: []Match{aff(vRedHat, Match{Words: ss("openshift container platform")})},
		CPE: []CPEMatch{{Vendors: vs("redhat"), Exact: ss("openshift_container_platform", "openshift")}}},

	// ---- databases ----
	{Slug: "mysql", Label: "MySQL", Types: ss(PTDatabase),
		Aff: []Match{aff(vMySQL, Match{Prefix: ss("mysql")})},
		CPE: []CPEMatch{{Vendors: vs("oracle", "mysql"), Prefix: ss("mysql")}}},
	{Slug: "mariadb", Label: "MariaDB", Types: ss(PTDatabase),
		Aff: []Match{aff(vs("mariadb", "mariadb foundation", "mariadb-corporation", "mariadb corporation"), Match{Prefix: ss("mariadb")})},
		CPE: []CPEMatch{{Vendors: vs("mariadb"), Exact: ss("mariadb")}}},
	{Slug: "postgresql", Label: "PostgreSQL", Types: ss(PTDatabase),
		Aff: []Match{aff(vs("postgresql", "postgresql global development group", "the postgresql global development group"), Match{Exact: ss("postgresql")})},
		CPE: []CPEMatch{{Vendors: vs("postgresql"), Exact: ss("postgresql")}}},
	{Slug: "sql-server", Label: "SQL Server", Types: ss(PTDatabase),
		Aff: []Match{aff(vMicrosoft, Match{Prefix: ss("microsoft sql server", "sql server"), Not: ss("odbc", "oledb", "ole db", "jdbc", "driver")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("sql_server")}}},
	{Slug: "oracle-database", Label: "Oracle Database", Types: ss(PTDatabase),
		Aff: []Match{aff(vOracle, Match{Prefix: ss("database server", "oracle database", "database -", "database")})},
		CPE: []CPEMatch{{Vendors: vs("oracle"), Exact: ss("database_server", "database")}}},
	{Slug: "mongodb", Label: "MongoDB", Types: ss(PTDatabase),
		Aff: []Match{aff(vMongoDB, Match{Exact: ss("mongodb", "mongodb server", "mongodb enterprise server")})},
		CPE: []CPEMatch{{Vendors: vs("mongodb"), Exact: ss("mongodb")}}},
	{Slug: "redis", Label: "Redis", Types: ss(PTDatabase),
		Aff: []Match{aff(vs("redis", "redis labs", "redis ltd", "redis ltd."), Match{Exact: ss("redis")})},
		CPE: []CPEMatch{{Vendors: vs("redis", "redislabs"), Exact: ss("redis")}}},
	{Slug: "sqlite", Label: "SQLite", Types: ss(PTDatabase, PTLibrary),
		Aff: []Match{aff(vs("sqlite"), Match{Exact: ss("sqlite")})},
		CPE: []CPEMatch{{Vendors: vs("sqlite"), Exact: ss("sqlite")}}},
	{Slug: "db2", Label: "Db2", Types: ss(PTDatabase),
		Aff: []Match{aff(vIBM, Match{Words: ss("db2")})},
		CPE: []CPEMatch{{Vendors: vs("ibm"), Prefix: ss("db2")}}},
	{Slug: "elasticsearch", Label: "Elasticsearch", Types: ss(PTDatabase),
		Aff: []Match{aff(vElastic, Match{Exact: ss("elasticsearch")})},
		CPE: []CPEMatch{{Vendors: vs("elastic", "elasticsearch"), Exact: ss("elasticsearch")}}},

	// ---- web / application servers, runtimes ----
	{Slug: "apache-http-server", Label: "Apache HTTP Server", Types: ss(PTWebServer),
		Aff: []Match{aff(vApache, Match{Exact: ss("apache http server", "http server", "httpd", "apache httpd")})},
		CPE: []CPEMatch{{Vendors: vs("apache"), Exact: ss("http_server")}}},
	{Slug: "tomcat", Label: "Apache Tomcat", Types: ss(PTWebServer),
		Aff: []Match{aff(vApache, Match{Exact: ss("apache tomcat", "tomcat")})},
		CPE: []CPEMatch{{Vendors: vs("apache"), Exact: ss("tomcat")}}},
	{Slug: "nginx", Label: "NGINX", Types: ss(PTWebServer),
		Aff: []Match{aff(vF5, Match{Prefix: ss("nginx")}), aff(vs("nginx", "nginx, inc."), Match{Prefix: ss("nginx")})},
		CPE: []CPEMatch{{Vendors: vs("f5", "nginx"), Prefix: ss("nginx")}}},
	{Slug: "weblogic", Label: "WebLogic Server", Types: ss(PTWebServer),
		Aff: []Match{aff(vOracle, Match{Words: ss("weblogic server")})},
		CPE: []CPEMatch{{Vendors: vs("oracle", "bea"), Exact: ss("weblogic_server")}}},
	{Slug: "websphere", Label: "WebSphere Application Server", Types: ss(PTWebServer),
		Aff: []Match{aff(vIBM, Match{Words: ss("websphere application server")})},
		CPE: []CPEMatch{{Vendors: vs("ibm"), Prefix: ss("websphere_application_server")}}},
	{Slug: "jboss-eap", Label: "JBoss EAP", Types: ss(PTWebServer),
		Aff: []Match{aff(vRedHat, Match{Words: ss("jboss enterprise application platform")})},
		CPE: []CPEMatch{{Vendors: vs("redhat"), Prefix: ss("jboss_enterprise_application_platform")}}},
	{Slug: "coldfusion", Label: "Adobe ColdFusion", Types: ss(PTWebServer),
		Aff: []Match{aff(vAdobe, Match{Prefix: ss("coldfusion", "adobe coldfusion")})},
		CPE: []CPEMatch{{Vendors: vs("adobe"), Exact: ss("coldfusion")}}},
	{Slug: "envoy", Label: "Envoy", Types: ss(PTWebServer),
		Aff: []Match{aff(vs("envoyproxy"), Match{Exact: ss("envoy")})},
		CPE: []CPEMatch{{Vendors: vs("envoyproxy"), Exact: ss("envoy")}}},
	{Slug: "traefik", Label: "Traefik", Types: ss(PTWebServer),
		Aff: []Match{aff(vs("traefik", "traefiklabs", "traefik labs"), Match{Exact: ss("traefik")})},
		CPE: []CPEMatch{{Vendors: vs("traefik"), Exact: ss("traefik")}}},
	{Slug: "apache-traffic-server", Label: "Apache Traffic Server", Types: ss(PTWebServer),
		Aff: []Match{aff(vApache, Match{Exact: ss("apache traffic server", "traffic server")})},
		CPE: []CPEMatch{{Vendors: vs("apache"), Exact: ss("traffic_server")}}},
	{Slug: "nodejs", Label: "Node.js", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("nodejs", "node.js", "node.js foundation", "openjs foundation"), Match{Exact: ss("node", "node.js", "nodejs")})},
		CPE: []CPEMatch{{Vendors: vs("nodejs"), Exact: ss("node.js")}}},
	{Slug: "php", Label: "PHP", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("php group", "php"), Match{Exact: ss("php")})},
		CPE: []CPEMatch{{Vendors: vs("php"), Exact: ss("php")}}},

	// ---- CMS ----
	{Slug: "wordpress", Label: "WordPress", Types: ss(PTCMS),
		Aff: []Match{aff(vs("wordpress", "wordpress foundation", "wordpress.org", "automattic"), Match{Exact: ss("wordpress", "wordpress core")})},
		CPE: []CPEMatch{{Vendors: vs("wordpress"), Exact: ss("wordpress")}}},
	{Slug: "drupal", Label: "Drupal", Types: ss(PTCMS),
		Aff: []Match{aff(vs("drupal", "drupal.org", "drupal core"), Match{Exact: ss("drupal core", "drupal", "core")})},
		CPE: []CPEMatch{{Vendors: vs("drupal"), Exact: ss("drupal")}}},
	{Slug: "joomla", Label: "Joomla!", Types: ss(PTCMS),
		Aff: []Match{aff(vs("joomla! project", "joomla!", "joomla"), Match{Exact: ss("joomla! cms", "joomla!", "joomla", "joomla cms")})},
		CPE: []CPEMatch{{Vendors: vs("joomla"), Exact: ss("joomla!", "joomla")}}},
	{Slug: "typo3", Label: "TYPO3", Types: ss(PTCMS),
		Aff: []Match{aff(vs("typo3", "typo3 core", "typo3 association"), Match{Exact: ss("typo3", "typo3 cms", "typo3 core", "core")})},
		CPE: []CPEMatch{{Vendors: vs("typo3"), Exact: ss("typo3")}}},
	{Slug: "magento", Label: "Adobe Commerce / Magento", Types: ss(PTCMS),
		Aff: []Match{aff(vAdobe, Match{Words: ss("magento", "adobe commerce")}), aff(vs("magento"), Match{Exact: ss("magento")})},
		CPE: []CPEMatch{{Vendors: vs("adobe", "magento"), Exact: ss("magento", "commerce", "magento_open_source")}}},
	{Slug: "aem", Label: "Adobe Experience Manager", Types: ss(PTCMS),
		Aff: []Match{aff(vAdobe, Match{Words: ss("experience manager")})},
		CPE: []CPEMatch{{Vendors: vs("adobe"), Prefix: ss("experience_manager")}}},
	{Slug: "liferay", Label: "Liferay Portal / DXP", Types: ss(PTCMS),
		Aff: []Match{aff(vs("liferay"), Match{Exact: ss("portal", "dxp", "liferay portal", "liferay dxp", "liferay")})},
		CPE: []CPEMatch{{Vendors: vs("liferay"), Exact: ss("liferay_portal", "dxp", "digital_experience_platform")}}},
	{Slug: "prestashop", Label: "PrestaShop", Types: ss(PTCMS),
		Aff: []Match{aff(vs("prestashop"), Match{Exact: ss("prestashop")})},
		CPE: []CPEMatch{{Vendors: vs("prestashop"), Exact: ss("prestashop")}}},
	{Slug: "craft-cms", Label: "Craft CMS", Types: ss(PTCMS),
		Aff: []Match{aff(vs("craftcms"), Match{Exact: ss("cms", "craft cms", "craftcms")})},
		CPE: []CPEMatch{{Vendors: vs("craftcms"), Exact: ss("craft_cms")}}},
	{Slug: "concrete-cms", Label: "Concrete CMS", Types: ss(PTCMS),
		Aff: []Match{aff(vs("concrete cms", "concretecms"), Match{Exact: ss("concrete cms", "concrete5")})},
		CPE: []CPEMatch{{Vendors: vs("concretecms", "concrete5"), Exact: ss("concrete_cms", "concrete5")}}},
	{Slug: "grav", Label: "Grav", Types: ss(PTCMS),
		Aff: []Match{aff(vs("getgrav", "grav", "trilby media"), Match{Exact: ss("grav", "getgrav/grav", "grav cms")})},
		CPE: []CPEMatch{{Vendors: vs("getgrav"), Prefix: ss("grav")}}},
	{Slug: "ghost", Label: "Ghost", Types: ss(PTCMS),
		Aff: []Match{aff(vs("tryghost", "ghost foundation"), Match{Exact: ss("ghost")})},
		CPE: []CPEMatch{{Vendors: vs("ghost"), Exact: ss("ghost")}}},
	{Slug: "mediawiki", Label: "MediaWiki", Types: ss(PTCMS),
		Aff: []Match{aff(vs("wikimedia foundation", "mediawiki"), Match{Prefix: ss("mediawiki")})},
		CPE: []CPEMatch{{Vendors: vs("mediawiki"), Exact: ss("mediawiki")}}},
	{Slug: "xwiki", Label: "XWiki", Types: ss(PTCMS),
		Aff: []Match{aff(vs("xwiki"), Match{Prefix: ss("xwiki-platform", "xwiki")})},
		CPE: []CPEMatch{{Vendors: vs("xwiki"), Exact: ss("xwiki")}}},

	// ---- mail / collaboration ----
	{Slug: "exchange", Label: "Exchange Server", Types: ss(PTMailCollab),
		Aff: []Match{aff(vMicrosoft, Match{Words: ss("exchange server", "outlook web access")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("exchange_server", "outlook_web_access")}}},
	{Slug: "sharepoint", Label: "SharePoint", Types: ss(PTMailCollab),
		Aff: []Match{aff(vMicrosoft, Match{Words: ss("sharepoint"), Not: ss("saml sso plugin")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("sharepoint")}}},
	{Slug: "outlook", Label: "Outlook", Types: ss(PTMailCollab),
		// (Outlook Web Access is Exchange's web client: exchange)
		Aff: []Match{aff(vMicrosoft, Match{Words: ss("outlook"), Not: ss("outlook web access")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("outlook"), Not: ss("outlook_web_access")}}},
	{Slug: "teams", Label: "Microsoft Teams", Types: ss(PTMailCollab),
		Aff: []Match{aff(vMicrosoft, Match{Words: ss("teams")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("teams")}}},
	{Slug: "thunderbird", Label: "Thunderbird", Types: ss(PTMailCollab),
		Aff: []Match{aff(vMozilla, Match{Prefix: ss("thunderbird")})},
		CPE: []CPEMatch{{Vendors: vs("mozilla"), Prefix: ss("thunderbird")}}},
	{Slug: "zimbra", Label: "Zimbra", Types: ss(PTMailCollab),
		Aff: []Match{aff(vs("zimbra", "synacor"), Match{Words: ss("zimbra")})},
		CPE: []CPEMatch{{Vendors: vs("zimbra", "synacor"), Prefix: ss("zimbra", "collaboration")}}},
	{Slug: "roundcube", Label: "Roundcube", Types: ss(PTMailCollab),
		Aff: []Match{aff(vs("roundcube"), Match{Words: ss("webmail", "roundcube")})},
		CPE: []CPEMatch{{Vendors: vs("roundcube"), Prefix: ss("webmail")}}},
	{Slug: "confluence", Label: "Confluence", Types: ss(PTMailCollab),
		Aff: []Match{aff(vAtlassian, Match{Prefix: ss("confluence")})},
		CPE: []CPEMatch{{Vendors: vs("atlassian"), Prefix: ss("confluence")}}},
	{Slug: "mattermost", Label: "Mattermost", Types: ss(PTMailCollab),
		Aff: []Match{aff(vs("mattermost"), Match{Prefix: ss("mattermost")})},
		CPE: []CPEMatch{{Vendors: vs("mattermost"), Prefix: ss("mattermost")}}},
	{Slug: "nextcloud", Label: "Nextcloud", Types: ss(PTMailCollab),
		Aff: []Match{aff(vs("nextcloud"), Match{Exact: ss("security-advisories", "nextcloud", "server"), Prefix: ss("nextcloud")})},
		CPE: []CPEMatch{{Vendors: vs("nextcloud"), Prefix: ss("nextcloud")}}},
	{Slug: "discourse", Label: "Discourse", Types: ss(PTMailCollab),
		Aff: []Match{aff(vs("discourse"), Match{Prefix: ss("discourse")})},
		CPE: []CPEMatch{{Vendors: vs("discourse"), Exact: ss("discourse")}}},
	{Slug: "fortimail", Label: "FortiMail", Types: ss(PTMailCollab),
		Aff: []Match{aff(vFortinet, Match{Prefix: ss("fortimail")})},
		CPE: []CPEMatch{{Vendors: vs("fortinet"), Prefix: ss("fortimail")}}},
	{Slug: "zoom", Label: "Zoom", Types: ss(PTMailCollab),
		Aff: []Match{aff(vZoom, Match{Words: ss("zoom")})},
		CPE: []CPEMatch{{Vendors: vs("zoom"), Prefix: ss("")}}},
	{Slug: "webex", Label: "Webex", Types: ss(PTMailCollab),
		Aff: []Match{aff(vCisco, Match{Words: ss("webex")})},
		CPE: []CPEMatch{{Vendors: vs("cisco", "webex"), Prefix: ss("webex")}}},
	{Slug: "cisco-ucm", Label: "Cisco Unified Communications Manager", Types: ss(PTMailCollab),
		Aff: []Match{aff(vCisco, Match{Words: ss("unified communications manager")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Prefix: ss("unified_communications_manager")}}},
	{Slug: "hcl-domino", Label: "HCL Domino / Notes", Types: ss(PTMailCollab),
		Aff: []Match{aff(vs("hcl software", "hclsoftware", "hcl technologies", "hcl"), Match{Words: ss("domino", "notes")})},
		CPE: []CPEMatch{{Vendors: vs("hcltech", "hcltechsw", "ibm"), Prefix: ss("domino", "notes", "lotus_domino", "lotus_notes")}}},

	// ---- office / document software ----
	{Slug: "office", Label: "Microsoft Office", Types: ss(PTOffice),
		Aff: []Match{aff(vMicrosoft, Match{Words: ss("office", "365 apps", "word", "excel", "powerpoint", "visio", "publisher", "onenote"),
			Prefix: ss("microsoft access", "access"),
			Not:    ss("officescan", "office online server", "office web apps", "visual studio", "outlook web access")}),
			aff(vMicrosoft, Match{Prefix: ss("microsoft office online server", "office online server", "microsoft office web apps", "office web apps")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("office", "365_apps", "word", "excel", "powerpoint", "visio", "publisher", "onenote", "access"),
			Not: ss("office_sharepoint")}}},
	{Slug: "acrobat", Label: "Adobe Acrobat / Reader", Types: ss(PTOffice),
		Aff: []Match{aff(vAdobe, Match{Words: ss("acrobat", "adobe reader"), Exact: ss("reader")})},
		CPE: []CPEMatch{{Vendors: vs("adobe"), Prefix: ss("acrobat"), Exact: ss("reader")}}},
	{Slug: "foxit-pdf", Label: "Foxit PDF Reader / Editor", Types: ss(PTOffice),
		Aff: []Match{aff(vs("foxit", "foxit software inc.", "foxit software"), Match{Words: ss("reader", "pdf", "phantompdf", "editor")})},
		CPE: []CPEMatch{{Vendors: vs("foxitsoftware", "foxit"), Prefix: ss("phantompdf", "foxit_reader", "reader", "foxit_pdf", "pdf_editor", "pdf_reader")}}},
	{Slug: "pdf-xchange", Label: "PDF-XChange", Types: ss(PTOffice),
		Aff: []Match{aff(vs("pdf-xchange", "tracker software"), Match{Words: ss("pdf-xchange")})},
		CPE: []CPEMatch{{Vendors: vs("pdf-xchange", "tracker-software"), Prefix: ss("pdf-xchange")}}},
	{Slug: "libreoffice", Label: "LibreOffice", Types: ss(PTOffice),
		Aff: []Match{aff(vs("the document foundation", "document foundation", "libreoffice"), Match{Exact: ss("libreoffice")})},
		CPE: []CPEMatch{{Vendors: vs("libreoffice"), Exact: ss("libreoffice")}}},

	// ---- developer / CI tooling ----
	{Slug: "gitlab", Label: "GitLab", Types: ss(PTDevOps),
		Aff: []Match{aff(vs("gitlab"), Match{Exact: ss("gitlab", "gitlab ce/ee", "gitlab-ce", "gitlab-ee", "gitlab enterprise edition", "gitlab community edition")})},
		CPE: []CPEMatch{{Vendors: vs("gitlab"), Exact: ss("gitlab")}}},
	{Slug: "jenkins", Label: "Jenkins", Types: ss(PTDevOps),
		Aff: []Match{aff(vJenkins, Match{Exact: ss("jenkins")})},
		CPE: []CPEMatch{{Vendors: vs("jenkins"), Exact: ss("jenkins")}}},
	{Slug: "teamcity", Label: "TeamCity", Types: ss(PTDevOps),
		Aff: []Match{aff(vs("jetbrains"), Match{Exact: ss("teamcity")})},
		CPE: []CPEMatch{{Vendors: vs("jetbrains"), Exact: ss("teamcity")}}},
	{Slug: "github-enterprise-server", Label: "GitHub Enterprise Server", Types: ss(PTDevOps),
		Aff: []Match{aff(vs("github"), Match{Exact: ss("enterprise server", "github enterprise server")})},
		CPE: []CPEMatch{{Vendors: vs("github"), Exact: ss("enterprise_server")}}},
	{Slug: "gitea", Label: "Gitea", Types: ss(PTDevOps),
		Aff: []Match{aff(vs("gitea", "go-gitea"), Match{Prefix: ss("gitea", "go-gitea/gitea")})},
		CPE: []CPEMatch{{Vendors: vs("gitea"), Exact: ss("gitea")}}},
	{Slug: "jira", Label: "Jira", Types: ss(PTDevOps),
		Aff: []Match{aff(vAtlassian, Match{Prefix: ss("jira")})},
		CPE: []CPEMatch{{Vendors: vs("atlassian"), Prefix: ss("jira")}}},
	{Slug: "artifactory", Label: "JFrog Artifactory", Types: ss(PTDevOps),
		Aff: []Match{aff(vs("jfrog"), Match{Prefix: ss("artifactory", "jfrog artifactory")})},
		CPE: []CPEMatch{{Vendors: vs("jfrog"), Prefix: ss("artifactory")}}},
	{Slug: "visual-studio", Label: "Visual Studio", Types: ss(PTDevOps),
		Aff: []Match{aff(vMicrosoft, Match{Words: ss("visual studio"), Not: ss("visual studio code")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("visual_studio"), Not: ss("visual_studio_code")}}},
	{Slug: "vscode", Label: "Visual Studio Code", Types: ss(PTDevOps),
		Aff: []Match{aff(vMicrosoft, Match{Words: ss("visual studio code")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("visual_studio_code")}}},
	{Slug: "airflow", Label: "Apache Airflow", Types: ss(PTDevOps),
		Aff: []Match{aff(vApache, Match{Prefix: ss("apache airflow", "airflow")})},
		CPE: []CPEMatch{{Vendors: vs("apache"), Prefix: ss("airflow")}}},
	{Slug: "n8n", Label: "n8n", Types: ss(PTDevOps),
		Aff: []Match{aff(vs("n8n-io", "n8n"), Match{Exact: ss("n8n")})},
		CPE: []CPEMatch{{Vendors: vs("n8n"), Exact: ss("n8n")}}},
	{Slug: "ansible", Label: "Ansible", Types: ss(PTDevOps),
		Aff: []Match{aff(vRedHat, Match{Words: ss("ansible")}), aff(vs("ansible"), Match{Prefix: ss("ansible")})},
		CPE: []CPEMatch{{Vendors: vs("redhat", "ansible"), Prefix: ss("ansible")}}},
	{Slug: "vim", Label: "Vim", Types: ss(PTDevOps),
		Aff: []Match{aff(vs("vim"), Match{Exact: ss("vim", "vim/vim")})},
		CPE: []CPEMatch{{Vendors: vs("vim"), Exact: ss("vim")}}},

	// ---- enterprise applications ----
	{Slug: "sap-netweaver", Label: "SAP NetWeaver", Types: ss(PTEnterpriseApp),
		Aff: []Match{aff(vSAP, Match{Words: ss("netweaver")})},
		CPE: []CPEMatch{{Vendors: vs("sap"), Prefix: ss("netweaver")}}},
	{Slug: "sap-businessobjects", Label: "SAP BusinessObjects", Types: ss(PTEnterpriseApp),
		Aff: []Match{aff(vSAP, Match{Words: ss("businessobjects", "business objects")})},
		CPE: []CPEMatch{{Vendors: vs("sap"), Prefix: ss("businessobjects")}}},
	{Slug: "oracle-ebs", Label: "Oracle E-Business Suite", Types: ss(PTEnterpriseApp),
		Aff: []Match{aff(vOracle, Match{Words: ss("e-business suite")})},
		CPE: []CPEMatch{{Vendors: vs("oracle"), Exact: ss("e-business_suite")}}},
	{Slug: "peoplesoft", Label: "PeopleSoft", Types: ss(PTEnterpriseApp),
		Aff: []Match{aff(vOracle, Match{Words: ss("peoplesoft")})},
		CPE: []CPEMatch{{Vendors: vs("oracle"), Prefix: ss("peoplesoft")}}},
	{Slug: "jd-edwards", Label: "JD Edwards", Types: ss(PTEnterpriseApp),
		Aff: []Match{aff(vOracle, Match{Words: ss("jd edwards")})},
		CPE: []CPEMatch{{Vendors: vs("oracle"), Prefix: ss("jd_edwards")}}},
	{Slug: "siebel", Label: "Siebel CRM", Types: ss(PTEnterpriseApp),
		Aff: []Match{aff(vOracle, Match{Words: ss("siebel")})},
		CPE: []CPEMatch{{Vendors: vs("oracle"), Prefix: ss("siebel")}}},
	{Slug: "dynamics-365", Label: "Microsoft Dynamics", Types: ss(PTEnterpriseApp),
		Aff: []Match{aff(vMicrosoft, Match{Words: ss("dynamics")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("dynamics")}}},
	{Slug: "erpnext", Label: "ERPNext / Frappe", Types: ss(PTEnterpriseApp),
		Aff: []Match{aff(vs("frappe"), Match{Exact: ss("erpnext", "frappe", "frappe framework", "hrms", "lms", "helpdesk", "crm")})},
		CPE: []CPEMatch{{Vendors: vs("frappe"), Prefix: ss("")}}},
	{Slug: "maximo", Label: "IBM Maximo", Types: ss(PTEnterpriseApp),
		Aff: []Match{aff(vIBM, Match{Words: ss("maximo")})},
		CPE: []CPEMatch{{Vendors: vs("ibm"), Prefix: ss("maximo")}}},

	// ---- identity / access management ----
	{Slug: "keycloak", Label: "Keycloak", Types: ss(PTIdentity),
		Aff: []Match{aff(vRedHat, Match{Words: ss("keycloak", "single sign-on")}), aff(vs("keycloak", "jboss keycloak"), Match{Words: ss("keycloak")})},
		CPE: []CPEMatch{{Vendors: vs("keycloak"), Exact: ss("keycloak")}, {Vendors: vs("redhat"), Prefix: ss("keycloak", "single_sign-on", "build_of_keycloak")}}},
	{Slug: "cisco-ise", Label: "Cisco Identity Services Engine", Types: ss(PTIdentity),
		Aff: []Match{aff(vCisco, Match{Words: ss("identity services engine")})},
		CPE: []CPEMatch{{Vendors: vs("cisco"), Prefix: ss("identity_services_engine")}}},
	{Slug: "ibm-verify-access", Label: "IBM Security Verify Access", Types: ss(PTIdentity),
		Aff: []Match{aff(vIBM, Match{Words: ss("security verify access", "verify identity access", "security access manager")})},
		CPE: []CPEMatch{{Vendors: vs("ibm"), Prefix: ss("security_verify_access", "security_access_manager", "verify_identity_access")}}},
	{Slug: "wso2-identity-server", Label: "WSO2 Identity Server", Types: ss(PTIdentity),
		Aff: []Match{aff(vs("wso2"), Match{Words: ss("identity server")})},
		CPE: []CPEMatch{{Vendors: vs("wso2"), Prefix: ss("identity_server")}}},
	{Slug: "vault", Label: "HashiCorp Vault", Types: ss(PTIdentity),
		Aff: []Match{aff(vs("hashicorp"), Match{Prefix: ss("vault")})},
		CPE: []CPEMatch{{Vendors: vs("hashicorp"), Prefix: ss("vault")}}},

	// ---- endpoint security ----
	{Slug: "microsoft-defender", Label: "Microsoft Defender", Types: ss(PTSecurity),
		Aff: []Match{aff(vMicrosoft, Match{Words: ss("defender", "malware protection engine", "antimalware platform", "forefront endpoint protection", "security essentials")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("malware_protection_engine", "defender", "windows_defender", "forefront_endpoint_protection", "security_essentials")}}},
	{Slug: "trend-micro-apex-one", Label: "Trend Micro Apex One", Types: ss(PTSecurity),
		Aff: []Match{aff(vTrend, Match{Words: ss("apex one", "officescan")})},
		CPE: []CPEMatch{{Vendors: vs("trendmicro"), Prefix: ss("apex_one", "officescan")}}},
	{Slug: "suricata", Label: "Suricata", Types: ss(PTSecurity),
		Aff: []Match{aff(vs("oisf", "open information security foundation"), Match{Exact: ss("suricata")})},
		CPE: []CPEMatch{{Vendors: vs("oisf"), Exact: ss("suricata")}}},

	// ---- monitoring / logging / IT management ----
	{Slug: "splunk", Label: "Splunk", Types: ss(PTMonitoring),
		Aff: []Match{aff(vSplunk, Match{Prefix: ss("splunk")})},
		CPE: []CPEMatch{{Vendors: vs("splunk"), Prefix: ss("splunk")}}},
	{Slug: "kibana", Label: "Kibana", Types: ss(PTMonitoring),
		Aff: []Match{aff(vElastic, Match{Exact: ss("kibana")})},
		CPE: []CPEMatch{{Vendors: vs("elastic", "elasticsearch"), Exact: ss("kibana")}}},
	{Slug: "grafana", Label: "Grafana", Types: ss(PTMonitoring),
		Aff: []Match{aff(vs("grafana", "grafana labs"), Match{Exact: ss("grafana", "grafana oss", "grafana enterprise")})},
		CPE: []CPEMatch{{Vendors: vs("grafana"), Exact: ss("grafana")}}},
	{Slug: "zabbix", Label: "Zabbix", Types: ss(PTMonitoring),
		Aff: []Match{aff(vs("zabbix"), Match{Prefix: ss("zabbix")})},
		CPE: []CPEMatch{{Vendors: vs("zabbix"), Prefix: ss("zabbix")}}},
	{Slug: "nagios", Label: "Nagios", Types: ss(PTMonitoring),
		Aff: []Match{aff(vs("nagios", "nagios enterprises, llc.", "nagios enterprises", "nagios enterprises, llc"), Match{Words: ss("nagios", "xi", "core")})},
		CPE: []CPEMatch{{Vendors: vs("nagios"), Prefix: ss("nagios")}}},
	{Slug: "solarwinds-platform", Label: "SolarWinds Platform (Orion)", Types: ss(PTMonitoring),
		Aff: []Match{aff(vs("solarwinds"), Match{Words: ss("solarwinds platform", "orion", "network performance monitor")})},
		CPE: []CPEMatch{{Vendors: vs("solarwinds"), Prefix: ss("orion", "solarwinds_platform", "network_performance_monitor")}}},
	{Slug: "cacti", Label: "Cacti", Types: ss(PTMonitoring),
		Aff: []Match{aff(vs("cacti", "the cacti group, inc."), Match{Exact: ss("cacti")})},
		CPE: []CPEMatch{{Vendors: vs("cacti"), Exact: ss("cacti")}}},
	{Slug: "glpi", Label: "GLPI", Types: ss(PTMonitoring),
		Aff: []Match{aff(vs("glpi-project", "glpi", "teclib"), Match{Exact: ss("glpi")})},
		CPE: []CPEMatch{{Vendors: vs("glpi-project"), Exact: ss("glpi")}}},
	{Slug: "ivanti-epm", Label: "Ivanti Endpoint Manager", Types: ss(PTMonitoring),
		Aff: []Match{aff(vIvanti, Match{Words: ss("endpoint manager")})},
		CPE: []CPEMatch{{Vendors: vs("ivanti"), Prefix: ss("endpoint_manager")}}},
	{Slug: "qradar", Label: "IBM QRadar", Types: ss(PTMonitoring),
		Aff: []Match{aff(vIBM, Match{Words: ss("qradar")})},
		CPE: []CPEMatch{{Vendors: vs("ibm"), Prefix: ss("qradar")}}},
	{Slug: "wireshark", Label: "Wireshark", Types: ss(PTMonitoring),
		Aff: []Match{aff(vs("wireshark foundation", "wireshark"), Match{Exact: ss("wireshark")})},
		CPE: []CPEMatch{{Vendors: vs("wireshark"), Exact: ss("wireshark")}}},

	// ---- remote access ----
	{Slug: "freerdp", Label: "FreeRDP", Types: ss(PTRemoteAccess),
		Aff: []Match{aff(vs("freerdp", "check point software technologies ltd."), Match{Exact: ss("freerdp")})},
		CPE: []CPEMatch{{Vendors: vs("freerdp"), Exact: ss("freerdp")}}},
	{Slug: "remote-desktop-client", Label: "Microsoft Remote Desktop client", Types: ss(PTRemoteAccess),
		Aff: []Match{aff(vMicrosoft, Match{Words: ss("remote desktop client", "remote desktop app", "windows app client")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss("remote_desktop")}}},
	{Slug: "screenconnect", Label: "ConnectWise ScreenConnect", Types: ss(PTRemoteAccess),
		Aff: []Match{aff(vs("connectwise"), Match{Words: ss("screenconnect")})},
		CPE: []CPEMatch{{Vendors: vs("connectwise"), Prefix: ss("screenconnect")}}},

	// ---- AI / ML ----
	{Slug: "tensorflow", Label: "TensorFlow", Types: ss(PTAI, PTLibrary),
		Aff: []Match{aff(append(append([]string(nil), vGoogle...), "tensorflow"), Match{Exact: ss("tensorflow")})},
		CPE: []CPEMatch{{Vendors: vs("google", "tensorflow"), Exact: ss("tensorflow")}}},
	{Slug: "vllm", Label: "vLLM", Types: ss(PTAI),
		Aff: []Match{aff(vs("vllm-project", "vllm"), Match{Exact: ss("vllm")})},
		CPE: []CPEMatch{{Vendors: vs("vllm"), Exact: ss("vllm")}}},
	{Slug: "langflow", Label: "Langflow", Types: ss(PTAI),
		Aff: []Match{aff(vs("langflow-ai", "langflow", "ibm"), Match{Words: ss("langflow")})},
		CPE: []CPEMatch{{Vendors: vs("langflow", "langflow-ai"), Exact: ss("langflow")}}},
	{Slug: "open-webui", Label: "Open WebUI", Types: ss(PTAI),
		Aff: []Match{aff(vs("open-webui", "open webui"), Match{Exact: ss("open-webui", "open webui")})},
		CPE: []CPEMatch{{Vendors: vs("openwebui", "open-webui"), Prefix: ss("open_webui", "open-webui")}}},
	{Slug: "mlflow", Label: "MLflow", Types: ss(PTAI),
		Aff: []Match{aff(vs("mlflow", "lfprojects"), Match{Exact: ss("mlflow", "mlflow/mlflow")})},
		CPE: []CPEMatch{{Vendors: vs("lfprojects", "mlflow"), Exact: ss("mlflow")}}},
	{Slug: "anything-llm", Label: "AnythingLLM", Types: ss(PTAI),
		Aff: []Match{aff(vs("mintplex-labs"), Match{Exact: ss("mintplex-labs/anything-llm", "anything-llm", "anythingllm")})},
		CPE: []CPEMatch{{Vendors: vs("mintplexlabs"), Prefix: ss("anything")}}},
	{Slug: "flowise", Label: "Flowise", Types: ss(PTAI),
		Aff: []Match{aff(vs("flowiseai", "flowise"), Match{Prefix: ss("flowise")})},
		CPE: []CPEMatch{{Vendors: vs("flowiseai"), Prefix: ss("flowise")}}},
	{Slug: "openclaw", Label: "OpenClaw", Types: ss(PTAI),
		Aff: []Match{aff(vs("openclaw"), Match{Exact: ss("openclaw")})},
		CPE: []CPEMatch{{Vendors: vs("openclaw"), Exact: ss("openclaw")}}},

	// ---- open-source libraries / frameworks ----
	{Slug: "openssl", Label: "OpenSSL", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("openssl", "openssl software foundation", "the openssl project"), Match{Exact: ss("openssl")})},
		CPE: []CPEMatch{{Vendors: vs("openssl"), Exact: ss("openssl")}}},
	{Slug: "imagemagick", Label: "ImageMagick", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("imagemagick"), Match{Exact: ss("imagemagick", "imagemagick/imagemagick")})},
		CPE: []CPEMatch{{Vendors: vs("imagemagick"), Exact: ss("imagemagick")}}},
	{Slug: "curl", Label: "curl", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("curl", "haxx"), Match{Exact: ss("curl", "libcurl")})},
		CPE: []CPEMatch{{Vendors: vs("haxx", "curl"), Exact: ss("curl", "libcurl")}}},
	{Slug: "ffmpeg", Label: "FFmpeg", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("ffmpeg"), Match{Exact: ss("ffmpeg")})},
		CPE: []CPEMatch{{Vendors: vs("ffmpeg"), Exact: ss("ffmpeg")}}},
	{Slug: "libxml2", Label: "libxml2", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("xmlsoft", "gnome", "libxml2"), Match{Exact: ss("libxml2")})},
		CPE: []CPEMatch{{Vendors: vs("xmlsoft"), Exact: ss("libxml2")}}},
	{Slug: "glibc", Label: "glibc", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("gnu", "the gnu c library", "gnu c library"), Match{Exact: ss("glibc", "the gnu c library", "gnu c library")})},
		CPE: []CPEMatch{{Vendors: vs("gnu"), Exact: ss("glibc")}}},
	{Slug: "spring-framework", Label: "Spring Framework", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("spring", "spring by vmware", "spring by vmware tanzu", "vmware tanzu", "vmware"), Match{Exact: ss("spring framework")})},
		CPE: []CPEMatch{{Vendors: vs("vmware", "pivotal_software", "pivotal"), Exact: ss("spring_framework")}}},
	{Slug: "log4j", Label: "Apache Log4j", Types: ss(PTLibrary),
		Aff: []Match{aff(vApache, Match{Words: ss("log4j")})},
		CPE: []CPEMatch{{Vendors: vs("apache"), Prefix: ss("log4j")}}},
	{Slug: "struts", Label: "Apache Struts", Types: ss(PTLibrary),
		Aff: []Match{aff(vApache, Match{Exact: ss("apache struts", "struts")})},
		CPE: []CPEMatch{{Vendors: vs("apache"), Exact: ss("struts")}}},
	{Slug: "django", Label: "Django", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("djangoproject", "django", "django software foundation"), Match{Exact: ss("django")})},
		CPE: []CPEMatch{{Vendors: vs("djangoproject"), Exact: ss("django")}}},
	{Slug: "rails", Label: "Ruby on Rails", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("rails", "rubyonrails"), Match{Exact: ss("rails", "ruby on rails", "actionpack", "activerecord", "activestorage", "actionview", "activesupport")})},
		CPE: []CPEMatch{{Vendors: vs("rubyonrails"), Prefix: ss("rails", "ruby_on_rails", "actionpack", "active")}}},
	{Slug: "symfony", Label: "Symfony", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("symfony", "sensiolabs"), Match{Prefix: ss("symfony")})},
		CPE: []CPEMatch{{Vendors: vs("sensiolabs", "symfony"), Prefix: ss("symfony")}}},
	{Slug: "nextjs", Label: "Next.js", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("vercel"), Match{Exact: ss("next.js")})},
		CPE: []CPEMatch{{Vendors: vs("vercel"), Exact: ss("next.js")}}},
	{Slug: "netty", Label: "Netty", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("netty"), Match{Exact: ss("netty")})},
		CPE: []CPEMatch{{Vendors: vs("netty"), Exact: ss("netty")}}},
	{Slug: "wolfssl", Label: "wolfSSL", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("wolfssl"), Match{Exact: ss("wolfssl")})},
		CPE: []CPEMatch{{Vendors: vs("wolfssl"), Exact: ss("wolfssl")}}},
	{Slug: "bouncy-castle", Label: "Bouncy Castle", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("legion of the bouncy castle inc.", "bouncycastle", "bouncy castle"), Match{Prefix: ss("bc-", "bouncy castle", "bouncycastle")})},
		CPE: []CPEMatch{{Vendors: vs("bouncycastle"), Prefix: ss("")}}},
	{Slug: "electron", Label: "Electron", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("electron", "electronjs"), Match{Exact: ss("electron")})},
		CPE: []CPEMatch{{Vendors: vs("electronjs"), Exact: ss("electron")}}},
	{Slug: "cpython", Label: "Python (CPython)", Types: ss(PTLibrary),
		Aff: []Match{aff(vs("python software foundation", "python"), Match{Exact: ss("cpython", "python")})},
		CPE: []CPEMatch{{Vendors: vs("python"), Exact: ss("python", "cpython")}}},
	{Slug: "java-se", Label: "Java SE", Types: ss(PTLibrary),
		Aff: []Match{aff(vOracle, Match{Exact: ss("java", "java se", "oracle java se", "java se jdk and jre", "jre", "jdk")})},
		CPE: []CPEMatch{{Vendors: vs("oracle", "sun"), Exact: ss("jre", "jdk", "java_se", "openjdk")}}},
	{Slug: "dotnet", Label: ".NET", Types: ss(PTLibrary),
		Aff: []Match{aff(vMicrosoft, Match{Prefix: ss(".net", "microsoft .net", "asp.net core", "microsoft asp.net core")})},
		CPE: []CPEMatch{{Vendors: vs("microsoft"), Prefix: ss(".net", "asp.net_core")}}},
}

// TypeRules assign a product type without a product tag. Vendor-only rules
// are allowed only where the data showed the vendor's products to be
// overwhelmingly of that type (docs/tags.md lists them with the evidence).
var TypeRules = []TypeRule{
	{ID: "vendor:tenda", Type: PTNetworkDevice, Match: Match{Vendors: vs("tenda", "shenzhen tenda technology co., ltd.", "shenzhen tenda technology co",
		"shenzhen tenda technology co.,ltd.", "shenzhen tenda technology")},
		CPE: []CPEMatch{{Vendors: vs("tenda"), Prefix: ss("")}},
		Why: "every product listed is a router, range extender or access point model (ac15, fh1202, ch22, ...)"},
	{ID: "vendor:totolink", Type: PTNetworkDevice, Match: Match{Vendors: vs("totolink")},
		CPE: []CPEMatch{{Vendors: vs("totolink"), Prefix: ss("")}},
		Why: "router and range extender models (a8000ru, a7100ru, x15, ex1200t, ...)"},
	{ID: "vendor:wavlink", Type: PTNetworkDevice, Match: Match{Vendors: vs("wavlink", "wavlink technology ltd.")},
		CPE: []CPEMatch{{Vendors: vs("wavlink"), Prefix: ss("")}},
		Why: "router, range extender and access point models (ac3000, wl-wn5xx, ...)"},
	{ID: "d-link:router", Type: PTNetworkDevice, Match: Match{Vendors: vDLink,
		Words: ss("dir-", "dir‑", "dsl-", "di-", "dap-", "dwr-", "dwm-", "dvg-", "dgs-", "des-", "dwl-", "dsr-", "dar-", "dhp-", "covr", "routers", "router")},
		CPE: []CPEMatch{{Vendors: vs("dlink", "d-link"), Prefix: ss("dir-", "dsl-", "di-", "dap-", "dwr-", "dwm-", "dvg-", "dgs-", "des-", "dwl-", "dsr-", "dar-", "dhp-", "covr")}},
		Why: "D-Link router, modem, access point and switch model families (DIR-, DSL-, DAP-, DWR-, DGS-, ...)"},
	{ID: "d-link:nas", Type: PTNAS, Match: Match{Vendors: vDLink, Words: ss("dns-", "dnr-", "sharecenter")},
		CPE: []CPEMatch{{Vendors: vs("dlink", "d-link"), Prefix: ss("dns-", "dnr-", "sharecenter")}},
		Why: "D-Link ShareCenter NAS and network video recorder models (DNS-, DNR-)"},
	{ID: "d-link:camera", Type: PTIoTCamera, Match: Match{Vendors: vDLink, Words: ss("dcs-")},
		CPE: []CPEMatch{{Vendors: vs("dlink", "d-link"), Prefix: ss("dcs-")}},
		Why: "D-Link IP camera models (DCS-)"},
	{ID: "vendor:netgear", Type: PTNetworkDevice, Match: Match{Vendors: vs("netgear", "netgear japan g.k.", "netgear, inc."), Not: ss("readynas")},
		CPE: []CPEMatch{{Vendors: vs("netgear"), Prefix: ss(""), Not: ss("readynas")}},
		Why: "router, Orbi mesh, range extender, cable/DSL gateway and switch models (RAX, R, RBR/RBS, EX, DGN, ...)"},
	{ID: "vendor:linksys", Type: PTNetworkDevice, Match: Match{Vendors: vs("linksys", "linksys llc")},
		CPE: []CPEMatch{{Vendors: vs("linksys"), Prefix: ss("")}},
		Why: "router, range extender and mesh models (E, WRT, RE, EA, MR, MX)"},
	{ID: "tp-link:network", Type: PTNetworkDevice, Match: Match{Vendors: vTPLink,
		Words: ss("archer", "deco", "omada", "tl-wr", "tl-mr", "tl-wa", "tl-wpa", "tl-sg", "tl-er", "jetstream", "er605", "er7206", "eap", "range extender", "router", "access point")},
		CPE: []CPEMatch{{Vendors: vs("tp-link"), Prefix: ss("archer", "deco", "omada", "tl-wr", "tl-wdr", "tl-wn", "tl-mr", "tl-wa", "tl-wpa", "tl-sg", "tl-er", "tl-r", "eap", "er605", "er7206")}},
		Why: "Archer/Deco/Omada routers, access points, gateways and switches"},
	{ID: "tp-link:iot", Type: PTIoTCamera, Match: Match{Vendors: vTPLink, Words: ss("tapo", "vigi", "kasa")},
		CPE: []CPEMatch{{Vendors: vs("tp-link"), Prefix: ss("tapo", "kasa", "nc2", "vigi", "tl-ipc", "tl-sc")}},
		Why: "Tapo and VIGI cameras, Tapo/Kasa smart-home devices"},
	{ID: "zyxel:firewall", Type: PTFirewallVPN, Match: Match{Vendors: vs("zyxel", "zyxel networks", "zyxel communications"),
		Words: ss("usg", "usg20", "usg flex", "atp", "zywall", "vpn series", "vpn firewall", "zywall vpn")},
		CPE: []CPEMatch{{Vendors: vs("zyxel"), Prefix: ss("usg", "atp", "zywall", "vpn")}},
		Why: "USG, USG FLEX, ATP, VPN and ZyWALL firewall series"},
	{ID: "vendor:qualcomm", Type: PTChipset, Match: Match{Vendors: vQualcomm},
		CPE: []CPEMatch{{Vendors: vs("qualcomm"), Prefix: ss("")}},
		Why: "Snapdragon and other chipsets, their firmware and closed-source components (\"all qualcomm products\", \"android for msm\")"},
	{ID: "vendor:unisoc", Type: PTChipset, Match: Match{Vendors: vs("unisoc (shanghai) technologies co., ltd.", "unisoc")},
		CPE: []CPEMatch{{Vendors: vs("unisoc"), Prefix: ss("")}},
		Why: "chipset model lists (sc9863a/t610/...) and their modem firmware"},
	{ID: "vendor:mediatek", Type: PTChipset, Match: Match{Vendors: vs("mediatek, inc.", "mediatek")},
		CPE: []CPEMatch{{Vendors: vs("mediatek"), Prefix: ss("")}},
		Why: "\"mediatek chipset\" or chipset model lists (mt6765, mt7622, ...)"},
	{ID: "vendor:hikvision", Type: PTIoTCamera, Match: Match{Vendors: vs("hikvision", "hangzhou hikvision system technology")},
		CPE: []CPEMatch{{Vendors: vs("hikvision"), Prefix: ss("")}},
		Why: "IP cameras, NVRs, intercoms and their video-management platforms (ds-2cd, hikcentral, ...)"},
	{ID: "vendor:dahua", Type: PTIoTCamera, Match: Match{Vendors: vs("dahua", "dahua technologies", "dahua technology", "zhejiang dahua technology co., ltd.")},
		CPE: []CPEMatch{{Vendors: vs("dahuasecurity", "dahua"), Prefix: ss("")}},
		Why: "IP cameras, NVRs and their management platforms"},
	{ID: "vendor:rockwell", Type: PTICS, Match: Match{Vendors: vs("rockwell automation", "rockwell", "rockwell auotmation", "rockwellautomation")},
		CPE: []CPEMatch{{Vendors: vs("rockwellautomation"), Prefix: ss("")}},
		Why: "PLCs, I/O modules, drives and FactoryTalk/Arena industrial software"},
	{ID: "vendor:iconics", Type: PTICS, Match: Match{Vendors: vs("mitsubishi electric iconics digital solutions", "iconics")},
		CPE: []CPEMatch{{Vendors: vs("iconics"), Prefix: ss("")}},
		Why: "ICONICS SCADA (GENESIS64, MC Works64, Hyper Historian)"},
	// Mitsubishi Electric also lists room air conditioners and appliances: only its automation lines are ICS.
	{ID: "mitsubishi:automation", Type: PTICS, Match: Match{Vendors: vs("mitsubishi electric corporation", "mitsubishi electric"),
		Words: ss("melsec", "melfa", "got1000", "got2000", "got3000", "cc-link", "gx works2", "gx works3", "gx developer", "mc works64", "genesis64",
			"iconics", "hyper historian", "cnc", "ac servo", "motion module", "melipc", "melsoft", "fa engineering", "factory automation")},
		Why: "MELSEC PLCs, MELFA robots, GOT HMIs, GX Works, CNCs, servo and motion modules"},
	{ID: "mitsubishi:appliance", Type: PTIoTCamera, Match: Match{Vendors: vs("mitsubishi electric corporation", "mitsubishi electric"),
		Words: ss("room air conditioner", "air conditioning", "air conditioners", "refrigerators", "heat pump", "hems adapter", "wi-fi interface",
			"wireless lan adapter", "ventilating fan", "bathroom thermo")},
		Why: "network-connected room air conditioners, refrigerators and their Wi-Fi/HEMS adapters"},
	{ID: "vendor:schneider-electric", Type: PTICS, Match: Match{Vendors: vSchneider},
		CPE: []CPEMatch{{Vendors: vs("schneider-electric", "schneider_electric"), Prefix: ss("")}},
		Why: "Modicon PLCs, EcoStruxure, SCADA and power-management products"},
	{ID: "vendor:abb", Type: PTICS, Match: Match{Vendors: vs("abb")},
		CPE: []CPEMatch{{Vendors: vs("abb"), Prefix: ss("")}},
		Why: "building and process automation (Aspect, Symphony Plus, control builders, HMIs)"},
	{ID: "vendor:delta-electronics", Type: PTICS, Match: Match{Vendors: vs("delta electronics", "delta electronics, inc.")},
		CPE: []CPEMatch{{Vendors: vs("deltaww", "delta_electronics"), Prefix: ss("")}},
		Why: "DIAEnergie, HMI and PLC software (DOPSoft, ISPSoft, CNCSoft), PLCs"},
	{ID: "vendor:phoenix-contact", Type: PTICS, Match: Match{Vendors: vs("phoenix contact")},
		CPE: []CPEMatch{{Vendors: vs("phoenixcontact", "phoenix_contact"), Prefix: ss("")}},
		Why: "CHARX charge controllers, industrial switches, PLCnext controllers"},
	{ID: "vendor:codesys", Type: PTICS, Match: Match{Vendors: vs("codesys", "codesys gmbh")},
		CPE: []CPEMatch{{Vendors: vs("codesys"), Prefix: ss("")}},
		Why: "CODESYS PLC runtimes and engineering tools"},
	{ID: "vendor:lexmark", Type: PTPrinter, Match: Match{Vendors: vs("lexmark", "lexmark international")},
		CPE: []CPEMatch{{Vendors: vs("lexmark"), Prefix: ss("")}},
		Why: "printer and MFP firmware model lists, print drivers and print management"},
	{ID: "vendor:qnap", Type: PTNAS, Match: Match{Vendors: vQNAP},
		CPE: []CPEMatch{{Vendors: vs("qnap"), Prefix: ss("")}},
		Why: "QTS/QuTS hero and the NAS apps that run on them (File Station, Qsync, Photo Station, ...)"},
	{ID: "vendor:jenkins", Type: PTDevOps, Match: Match{Vendors: vs("jenkins project")},
		CPE: []CPEMatch{{Vendors: vs("jenkins"), Prefix: ss("")}},
		Why: "Jenkins and Jenkins plugins"},
	{ID: "vendor:jetbrains", Type: PTDevOps, Match: Match{Vendors: vs("jetbrains")},
		CPE: []CPEMatch{{Vendors: vs("jetbrains"), Prefix: ss("")}},
		Why: "IDEs, TeamCity, YouTrack, Hub, Ktor"},
	{ID: "vendor:sap", Type: PTEnterpriseApp, Match: Match{Vendors: vSAP},
		CPE: []CPEMatch{{Vendors: vs("sap"), Prefix: ss("")}},
		Why: "NetWeaver, S/4HANA, BusinessObjects, Business One and other enterprise applications"},
	{ID: "vendor:trend-micro", Type: PTSecurity, Match: Match{Vendors: vTrend},
		CPE: []CPEMatch{{Vendors: vs("trendmicro"), Prefix: ss("")}},
		Why: "Apex One, OfficeScan, Worry-Free, Deep Security and other security products"},
	{ID: "vendor:eset", Type: PTSecurity, Match: Match{Vendors: vs("eset, spol. s r.o.", "eset", "eset spol. s.r.o.", "eset, spol. s.r.o", "eset s.r.o")},
		CPE: []CPEMatch{{Vendors: vs("eset"), Prefix: ss("")}},
		Why: "antivirus, endpoint, mail and server security products"},
	{ID: "gen-digital:antivirus", Type: PTSecurity, Match: Match{Vendors: vs("gen digital", "avast", "avg", "avg/avast", "norton"),
		Words: ss("antivirus", "anti-virus", "anitvirus", "internet security", "total security", "premium security", "norton 360", "avast one", "endpoint")},
		Why: "Norton, Avast, AVG and Avira antivirus suites (their CCleaner, TuneUp and password managers are left out)"},
	{ID: "vendor:mcafee-trellix", Type: PTSecurity, Match: Match{Vendors: vs("mcafee", "mcafee,llc", "mcafee, llc", "mcafee llc", "trellix")},
		CPE: []CPEMatch{{Vendors: vs("mcafee", "trellix"), Prefix: ss("")}},
		Why: "endpoint security, ePO, DLP, network security and gateway products"},
	{ID: "vendor:bitdefender", Type: PTSecurity, Match: Match{Vendors: vs("bitdefender")},
		CPE: []CPEMatch{{Vendors: vs("bitdefender"), Prefix: ss("")}},
		Why: "antivirus, GravityZone and endpoint security tools"},
	{ID: "vendor:sophos", Type: PTSecurity, Match: Match{Vendors: vs("sophos")},
		CPE: []CPEMatch{{Vendors: vs("sophos"), Prefix: ss("")}},
		Why: "endpoint (Intercept X, HitmanPro) and network security products"},
	// Any vendor: these words name the product type whatever the vendor.
	{ID: "words:wordpress-plugin", Type: PTCMS, Match: Match{Words: ss("wordpress", "woocommerce", "elementor", "for joomla", "drupal")},
		Why: "WordPress/WooCommerce/Elementor plugins and themes, Joomla extensions and Drupal modules name the CMS they extend"},
	{ID: "words:printer", Type: PTPrinter, Match: Match{Words: ss("printer", "printers", "laserjet", "officejet", "deskjet", "designjet", "pagewide",
		"multifunction printer", "multifunction printers", "multi-function peripheral", "mfps", "e-studio", "imagerunner", "bizhub")},
		// (not bare "mfp": Siemens names SIMATIC S7-1500 "MFP" CPUs)
		Why: "printer and MFP product names"},
	{ID: "words:ip-camera", Type: PTIoTCamera, Match: Match{Words: ss("ip camera", "network camera", "ip cameras", "network video recorder", "dvr", "nvr")},
		Why: "camera and video-recorder product names"},
	{ID: "words:router", Type: PTNetworkDevice, Match: Match{Words: ss("wireless router", "wifi router", "wi-fi router", "vpn router", "range extender", "wireless access point")},
		Why: "router, extender and access point product names (not bare \"router\": vue-router, react-router and HTTP routers are libraries)"},
}

// ---------------------------------------------------------------- matching

// Normalize lower-cases s, trims it and collapses whitespace runs to one
// space (the form every affected rule is written in).
func Normalize(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// boundaryAt reports whether s has a word boundary just before byte i
// (between s[:i] and s[i:]).
func boundaryBefore(s string, i int) bool {
	if i <= 0 {
		return true
	}
	r := lastRune(s[:i])
	return !isWordRune(r)
}

func boundaryAfter(s string, j int) bool {
	if j >= len(s) {
		return true
	}
	r := firstRune(s[j:])
	return !isWordRune(r)
}

func firstRune(s string) rune {
	for _, r := range s {
		return r
	}
	return 0
}

func lastRune(s string) rune {
	var last rune
	for _, r := range s {
		last = r
	}
	return last
}

// containsWord reports whether phrase occurs in s delimited by word
// boundaries on both sides (the phrase's own first and last characters
// need not be letters: "for joomla", "big-ip", ".net").
func containsWord(s, phrase string) bool {
	if phrase == "" {
		return false
	}
	for off := 0; off <= len(s)-len(phrase); {
		i := strings.Index(s[off:], phrase)
		if i < 0 {
			return false
		}
		i += off
		j := i + len(phrase)
		okL := !isWordRune(firstRune(phrase)) || boundaryBefore(s, i)
		okR := !isWordRune(lastRune(phrase)) || boundaryAfter(s, j)
		if okL && okR {
			return true
		}
		off = i + 1
	}
	return false
}

func hasWordPrefix(s, p string) bool {
	return strings.HasPrefix(s, p) && (!isWordRune(lastRune(p)) || boundaryAfter(s, len(p)))
}

// matchProduct applies the product part of m (vendor already checked).
func (m *Match) matchProduct(p string) bool {
	any := len(m.Exact)+len(m.Prefix)+len(m.Words) == 0
	ok := any
	for _, x := range m.Exact {
		if p == x {
			ok = true
			break
		}
	}
	if !ok {
		for _, x := range m.Prefix {
			if hasWordPrefix(p, x) {
				ok = true
				break
			}
		}
	}
	if !ok {
		for _, x := range m.Words {
			if containsWord(p, x) {
				ok = true
				break
			}
		}
	}
	if !ok {
		return false
	}
	for _, x := range m.Not {
		if containsWord(p, x) {
			return false
		}
	}
	return true
}

func (m *CPEMatch) matchProduct(p string) bool {
	ok := false
	for _, x := range m.Exact {
		if p == x {
			ok = true
			break
		}
	}
	if !ok {
		for _, x := range m.Prefix {
			if strings.HasPrefix(p, x) {
				ok = true
				break
			}
		}
	}
	if !ok {
		return false
	}
	for _, x := range m.Not {
		if strings.HasPrefix(p, x) {
			return false
		}
	}
	return true
}

// owner of a rule: a product (index into Products) or a type rule (index
// into TypeRules).
type ruleRef struct {
	product int // -1 for a type rule
	typ     int
	m       *Match
}

type cpeRef struct {
	product int // -1 for a type rule
	typ     int
	m       *CPEMatch
}

var (
	affByVendor = map[string][]ruleRef{}
	affAny      []ruleRef
	cpeByVendor = map[string][]cpeRef{}
	productIdx  = map[string]int{}
)

func indexProducts() {
	for i := range Products {
		p := &Products[i]
		productIdx[p.Slug] = i
		for j := range p.Aff {
			m := &p.Aff[j]
			r := ruleRef{product: i, typ: -1, m: m}
			if m.Vendors == nil {
				affAny = append(affAny, r)
			}
			for _, v := range m.Vendors {
				affByVendor[v] = append(affByVendor[v], r)
			}
		}
		for j := range p.CPE {
			m := &p.CPE[j]
			for _, v := range m.Vendors {
				cpeByVendor[v] = append(cpeByVendor[v], cpeRef{product: i, typ: -1, m: m})
			}
		}
	}
	for i := range TypeRules {
		m := &TypeRules[i].Match
		r := ruleRef{product: -1, typ: i, m: m}
		if m.Vendors == nil {
			affAny = append(affAny, r)
		}
		for _, v := range m.Vendors {
			affByVendor[v] = append(affByVendor[v], r)
		}
		for j := range TypeRules[i].CPE {
			c := &TypeRules[i].CPE[j]
			for _, v := range c.Vendors {
				cpeByVendor[v] = append(cpeByVendor[v], cpeRef{product: -1, typ: i, m: c})
			}
		}
	}
}

// AffectedRow is one row of the affected table, as stored.
type AffectedRow struct {
	Vendor  string
	Product string
}

// CPE is the part, vendor and product of a CPE 2.3 name (unescaped, lower
// case).
type CPE struct {
	Part    string
	Vendor  string
	Product string
}

// ParseCPE splits a CPE 2.3 formatted string ("cpe:2.3:a:vendor:product:
// version:..."), honouring backslash escapes ("joomla\!" is "joomla!",
// "\:" is a colon inside a component). ok is false for anything that is not
// a CPE 2.3 name with a part, vendor and product.
func ParseCPE(s string) (CPE, bool) {
	var parts []string
	var b strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			parts = append(parts, b.String())
			b.Reset()
			if len(parts) == 5 { // cpe, 2.3, part, vendor, product: the rest is versions
				goto done
			}
		default:
			b.WriteRune(r)
		}
	}
	parts = append(parts, b.String())
done:
	if len(parts) < 5 || parts[0] != "cpe" || parts[1] != "2.3" {
		return CPE{}, false
	}
	c := CPE{Part: strings.ToLower(parts[2]), Vendor: strings.ToLower(parts[3]), Product: strings.ToLower(parts[4])}
	if (c.Part != "a" && c.Part != "o" && c.Part != "h") || c.Vendor == "" || c.Product == "" || c.Vendor == "*" || c.Product == "*" {
		return CPE{}, false
	}
	return c, true
}

// productHit collects the evidence of one product or one type rule.
type productHit struct {
	aff map[AffectedRow]bool
	cpe map[CPE]bool
}

func (h *productHit) addAff(r AffectedRow) {
	if h.aff == nil {
		h.aff = map[AffectedRow]bool{}
	}
	h.aff[r] = true
}

func (h *productHit) addCPE(c CPE) {
	if h.cpe == nil {
		h.cpe = map[CPE]bool{}
	}
	h.cpe[c] = true
}

// matchProducts matches affected rows and CPE names against the registry:
// hits per product slug and per type rule id.
func matchProducts(rows []AffectedRow, cpes []CPE) (prods map[string]*productHit, rules map[string]*productHit) {
	prods = map[string]*productHit{}
	rules = map[string]*productHit{}
	hit := func(m map[string]*productHit, k string) *productHit {
		h := m[k]
		if h == nil {
			h = &productHit{}
			m[k] = h
		}
		return h
	}
	for _, r := range rows {
		v, p := Normalize(r.Vendor), Normalize(r.Product)
		try := func(refs []ruleRef) {
			for _, ref := range refs {
				if !ref.m.matchProduct(p) {
					continue
				}
				if ref.product >= 0 {
					hit(prods, Products[ref.product].Slug).addAff(r)
				} else {
					hit(rules, TypeRules[ref.typ].ID).addAff(r)
				}
			}
		}
		try(affByVendor[v])
		try(affAny)
	}
	for _, c := range cpes {
		for _, ref := range cpeByVendor[c.Vendor] {
			if !ref.m.matchProduct(c.Product) {
				continue
			}
			if ref.product >= 0 {
				hit(prods, Products[ref.product].Slug).addCPE(c)
			} else {
				hit(rules, TypeRules[ref.typ].ID).addCPE(c)
			}
		}
	}
	return prods, rules
}

// BasisAffected is one affected row (vendor and product as stored).
type BasisAffected struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

// BasisCPE is the part, vendor and product of a CPE name NVD's analysts
// gave (vulnerable = true).
type BasisCPE struct {
	Part    string `json:"part"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

func (h *productHit) merge(o *productHit) {
	for r := range o.aff {
		h.addAff(r)
	}
	for c := range o.cpe {
		h.addCPE(c)
	}
}

// fill writes the evidence of h into b: sorted, deduplicated, at most
// maxBasisItems of each kind, with the total counts.
func (h *productHit) fill(b *Basis) {
	if len(h.aff) > 0 {
		var xs []BasisAffected
		for r := range h.aff {
			xs = append(xs, BasisAffected{Vendor: r.Vendor, Product: r.Product})
		}
		sort.Slice(xs, func(i, j int) bool {
			if xs[i].Vendor != xs[j].Vendor {
				return xs[i].Vendor < xs[j].Vendor
			}
			return xs[i].Product < xs[j].Product
		})
		b.AffectedCount = len(xs)
		if len(xs) > maxBasisItems {
			xs = xs[:maxBasisItems]
		}
		b.Affected = xs
	}
	if len(h.cpe) > 0 {
		var xs []BasisCPE
		for c := range h.cpe {
			xs = append(xs, BasisCPE{Part: c.Part, Vendor: c.Vendor, Product: c.Product})
		}
		sort.Slice(xs, func(i, j int) bool {
			if xs[i].Vendor != xs[j].Vendor {
				return xs[i].Vendor < xs[j].Vendor
			}
			if xs[i].Product != xs[j].Product {
				return xs[i].Product < xs[j].Product
			}
			return xs[i].Part < xs[j].Part
		})
		b.CPECount = len(xs)
		if len(xs) > maxBasisItems {
			xs = xs[:maxBasisItems]
		}
		b.CPE = xs
	}
}

// deriveProducts adds the product and product-type tags of one CVE to got.
func deriveProducts(rows []AffectedRow, cpes []CPE, got map[string]Basis) {
	if len(rows) == 0 && len(cpes) == 0 {
		return
	}
	prods, rules := matchProducts(rows, cpes)
	type typeAcc struct {
		hit   productHit
		prods []string
		rules []string
	}
	types := map[string]*typeAcc{}
	acc := func(t string) *typeAcc {
		a := types[t]
		if a == nil {
			a = &typeAcc{}
			types[t] = a
		}
		return a
	}
	for slug, h := range prods {
		b := Basis{}
		h.fill(&b)
		got[slug] = b
		for _, t := range Products[productIdx[slug]].Types {
			a := acc(t)
			a.hit.merge(h)
			a.prods = append(a.prods, slug)
		}
	}
	for id, h := range rules {
		t := typeRuleType[id]
		a := acc(t)
		a.hit.merge(h)
		a.rules = append(a.rules, id)
	}
	for t, a := range types {
		b := Basis{}
		a.hit.fill(&b)
		sort.Strings(a.prods)
		sort.Strings(a.rules)
		b.Products, b.TypeRules = a.prods, a.rules
		got[t] = b
	}
}

var typeRuleType = map[string]string{}

func init() {
	indexProducts()
	for _, r := range TypeRules {
		if _, dup := typeRuleType[r.ID]; dup {
			panic("tags: duplicate type rule " + r.ID)
		}
		typeRuleType[r.ID] = r.Type
	}
}

package tags

// ShortNames maps a product tag to the short name people actually use for
// it on the web, where the label is long or lists several products
// ("Adobe Commerce / Magento" → "Magento"). The share card draws it as the
// watermark of a product without a brand mark (docs/tagicons.md "On the
// share card"), in one big line, so keep each to two words and 18
// characters at most (TestShortNames). A tag missing here uses its label.
var ShortNames = map[string]string{
	"remote-desktop-client": "Remote Desktop",
	"websphere":             "WebSphere",
	"vmware-workstation":    "VMware Workstation",
	"solarwinds-platform":   "SolarWinds Orion",
	"ibm-verify-access":     "Verify Access",
	"foxit-pdf":             "Foxit PDF",
	"screenconnect":         "ScreenConnect",
	"magento":               "Magento",
	"aem":                   "AEM",
	"netscaler":             "NetScaler",
	"oracle-ebs":            "Oracle EBS",
	"ivanti-epm":            "Ivanti EPM",
	"acrobat":               "Acrobat",
	"ivanti-connect-secure": "Connect Secure",
	"vcenter":               "vCenter",
	"qnap-qts":              "QNAP QTS",
	"liferay":               "Liferay",
	"wso2-identity-server":  "WSO2",
	"fireware":              "Fireware",
	"check-point-quantum":   "Check Point",
	"hcl-domino":            "Domino",
	"vscode":                "VS Code",
	"dynamics-365":          "Dynamics 365",
	"microsoft-defender":    "Defender",
	"scalance":              "SCALANCE",
	"coldfusion":            "ColdFusion",
	"office":                "Office",
	"simatic":               "SIMATIC",
	"weblogic":              "WebLogic",
	"exchange":              "Exchange",
	"teams":                 "Teams",
	"edge":                  "Edge",
	"zephyr":                "Zephyr",
	"esxi":                  "ESXi",
	"powervm":               "PowerVM",
	"siebel":                "Siebel",
	"maximo":                "Maximo",
	"qradar":                "QRadar",
	"junos":                 "Junos",
	// tags that have a brand mark today; here so the name is ready if the
	// mark ever goes
	"ios-ipados":               "iOS",
	"snapdragon":               "Snapdragon",
	"nvidia-gpu-driver":        "NVIDIA GPU",
	"cisco-ios-xe":             "IOS XE",
	"cisco-ios-xr":             "IOS XR",
	"cisco-rv-routers":         "Cisco RV",
	"cisco-ftd":                "Cisco FTD",
	"cisco-fmc":                "Cisco FMC",
	"anyconnect":               "AnyConnect",
	"powerscale-onefs":         "OneFS",
	"docker":                   "Docker",
	"apache-http-server":       "Apache httpd",
	"apache-traffic-server":    "Traffic Server",
	"cisco-ucm":                "Cisco CUCM",
	"github-enterprise-server": "GitHub Enterprise",
	"sap-businessobjects":      "BusinessObjects",
	"erpnext":                  "ERPNext",
	"cisco-ise":                "Cisco ISE",
	"trend-micro-apex-one":     "Apex One",
	"rails":                    "Rails",
}

// ShortName is the short name of a product tag: its ShortNames entry, else
// its label; "" for a slug that isn't in the vocabulary.
func ShortName(slug string) string {
	if s := ShortNames[slug]; s != "" {
		return s
	}
	t, _ := Lookup(slug)
	return t.Label
}

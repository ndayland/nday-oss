package tags

// Icons maps a tag slug to the Simple Icons (https://simpleicons.org,
// CC0-1.0) slug of the mark drawn in front of its label. Only tags of the
// product and ecosystem dimensions have icons, and only where the set has a
// mark that is the brand of the tag: the product's (or ecosystem's) own mark
// first, else the mark of the vendor that makes the product. Several tags
// may share a vendor mark. No icon is better than a guess: no generic
// symbol, no merely similar mark, no other company's logo, no mark of an
// unrelated product of the same parent company. A tag missing here simply
// has no icon (docs/tagicons.md lists them and why).
//
// Each target is a symbol of internal/webui/static/tagicons.svg, which
// tools/tagicons generates from this map and the Simple Icons package
// (tests check both directions).
var Icons = map[string]string{
	// ---- products: their own mark
	"linux-kernel":     "linux",
	"ios-ipados":       "ios",
	"android":          "android",
	"harmonyos":        "harmonyos",
	"freebsd":          "freebsd",
	"chrome":           "googlechrome",
	"firefox":          "firefoxbrowser",
	"safari":           "safari",
	"snapdragon":       "snapdragon",
	"virtualbox":       "virtualbox",
	"qemu":             "qemu",
	"kubernetes":       "kubernetes",
	"docker":           "docker",
	"rancher":          "rancher",
	"openshift":        "redhatopenshift",
	"mysql":            "mysql",
	"mariadb":          "mariadb",
	"postgresql":       "postgresql",
	"mongodb":          "mongodb",
	"redis":            "redis",
	"sqlite":           "sqlite",
	"elasticsearch":    "elasticsearch",
	"tomcat":           "apachetomcat",
	"nginx":            "nginx",
	"envoy":            "envoyproxy",
	"traefik":          "traefikproxy",
	"nodejs":           "nodedotjs",
	"php":              "php",
	"wordpress":        "wordpress",
	"drupal":           "drupal",
	"joomla":           "joomla",
	"typo3":            "typo3",
	"prestashop":       "prestashop",
	"craft-cms":        "craftcms",
	"grav":             "grav",
	"ghost":            "ghost",
	"thunderbird":      "thunderbird",
	"roundcube":        "roundcube",
	"confluence":       "confluence",
	"mattermost":       "mattermost",
	"nextcloud":        "nextcloud",
	"discourse":        "discourse",
	"libreoffice":      "libreoffice",
	"gitlab":           "gitlab",
	"jenkins":          "jenkins",
	"teamcity":         "teamcity",
	"gitea":            "gitea",
	"jira":             "jira",
	"airflow":          "apacheairflow",
	"n8n":              "n8n",
	"ansible":          "ansible",
	"vim":              "vim",
	"erpnext":          "erpnext",
	"vault":            "vault",
	"kibana":           "kibana",
	"grafana":          "grafana",
	"wireshark":        "wireshark",
	"tensorflow":       "tensorflow",
	"vllm":             "vllm",
	"langflow":         "langflow",
	"mlflow":           "mlflow",
	"curl":             "curl",
	"ffmpeg":           "ffmpeg",
	"spring-framework": "spring",
	"django":           "django",
	"rails":            "rubyonrails",
	"symfony":          "symfony",
	"nextjs":           "nextdotjs",
	"electron":         "electron",
	"cpython":          "python",
	"dotnet":           "dotnet",

	// ---- products: the vendor's mark
	"watchos":                  "apple",
	"tvos":                     "apple",
	"visionos":                 "apple",
	"emui":                     "huawei",
	"nvidia-gpu-driver":        "nvidia",
	"cisco-ios-xe":             "cisco",
	"cisco-ios":                "cisco",
	"cisco-ios-xr":             "cisco",
	"cisco-nx-os":              "cisco",
	"cisco-rv-routers":         "cisco",
	"cisco-asa":                "cisco",
	"cisco-ftd":                "cisco",
	"cisco-fmc":                "cisco",
	"anyconnect":               "cisco",
	"cisco-ucm":                "cisco",
	"cisco-ise":                "cisco",
	"routeros":                 "mikrotik",
	"big-ip":                   "f5",
	"fortios":                  "fortinet",
	"fortiproxy":               "fortinet",
	"fortiweb":                 "fortinet",
	"fortimanager":             "fortinet",
	"fortianalyzer":            "fortinet",
	"fortimail":                "fortinet",
	"pan-os":                   "paloaltonetworks",
	"globalprotect":            "paloaltonetworks",
	"powerscale-onefs":         "dell",
	"modicon":                  "schneiderelectric",
	"jboss-eap":                "redhat",
	"apache-http-server":       "apache",
	"apache-traffic-server":    "apache",
	"log4j":                    "apache",
	"struts":                   "apache",
	"github-enterprise-server": "github",
	"artifactory":              "jfrog",
	"sap-netweaver":            "sap",
	"sap-businessobjects":      "sap",
	"trend-micro-apex-one":     "trendmicro",

	// ---- ecosystems
	"npm":            "npm",
	"pypi":           "pypi",
	"maven":          "apachemaven",
	"go":             "go",
	"nuget":          "nuget",
	"rubygems":       "rubygems",
	"crates-io":      "rust",
	"hex":            "elixir",
	"pub":            "dart",
	"swift":          "swift",
	"github-actions": "githubactions",
}

// IconFor returns the icon (Simple Icons slug) of a tag, "" when it has none.
// Tags outside the product and ecosystem dimensions never have one.
func IconFor(slug string) string {
	t, ok := Lookup(slug)
	if !ok || (t.Dim != DimProduct && t.Dim != DimEcosystem) {
		return ""
	}
	return Icons[slug]
}

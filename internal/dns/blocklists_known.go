package dns

// KnownBlocklist describes a well-known, curated DNS blocklist that users can
// reference by short name instead of a full URL in configuration.
type KnownBlocklist struct {
	Name        string // short identifier, e.g. "hagezi-pro"
	Description string // human-readable description
	URL         string // AdblockPlus-format download URL
	Source      string // "oisd" or "hagezi"
}

// KnownBlocklists is the built-in registry of popular DNS blocklists.
// All URLs point to AdblockPlus-compatible format lists.
var KnownBlocklists = []KnownBlocklist{
	// ──────────────────────────────────────────────────────────────────────
	// OISD — curated, aggregated domain blocklists  (https://oisd.nl)
	// ──────────────────────────────────────────────────────────────────────
	{
		Name:        "oisd-big",
		Description: "OISD Big — comprehensive ad/tracking/malware blocklist",
		URL:         "https://raw.githubusercontent.com/cbuijs/oisd/refs/heads/master/big/domains.adblock",
		Source:      "oisd",
	},
	{
		Name:        "oisd-small",
		Description: "OISD Small — lighter version (top 1M domains only)",
		URL:         "https://raw.githubusercontent.com/cbuijs/oisd/refs/heads/master/small/domains.adblock",
		Source:      "oisd",
	},
	{
		Name:        "oisd-nsfw",
		Description: "OISD NSFW — blocks adult/porn/shock sites",
		URL:         "https://raw.githubusercontent.com/cbuijs/oisd/refs/heads/master/nsfw/domains.adblock",
		Source:      "oisd",
	},
	//{
	//	Name:        "oisd-nsfw-small",
	//	Description: "OISD NSFW Small — lighter NSFW list (top 1M domains only)",
	//	URL:         "https://raw.githubusercontent.com/cbuijs/oisd/refs/heads/master/big/domains.adblock",
	//	Source:      "oisd",
	// },

	// ──────────────────────────────────────────────────────────────────────
	// Hagezi Multi — all-in-one blocklists at various blocking levels
	// https://github.com/hagezi/dns-blocklists
	// ──────────────────────────────────────────────────────────────────────
	{
		Name:        "hagezi-light",
		Description: "Hagezi Light — basic protection, ads & tracking (~118k domains)",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-normal",
		Description: "Hagezi Normal — all-round protection (~306k domains)",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-pro",
		Description: "Hagezi Pro — extended protection, recommended (~400k domains)",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-pro-mini",
		Description: "Hagezi Pro Mini — size-optimised Pro (top 1/10M domains, ~74k)",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.mini.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-proplus",
		Description: "Hagezi Pro++ — maximum protection, more aggressive (~462k domains)",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-proplus-mini",
		Description: "Hagezi Pro++ Mini — size-optimised Pro++ (~100k domains)",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.mini.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-ultimate",
		Description: "Hagezi Ultimate — aggressive protection (~525k domains)",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-ultimate-mini",
		Description: "Hagezi Ultimate Mini — size-optimised Ultimate (~111k domains)",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.mini.txt",
		Source:      "hagezi",
	},

	// ──────────────────────────────────────────────────────────────────────
	// Hagezi Specialty — targeted blocklists for specific threats/categories
	// ──────────────────────────────────────────────────────────────────────
	{
		Name:        "hagezi-tif",
		Description: "Hagezi Threat Intelligence Feeds — malware, phishing, C&C (full)",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-tif-medium",
		Description: "Hagezi Threat Intelligence Feeds — medium version",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-tif-mini",
		Description: "Hagezi Threat Intelligence Feeds — mini version",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-fake",
		Description: "Hagezi Fake — blocks fake stores, scams, rip-offs & cost traps",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-popupads",
		Description: "Hagezi Pop-Up Ads — blocks annoying and malicious pop-up ads",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/popupads.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-doh-vpn-proxy-bypass",
		Description: "Hagezi DoH/VPN/TOR/Proxy Bypass — prevents DNS bypass methods",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-doh",
		Description: "Hagezi Encrypted DNS Servers — blocks DoH/DoT servers only",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-dyndns",
		Description: "Hagezi Dynamic DNS — blocks malicious use of dynamic DNS services",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-hoster",
		Description: "Hagezi Badware Hoster — blocks malicious hosting services",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-nosafesearch",
		Description: "Hagezi No Safesearch — blocks search engines without SafeSearch support",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-gambling",
		Description: "Hagezi Gambling — blocks gambling content (full)",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-gambling-medium",
		Description: "Hagezi Gambling — medium version",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.medium.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-gambling-mini",
		Description: "Hagezi Gambling — mini version",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.mini.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-anti-piracy",
		Description: "Hagezi Anti Piracy — blocks piracy domains",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-social",
		Description: "Hagezi Social Networks — blocks access to social networks",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-nsfw",
		Description: "Hagezi NSFW — blocks adult content",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
		Source:      "hagezi",
	},
	{
		Name:        "hagezi-urlshortener",
		Description: "Hagezi URL Shortener — blocks URL/link shorteners",
		URL:         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/urlshortener.txt",
		Source:      "hagezi",
	},
}

// knownBlocklistIndex is a map from list name to its definition, built at init time.
var knownBlocklistIndex map[string]*KnownBlocklist

func init() {
	knownBlocklistIndex = make(map[string]*KnownBlocklist, len(KnownBlocklists))
	for i := range KnownBlocklists {
		knownBlocklistIndex[KnownBlocklists[i].Name] = &KnownBlocklists[i]
	}
}

// LookupKnownBlocklist returns the blocklist definition for a given short name,
// or nil if the name is not recognised.
func LookupKnownBlocklist(name string) *KnownBlocklist {
	return knownBlocklistIndex[name]
}

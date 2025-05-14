chrome.runtime.onInstalled.addListener(() => {
  const categories = {};
  chrome.contextMenus.create({ id: "IP", title: "IP", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-quickdraw", parentId: "IP", title: "Quickdraw 🏹", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-virustotal", parentId: "IP", title: "Virustotal", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-shodan", parentId: "IP", title: "Shodan", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-abuseipdb", parentId: "IP", title: "Abuseipdb", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-otx", parentId: "IP", title: "Otx", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-greynoise", parentId: "IP", title: "Greynoise", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-talos", parentId: "IP", title: "Talos", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-xforce", parentId: "IP", title: "Xforce", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-scamalytics", parentId: "IP", title: "Scamalytics", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-ipinfo", parentId: "IP", title: "Ipinfo", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-arin", parentId: "IP", title: "Arin", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-mirai", parentId: "IP", title: "Mirai", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-securitytrails", parentId: "IP", title: "Securitytrails", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-spyse", parentId: "IP", title: "Spyse", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-ipqs", parentId: "IP", title: "Ipqs", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-ipvoid", parentId: "IP", title: "Ipvoid", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-spur", parentId: "IP", title: "Spur", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "IP-openall", parentId: "IP", title: "Open in All", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN", title: "DOMAIN", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-quickdraw", parentId: "DOMAIN", title: "Quickdraw 🏹", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-virustotal", parentId: "DOMAIN", title: "Virustotal", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-urlscan", parentId: "DOMAIN", title: "Urlscan", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-otx", parentId: "DOMAIN", title: "Otx", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-securitytrails", parentId: "DOMAIN", title: "Securitytrails", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-spyse", parentId: "DOMAIN", title: "Spyse", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-threatminer", parentId: "DOMAIN", title: "Threatminer", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-alexa", parentId: "DOMAIN", title: "Alexa", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-threatcrowd", parentId: "DOMAIN", title: "Threatcrowd", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-bluecoat", parentId: "DOMAIN", title: "Bluecoat", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-fortiguard", parentId: "DOMAIN", title: "Fortiguard", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "DOMAIN-openall", parentId: "DOMAIN", title: "Open in All", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "HASH", title: "HASH", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "HASH-quickdraw", parentId: "HASH", title: "Quickdraw 🏹", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "HASH-virustotal", parentId: "HASH", title: "Virustotal", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "HASH-hybrid", parentId: "HASH", title: "Hybrid", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "HASH-malshare", parentId: "HASH", title: "Malshare", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "HASH-otx", parentId: "HASH", title: "Otx", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "HASH-xforce", parentId: "HASH", title: "Xforce", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "HASH-talosfile", parentId: "HASH", title: "Talosfile", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "HASH-threatminer", parentId: "HASH", title: "Threatminer", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "HASH-openall", parentId: "HASH", title: "Open in All", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "URL", title: "URL", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "URL-quickdraw", parentId: "URL", title: "Quickdraw 🏹", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "URL-virustotal", parentId: "URL", title: "Virustotal", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "URL-urlscan", parentId: "URL", title: "Urlscan", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "URL-urlhaus", parentId: "URL", title: "Urlhaus", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "URL-zulu", parentId: "URL", title: "Zulu", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "URL-sitecheck", parentId: "URL", title: "Sitecheck", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "URL-urlvoid", parentId: "URL", title: "Urlvoid", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "URL-openall", parentId: "URL", title: "Open in All", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "EMAIL", title: "EMAIL", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "EMAIL-quickdraw", parentId: "EMAIL", title: "Quickdraw 🏹", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "EMAIL-icann", parentId: "EMAIL", title: "Icann", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "EMAIL-hibp", parentId: "EMAIL", title: "Hibp", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "EMAIL-mxtoolbox", parentId: "EMAIL", title: "Mxtoolbox", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "EMAIL-openall", parentId: "EMAIL", title: "Open in All", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "SANDBOX", title: "SANDBOX", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "SANDBOX-quickdraw", parentId: "SANDBOX", title: "Quickdraw 🏹", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "SANDBOX-anyrun", parentId: "SANDBOX", title: "Anyrun", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "SANDBOX-joesandbox", parentId: "SANDBOX", title: "Joesandbox", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "SANDBOX-triage", parentId: "SANDBOX", title: "Triage", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "SANDBOX-openall", parentId: "SANDBOX", title: "Open in All", contexts: ["selection"] });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  const ioc = encodeURIComponent(info.selectionText);
  const lookupMap = {"ip": {"virustotal": "https://www.virustotal.com/gui/ip-address/{ioc}", "shodan": "https://www.shodan.io/host/{ioc}", "abuseipdb": "https://www.abuseipdb.com/check/{ioc}", "otx": "https://otx.alienvault.com/indicator/ip/{ioc}", "greynoise": "https://viz.greynoise.io/ip/{ioc}", "talos": "https://talosintelligence.com/reputation_center/lookup?search={ioc}", "xforce": "https://exchange.xforce.ibmcloud.com/ip/{ioc}", "scamalytics": "https://scamalytics.com/ip/{ioc}", "ipinfo": "https://ipinfo.io/{ioc}", "arin": "https://search.arin.net/rdap/?query={ioc}", "mirai": "https://mirai.badpackets.net/?source_ip_address={ioc}", "securitytrails": "https://securitytrails.com/list/ip/{ioc}", "spyse": "https://spyse.com/target/ip/{ioc}", "ipqs": "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ioc}", "ipvoid": "https://www.ipvoid.com/ip/{ioc}", "spur": "https://spur.us/#/{ioc}"}, "domain": {"virustotal": "https://www.virustotal.com/gui/domain/{ioc}", "urlscan": "https://urlscan.io/domain/{ioc}", "otx": "https://otx.alienvault.com/indicator/domain/{ioc}", "securitytrails": "https://securitytrails.com/domain/{ioc}", "spyse": "https://spyse.com/target/domain/{ioc}", "threatminer": "https://www.threatminer.org/domain.php?q={ioc}", "alexa": "https://www.alexa.com/siteinfo/{ioc}", "threatcrowd": "https://www.threatcrowd.org/pivot.php?data={ioc}", "bluecoat": "https://sitereview.bluecoat.com/#/lookup-result/{ioc}", "fortiguard": "https://fortiguard.com/search?q={ioc}"}, "hash": {"virustotal": "https://www.virustotal.com/gui/file/{ioc}", "hybrid": "https://www.hybrid-analysis.com/search?query={ioc}", "malshare": "https://malshare.com/sample.php?action=detail&hash={ioc}", "otx": "https://otx.alienvault.com/indicator/file/{ioc}", "xforce": "https://exchange.xforce.ibmcloud.com/malware/{ioc}", "talosfile": "https://talosintelligence.com/talos_file_reputation/{ioc}", "threatminer": "https://www.threatminer.org/sample.php?q={ioc}"}, "url": {"virustotal": "https://www.virustotal.com/gui/url/{ioc}", "urlscan": "https://urlscan.io/result/{ioc}", "urlhaus": "https://urlhaus.abuse.ch/browse.php?search={ioc}", "zulu": "https://zulu.zscaler.com/{ioc}", "sitecheck": "https://sitecheck.sucuri.net/results/{ioc}", "urlvoid": "https://urlvoid.com/scan/{ioc}"}, "email": {"icann": "https://lookup.icann.org/en/lookup?searchTerm={ioc}", "hibp": "https://haveibeenpwned.com/account/{ioc}", "mxtoolbox": "https://mxtoolbox.com/EmailHeaders.aspx"}, "sandbox": {"anyrun": "https://any.run", "joesandbox": "https://www.joesandbox.com", "triage": "https://tria.ge"}};
  const handleLookup = (type, tools) => {
    for (const tool of tools) {
      const url = lookupMap[type][tool];
      if (url) chrome.tabs.create({ url: url.replace("{ioc}", ioc) });
    }
  };
  if (info.menuItemId.endsWith("-quickdraw")) {
    const type = info.menuItemId.split("-")[0].toLowerCase();
    chrome.storage.local.get(["quickdrawPrefs"], (result) => {
      const prefs = result.quickdrawPrefs || {};
      const selected = prefs[type] || [];
      handleLookup(type, selected);
    });
    return;
  }
  if (info.menuItemId.endsWith("-openall")) {
    const type = info.menuItemId.split("-")[0].toLowerCase();
    handleLookup(type, Object.keys(lookupMap[type]));
    return;
  }
  const [type, tool] = info.menuItemId.split("-");
  if (lookupMap[type.toLowerCase()] && lookupMap[type.toLowerCase()][tool]) {
    chrome.tabs.create({ url: lookupMap[type.toLowerCase()][tool].replace("{ioc}", ioc) });
  }
});
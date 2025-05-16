
// background.js for IOC Quickdraw

const TOOL_URLS = {
  ip: {
    "AbuseIPDB": "https://www.abuseipdb.com/check/{{ioc}}",
    "AlienVault OTX": "https://otx.alienvault.com/indicator/ip/{{ioc}}",
    "ARIN": "https://search.arin.net/rdap/?query={{ioc}}",
    "Bad Packets": "https://api.badpackets.net/ip/{{ioc}}",
    "BlacklistMaster": "https://www.blacklistmaster.com/?q={{ioc}}",
    "Censys": "https://search.censys.io/hosts/{{ioc}}",
    "GreyNoise": "https://viz.greynoise.io/ip/{{ioc}}",
    "IPinfo": "https://ipinfo.io/{{ioc}}",
    "IPVoid": "https://www.ipvoid.com/ip-blacklist-check/?ip={{ioc}}",
    "IP Quality Score": "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{{ioc}}",
    "MX Toolbox": "https://mxtoolbox.com/SuperTool.aspx?action=ip%3A{{ioc}}",
    "Scamlytics": "https://scamlytics.com/ip/{{ioc}}",
    "Shodan": "https://www.shodan.io/host/{{ioc}}",
    "Spur": "https://spur.us/context/{{ioc}}",
    "Talos": "https://talosintelligence.com/reputation_center/lookup?search={{ioc}}",
    "ThreatMiner": "https://www.threatminer.org/host.php?q={{ioc}}",
    "URLhaus": "https://urlhaus.abuse.ch/browse.php?search={{ioc}}",
    "VirusTotal": "https://www.virustotal.com/gui/ip-address/{{ioc}}",
    "X-Force": "https://exchange.xforce.ibmcloud.com/ip/{{ioc}}"
  },
  domain: {
    "BlueCoat": "https://sitereview.bluecoat.com/#/lookup?url={{ioc}}",
    "Censys": "https://search.censys.io/hosts/{{ioc}}",
    "FortiGuard": "https://www.fortiguard.com/search?query={{ioc}}",
    "host.io": "https://host.io/domain/{{ioc}}",
    "MX Toolbox": "https://mxtoolbox.com/SuperTool.aspx?action=domain%3A{{ioc}}",
    "Pulsedive": "https://pulsedive.com/indicator/domain/{{ioc}}",
    "SecurityTrails": "https://securitytrails.com/domain/{{ioc}}/historical",
    "Shodan": "https://www.shodan.io/search?query=hostname:{{ioc}}",
    "Spyse": "https://spyse.com/domain/{{ioc}}",
    "Talos": "https://talosintelligence.com/reputation_center/lookup?search={{ioc}}",
    "ThreatCrowd": "https://www.threatcrowd.org/domain.php?domain={{ioc}}",
    "ThreatMiner": "https://www.threatminer.org/domain.php?q={{ioc}}",
    "TOR Relay Search": "https://metrics.torproject.org/rs.html#search/{{ioc}}",
    "URLhaus": "https://urlhaus.abuse.ch/browse.php?search={{ioc}}",
    "VirusTotal": "https://www.virustotal.com/gui/domain/{{ioc}}",
    "X-Force": "https://exchange.xforce.ibmcloud.com/url/{{ioc}}"
  },
  hash: {
    "AlienVault OTX": "https://otx.alienvault.com/indicator/file/{{ioc}}",
    "Hybrid Analysis": "https://www.hybrid-analysis.com/sample/{{ioc}}",
    "Talos": "https://talosintelligence.com/reputation_center/lookup?search={{ioc}}",
    "ThreatMiner": "https://www.threatminer.org/file.php?q={{ioc}}",
    "URLhaus": "https://urlhaus.abuse.ch/browse.php?search={{ioc}}",
    "VirusTotal": "https://www.virustotal.com/gui/file/{{ioc}}",
    "X-Force": "https://exchange.xforce.ibmcloud.com/file/{{ioc}}"
  },
  url: {
    "Any.Run": "https://app.any.run/tasks?url={{ioc}}",
    "BlueCoat": "https://sitereview.bluecoat.com/#/lookup?url={{ioc}}",
    "Extract Links": "https://extracturls.com/?url={{ioc}}",
    "FortiGuard": "https://www.fortiguard.com/search?query={{ioc}}",
    "TrendMicro": "https://global.sitesafety.trendmicro.com/index?url={{ioc}}",
    "URLScan": "https://urlscan.io/search/#{{ioc}}",
    "URLhaus": "https://urlhaus.abuse.ch/browse.php?search={{ioc}}",
    "VirusTotal": "https://www.virustotal.com/gui/url/{{ioc}}",
    "X-Force": "https://exchange.xforce.ibmcloud.com/url/{{ioc}}",
    "Zscaler": "https://zulu.zscaler.com/?url={{ioc}}"
  },
  email: {
    "ICANN WHOIS Lookup": "https://lookup.icann.org/?name={{ioc}}",
    "Have I Been Pwned": "https://haveibeenpwned.com/unifiedsearch/{{ioc}}",
    "MXToolbox": "https://mxtoolbox.com/SuperTool.aspx?action=email%3A{{ioc}}"
  },
  sandbox: {
    "ANY.RUN": "https://app.any.run/tasks?url={{ioc}}",
    "Browserling": "https://www.browserling.com/tools/screenshot?url={{ioc}}",
    "Joe Sandbox": "https://www.joesandbox.com/analysis/{{ioc}}",
    "SiteShot": "https://screenshot.site/?url={{ioc}}",
    "URLScan": "https://urlscan.io/search/#{{ioc}}"
  }
};

const contextTypes = {
  ip: 'IP Lookup',
  domain: 'Domain Lookup',
  url: 'URL Lookup',
  hash: 'Hash Lookup',
  email: 'Email Lookup',
  sandbox: 'Sandbox Analysis'
};

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    for (const type in contextTypes) {
      // Parent menu without emoji
      chrome.contextMenus.create({
        id: type,
        title: contextTypes[type],
        contexts: ['selection']
      });
      // Quickdraw with bow emoji
      chrome.contextMenus.create({
        id: `${type}_quickdraw`,
        parentId: type,
        title: '🏹 Quickdraw',
        contexts: ['selection']
      });
      // Individual tools
      for (const toolName in TOOL_URLS[type]) {
        chrome.contextMenus.create({
          id: `${type}_${toolName}`,
          parentId: type,
          title: toolName,
          contexts: ['selection']
        });
      }
    }
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  const { menuItemId, selectionText } = info;
  if (!selectionText) return;
  const text = selectionText.trim();
  const [type, action] = menuItemId.split(/_(.+)/); // split only first underscore
  if (action === 'quickdraw') {
    chrome.storage.sync.get(`${type}Tools`, data => {
      const list = data[`${type}Tools`] || [];
      list.forEach(toolName => {
        const template = TOOL_URLS[type][toolName];
        if (template) {
          const url = template.replace('{{ioc}}', encodeURIComponent(text));
          chrome.tabs.create({ url });
        }
      });
    });
  } else {
    const template = TOOL_URLS[type][action];
    if (template) {
      const url = template.replace('{{ioc}}', encodeURIComponent(text));
      chrome.tabs.create({ url });
    }
  }
});

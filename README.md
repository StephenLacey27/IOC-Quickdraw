
# IOC Quickdraw

IOC Quickdraw is a fast, secure, and highly customizable OSINT Chrome and Firefox extension for cybersecurity professionals. It allows you to quickly pivot on indicators of compromise (IOCs) such as IPs, domains, hashes, URLs, and emails using a growing library of investigation tools.

## Key Features

- Right-click context menu integration for instant IOC lookups
- Supports IP addresses, domains, URLs, file hashes, emails, and sandbox portals
- Custom "Quickdraw" loadouts: choose only the tools you use
- "Open All" option for full multi-source correlation
- No background traffic, tracking, or analytics

## Installation

### Chrome
1. Visit `chrome://extensions`
2. Enable Developer Mode
3. Click "Load Unpacked"
4. Select the `chrome/` directory inside the source folder

### Firefox
1. Visit `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `manifest.json` from the `firefox/` folder

## IOC Types and Supported Tools

### IP
- AbuseIPDB
- AlienVault OTX
- ARIN
- Bad Packets
- FortiGuard
- GreyNoise
- HackerTarget
- IPInfo
- IPVoid
- IPQualityScore
- MXToolbox
- Pulsedive
- Scamalytics
- SecurityTrails
- Shodan
- Spur.us
- Spyse
- Talos
- ThreatCrowd
- ThreatMiner
- Tor Relay Search
- URLhaus
- VirusTotal
- X-Force

### Domain
- Alexa
- Bluecoat
- Censys
- FortiGuard
- Host.io
- MXToolbox
- Pulsedive
- SecurityTrails
- Shodan
- Spyse
- Talos
- ThreatCrowd
- ThreatMiner
- Tor Relay Search
- URLhaus
- VirusTotal
- X-Force

### Hash
- AlienVault OTX
- Hybrid Analysis
- MalShare
- Talos
- ThreatMiner
- URLhaus
- VirusTotal
- X-Force

### URL
- Any.Run
- Bluecoat
- FortiGuard
- Hackertarget Extract Links
- Sucuri SiteCheck
- TrendMicro Site Safety
- URLhaus
- URLScan
- VirusTotal
- X-Force
- Zscaler Zulu

### Email
- ICANN WHOIS Lookup
- Have I Been Pwned
- MXToolbox

### Sandbox (landing pages)
- ANY.RUN
- Joe Sandbox
- Triage

## Customization

Visit the extension's options page to configure which tools appear in each IOC menu or in the Quickdraw set. These preferences are stored locally and never leave your browser.

## License

MIT License. See LICENSE for full details.

## Author

Stephen Lacey  
Cybersecurity Analyst and OSINT Engineer

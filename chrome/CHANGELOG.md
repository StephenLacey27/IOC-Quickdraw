
# Changelog

## [1.3.1] – 2025-05-15

### Fixed
- Removed unnecessary `"tabs"` permission to comply with Chrome Web Store policy.


## [1.3.0] – 2025-05-15

### Added
- 🏹 “Quickdraw” context-menu entry at the top of each IOC category (IP, Domain, URL, Hash, Email, Sandbox).

### Changed
- OSINT tool lists updated to user-specified sources:
  - **IP**: trimmed to AbuseIPDB, AlienVault OTX, ARIN, Bad Packets, BlacklistMaster, Censys, GreyNoise, IPinfo, IPVoid, IP Quality Score, MX Toolbox, Scamlytics, Shodan, Spur, Talos, ThreatMiner, URLhaus, VirusTotal, X-Force  
  - **Domain**: BlueCoat, Censys, FortiGuard, host.io, MX Toolbox, Pulsedive, SecurityTrails, Shodan, Spyse, Talos, ThreatCrowd, ThreatMiner, TOR Relay Search, URLhaus, VirusTotal, X-Force  
  - **File Hash**: AlienVault OTX, Hybrid Analysis, Talos, ThreatMiner, URLhaus, VirusTotal, X-Force  
  - **URL**: Any.Run, BlueCoat, Extract Links, FortiGuard, TrendMicro, URLScan, URLhaus, VirusTotal, X-Force, Zscaler  
  - **Email**: ICANN WHOIS, Have I Been Pwned, MXToolbox  
  - **Sandbox**: ANY.RUN, Browserling, Joe Sandbox, SiteShot, URLScan  
- Fixed key mismatch: “Spur” value now exactly matches `TOOL_URLS.ip["Spur"]`.

### Fixed
- Removed stray duplicate attributes in `options.html`


## [1.2] - 2025-05-15
### Added
- New IOC categories: **Email** and **Sandbox**
- Email sources: ICANN WHOIS Lookup, Have I Been Pwned, MXToolbox
- Sandbox sources: ANY.RUN, Browserling, Joe Sandbox, SiteShot, urlscan

### Updated
- All existing IOC lists fully expanded per artifact type
- Rebuilt `background.js` to support entire updated source list
- Simplified `options.js` to auto-detect checkboxes by ID
- Clean, modernized `options.html` layout
- Alphabetized menu listings

### Fixed
- Compatibility cleanup for Chrome Web Store packaging
- Removed unused legacy context menu code

## [1.1] - 2025-05-10
- Initial public release of IOC Quickdraw

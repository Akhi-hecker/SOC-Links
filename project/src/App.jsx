import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faGithub, faLinkedin } from '@fortawesome/free-brands-svg-icons';
import { faEnvelope, faBars, faTimes } from '@fortawesome/free-solid-svg-icons';
import { Link } from 'react-scroll';
import './index.css';

function App() {
  const [isNavOpen, setIsNavOpen] = useState(false);

  const toggleNav = () => {
    setIsNavOpen(!isNavOpen);
  };

  return (
    <div>
      <nav>
        <div className="container">
          <button className="hamburger" onClick={toggleNav}>
            <FontAwesomeIcon icon={isNavOpen ? faTimes : faBars} />
          </button>
          <ul className={isNavOpen ? 'open' : ''}>
            <li><Link to="phishing" smooth={true} duration={500} onClick={toggleNav}>Phishing Analysis</Link></li>
            <li><Link to="network" smooth={true} duration={500} onClick={toggleNav}>Network Security</Link></li>
            <li><Link to="endpoint" smooth={true} duration={500} onClick={toggleNav}>Endpoint Security</Link></li>
            <li><Link to="siem" smooth={true} duration={500} onClick={toggleNav}>SIEM Resources</Link></li>
            <li><Link to="threat" smooth={true} duration={500} onClick={toggleNav}>Threat Intelligence</Link></li>
            <li><Link to="forensics" smooth={true} duration={500} onClick={toggleNav}>Digital Forensics</Link></li>
            <li><Link to="incident" smooth={true} duration={500} onClick={toggleNav}>Incident Response</Link></li>
            <li><Link to="contact" smooth={true} duration={500} onClick={toggleNav}>Contact</Link></li>
          </ul>
        </div>
      </nav>

      <div style={{ textAlign: 'center', marginBottom: '2rem', color: '#d0d0d0' }}>
        <p style={{ fontSize: '2.5rem', fontWeight: 'bold' }}>A Blog on Useful SOC Resources</p>
      </div>

      <div className="container">
        {/* Phishing Analysis Section */}
        <section id="phishing">
          <h2>Phishing Analysis Tools</h2>
          <div className="card">
            <h3>Domain Analysis Tools</h3>
            <ul>
              <li><a href="https://www.whois.com/" target="_blank" rel="noopener noreferrer">Whois.com</a> - Provides WHOIS lookup services.</li>
              <li><a href="https://whois.domaintools.com/" target="_blank" rel="noopener noreferrer">Whois Lookup - DomainTools</a> - Offers comprehensive WHOIS information.</li>
              <li><a href="https://reverseip.domaintools.com/" target="_blank" rel="noopener noreferrer">Reverse IP Lookup - DomainTools</a> - Finds domains hosted on a specific IP.</li>
              <li><a href="https://mxtoolbox.com/ReverseIP.aspx" target="_blank" rel="noopener noreferrer">Reverse IP Lookup - MxToolbox</a> - Similar to DomainTools.</li>
              <li><a href="https://centralops.net/domain/" target="_blank" rel="noopener noreferrer">CentralOps Domain Dossier</a> - Gathers domain information and DNS records.</li>
              <li><a href="https://haveibeenpwned.com/Squatting" target="_blank" rel="noopener noreferrer">Have I Been Squatted?</a> - Checks for domain squatting.</li>
              <li><a href="https://talosintelligence.com/" target="_blank" rel="noopener noreferrer">Cisco Talos - IP and Domain Reputation Center</a> - Provides threat intelligence on IPs and domains.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Email Header Analysis Tools</h3>
            <ul>
              <li><a href="https://mha.azurewebsites.net/" target="_blank" rel="noopener noreferrer">Message Header Analyzer</a> - Analyzes email headers.</li>
              <li><a href="https://mxtoolbox.com/EmailHeaders.aspx" target="_blank" rel="noopener noreferrer">Email Header Analyzer, RFC822 Parser - MxToolbox</a> - Parses email headers.</li>
              <li><a href="https://toolbox.googleapps.com/apps/messageheader/" target="_blank" rel="noopener noreferrer">Google Admin Toolbox</a> - Analyzes email headers.</li>
              <li><a href="https://github.com/jordan-wright/email-ioc-extractor" target="_blank" rel="noopener noreferrer">Email-IOC-Extractor</a> - Python script to extract IOCs from email files.</li>
            </ul>
          </div>
          <div className="card">
            <h3>URL Analysis Tools</h3>
            <ul>
              <li><a href="https://urlscan.io/" target="_blank" rel="noopener noreferrer">URLScan.io</a> - Scans URLs for security issues.</li>
              <li><a href="https://www.virustotal.com/gui/home/url" target="_blank" rel="noopener noreferrer">VirusTotal - URL Submission</a> - Analyzes URLs using multiple antivirus engines.</li>
              <li><a href="https://unshorten.it/" target="_blank" rel="noopener noreferrer">Unshorten.It</a> - Expands shortened URLs.</li>
              <li><a href="https://threatcop.com/phishing-url-checker" target="_blank" rel="noopener noreferrer">Threatcop - Phishing URL Checker</a> - Checks URLs against phishing databases.</li>
              <li><a href="https://safebrowsing.google.com/" target="_blank" rel="noopener noreferrer">Google Safe Browsing</a> - Checks URLs against unsafe web resources.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Attachment Analysis Tools</h3>
            <ul>
              <li><a href="https://www.virustotal.com/gui/home/upload" target="_blank" rel="noopener noreferrer">VirusTotal - File Submission</a> - Checks files for malware.</li>
              <li><a href="https://blog.didierstevens.com/" target="_blank" rel="noopener noreferrer">DidierStevensSuite (Various Scripts)</a> - Python scripts for analyzing file types.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Dynamic Attachment Analysis Tools</h3>
            <ul>
              <li><a href="https://www.hybrid-analysis.com/" target="_blank" rel="noopener noreferrer">Hybrid Analysis</a> - Cloud-based malware analysis service.</li>
              <li><a href="https://www.joesandbox.com/" target="_blank" rel="noopener noreferrer">Joe Sandbox Cloud Basic</a> - Advanced malware analysis platform.</li>
              <li><a href="https://cuckoosandbox.org/" target="_blank" rel="noopener noreferrer">Cuckoo Sandbox</a> - Open-source automated malware analysis system.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Automated Analysis Tools</h3>
            <ul>
              <li><a href="https://phishtool.com/" target="_blank" rel="noopener noreferrer">PhishTool</a> - Tool for phishing email analysis.</li>
              <li><a href="https://github.com/s0md3v/eml_analyzer" target="_blank" rel="noopener noreferrer">EML Analyzer</a> - Analyzes EML files for phishing indicators.</li>
              <li><a href="https://gchq.github.io/CyberChef/" target="_blank" rel="noopener noreferrer">CyberChef</a> - Web app for data analysis.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Phishing Samples Resources</h3>
            <ul>
              <li><a href="https://www.phishtank.com/" target="_blank" rel="noopener noreferrer">PhishTank</a> - Community-driven platform for phishing URLs.</li>
              <li><a href="https://openphish.com/" target="_blank" rel="noopener noreferrer">OpenPhish</a> - Real-time identification of phishing URLs.</li>
              <li><a href="https://bazaar.abuse.ch/" target="_blank" rel="noopener noreferrer">MalwareBazaar | Malware Sample Exchange</a> - Repository for malware samples.</li>
            </ul>
          </div>
        </section>

        {/* Network Security Section */}
        <section id="network">
          <h2>Network Security Tools</h2>
          <div className="card">
            <h3>Wireshark</h3>
            <p>Wireshark is a powerful network protocol analyzer.</p>
            <ul>
              <li><a href="https://www.wireshark.org/" target="_blank" rel="noopener noreferrer">Wireshark.org</a> - Official website.</li>
              <li><a href="https://www.wireshark.org/docs/" target="_blank" rel="noopener noreferrer">Wireshark - Documentation</a> - Comprehensive documentation.</li>
              <li><a href="https://wiki.wireshark.org/CaptureFilters" target="_blank" rel="noopener noreferrer">Capture Filters - Wireshark Wiki</a> - Guidelines on capture filters.</li>
              <li><a href="https://wiki.wireshark.org/DisplayFilters" target="_blank" rel="noopener noreferrer">Display Filters - Wireshark Wiki</a> - Information on display filters.</li>
              <li><a href="https://www.wiresharktraining.com/advanced-filtering-techniques/" target="_blank" rel="noopener noreferrer">Advanced Filtering Techniques</a> - Detailed instructions on filtering.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Snort</h3>
            <p>Snort is an open-source network intrusion detection and prevention system.</p>
            <ul>
              <li><a href="https://snort.org/" target="_blank" rel="noopener noreferrer">Snort - Network Intrusion Detection & Prevention System</a> - Official site.</li>
              <li><a href="https://github.com/snorpy/snorpy" target="_blank" rel="noopener noreferrer">Snorpy: A GUI for Snort</a> - Python GUI for Snort.</li>
              <li><a href="https://snorpy.com/" target="_blank" rel="noopener noreferrer">Web-Based Snort Rule Creator</a> - Web application for creating Snort rules.</li>
            </ul>
          </div>
          <div className="card">
            <h3>PCAP Samples</h3>
            <p>PCAP files are used for capturing network traffic data.</p>
            <ul>
              <li><a href="https://www.malware-traffic-analysis.net/" target="_blank" rel="noopener noreferrer">Malware Traffic Analysis</a> - PCAP and malware samples.</li>
              <li><a href="https://securityonion.net/" target="_blank" rel="noopener noreferrer">Security Onion</a> - PCAPs for testing and training.</li>
              <li><a href="https://www.netresec.com/?page=Pcaps" target="_blank" rel="noopener noreferrer">Netresec Public PCAPs</a> - Collection of public PCAP files.</li>
              <li><a href="https://wiki.wireshark.org/SampleCaptures" target="_blank" rel="noopener noreferrer">Wireshark Wiki - Sample Captures</a> - Sample captures from the Wireshark community.</li>
              <li><a href="https://github.com/thongsia/public-packet-captures" target="_blank" rel="noopener noreferrer">Public Packet Captures by Thongsia</a> - GitHub repository of PCAPs.</li>
              <li><a href="https://github.com/chrissanders/packets" target="_blank" rel="noopener noreferrer">Packet Capture Collection by Chris Sanders</a> - GitHub repository of PCAPs.</li>
            </ul>
          </div>
        </section>

        {/* Endpoint Security Section */}
        <section id="endpoint">
          <h2>Endpoint Security Tools</h2>
          <div className="card">
            <h3>Sysinternals Suite</h3>
            <p>The Sysinternals Suite is a collection of utilities for managing Windows environments.</p>
            <ul>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/" target="_blank" rel="noopener noreferrer">Sysinternals - Microsoft Learn</a> - Official Microsoft page.</li>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns" target="_blank" rel="noopener noreferrer">Autoruns</a> - Displays programs configured to run at startup.</li>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/diskmon" target="_blank" rel="noopener noreferrer">DiskMon</a> - Monitors and logs disk activity.</li>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/logonsessions" target="_blank" rel="noopener noreferrer">LogonSessions</a> - Lists active logon sessions.</li>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/procdump" target="_blank" rel="noopener noreferrer">ProcDump</a> - Command-line utility for creating crash dumps.</li>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer" target="_blank" rel="noopener noreferrer">Process Explorer</a> - Detailed information about running processes.</li>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/process-monitor" target="_blank" rel="noopener noreferrer">Process Monitor</a> - Captures real-time file system, Registry, and process activity.</li>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon" target="_blank" rel="noopener noreferrer">PsLoggedOn</a> - Displays users logged onto a system.</li>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" target="_blank" rel="noopener noreferrer">Sysmon</a> - Monitors and logs system activity to the Windows event log.</li>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview" target="_blank" rel="noopener noreferrer">TCPView for Windows</a> - Shows open connections and listening ports.</li>
              <li><a href="https://learn.microsoft.com/en-us/sysinternals/downloads/regmon" target="_blank" rel="noopener noreferrer">RegMon (Registry Monitor)</a> - Monitors Registry activity.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Sysmon Configuration</h3>
            <ul>
              <li><a href="https://github.com/SwiftOnSecurity/sysmon-config" target="_blank" rel="noopener noreferrer">Sysmon GitHub Repository</a> - Configuration files and templates.</li>
              <li><a href="https://github.com/Neo23x0/sysmon-modular" target="_blank" rel="noopener noreferrer">Sysmon Modular Configuration</a> - Modular approach to configuring Sysmon.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Windows Events Monitoring</h3>
            <ul>
              <li><a href="https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil" target="_blank" rel="noopener noreferrer">wevtutil</a> - Command-line utility for managing Windows event logs.</li>
              <li><a href="https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.3" target="_blank" rel="noopener noreferrer">Get-WinEvent (PowerShell)</a> - Retrieves events from event logs.</li>
              <li><a href="https://devblogs.microsoft.com/scripting/creating-get-winevent-queries-with-filterhashtable/" target="_blank" rel="noopener noreferrer">Creating Get-WinEvent Queries with FilterHashtable</a> - Guide on creating efficient queries.</li>
              <li><a href="https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx" target="_blank" rel="noopener noreferrer">Appendix L: Events to Monitor</a> - List of specific events to monitor.</li>
            </ul>
          </div>
        </section>

        {/* SIEM Resources Section */}
        <section id="siem">
          <h2>SIEM Resources</h2>
          <div className="card">
            <h3>Common Attack Signatures</h3>
            <p>Understanding common attack signatures is essential for effective SIEM implementation.</p>
            <ul>
              <li><a href="https://www.w3schools.com/tags/ref_urlencode.ASP" target="_blank" rel="noopener noreferrer">HTML URL Encoding Reference</a> - Guide to HTML URL encoding.</li>
              <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings" target="_blank" rel="noopener noreferrer">PayloadsAllTheThings (GitHub)</a> - Repository of payloads and bypass techniques.</li>
              <li><a href="https://portswigger.net/web-security/cross-site-scripting/cheat-sheet" target="_blank" rel="noopener noreferrer">XSS Payload List</a> - Curated list of XSS payloads.</li>
              <li><a href="https://portswigger.net/web-security/sql-injection/cheat-sheet" target="_blank" rel="noopener noreferrer">SQL Injection Payload List</a> - Collection of SQL injection payloads.</li>
              <li><a href="https://portswigger.net/web-security/xxe/cheat-sheet" target="_blank" rel="noopener noreferrer">XXE Injection Payload List</a> - Repository of XXE injection payloads.</li>
              <li><a href="https://portswigger.net/web-security/os-command-injection/cheat-sheet" target="_blank" rel="noopener noreferrer">Command Injection Payload List</a> - List of command injection payloads.</li>
              <li><a href="https://portswigger.net/web-security/file-path-traversal/cheat-sheet" target="_blank" rel="noopener noreferrer">LFI and RFI Payload List</a> - Resources for LFI and RFI attack payloads.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Log Analysis Tools</h3>
            <p>Log analysis is a critical part of SIEM.</p>
            <ul>
              <li><a href="https://stedolan.github.io/jq/" target="_blank" rel="noopener noreferrer">jq</a> - Command-line JSON processor.</li>
              <li><a href="https://github.com/tonikelope/awesome-log-analysis" target="_blank" rel="noopener noreferrer">Awesome Log Analysis (GitHub)</a> - Curated list of log analysis tools.</li>
              <li><a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Status" target="_blank" rel="noopener noreferrer">HTTP Response Status Codes (MDN)</a> - Details on HTTP response status codes.</li>
              <li><a href="https://regex101.com/" target="_blank" rel="noopener noreferrer">regex101</a> - Online regex tester.</li>
              <li><a href="https://www.whatismybrowser.com/guides/the-latest-user-agent" target="_blank" rel="noopener noreferrer">User Agent Parser (WhatIsMyBrowser.com)</a> - Tool to parse user agent strings.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Splunk</h3>
            <p>Splunk is a powerful platform for SIEM solutions.</p>
            <ul>
              <li><a href="https://www.splunk.com/" target="_blank" rel="noopener noreferrer">Splunk Overview</a> - Official Splunk site.</li>
              <li><a href="https://www.splunk.com/en_us/resources/free-trials/splunk-enterprise.html" target="_blank" rel="noopener noreferrer">Splunk Enterprise Free Trial</a> - Free trial version.</li>
              <li><a href="https://www.splunk.com/en_us/software/universal-forwarder.html" target="_blank" rel="noopener noreferrer">Universal Forwarder for Remote Data Collection</a> - Tool for collecting data.</li>
              <li><a href="https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutthesearchprocessinglanguage" target="_blank" rel="noopener noreferrer">Understanding SPL Syntax</a> - Documentation on SPL.</li>
              <li><a href="https://docs.splunk.com/Documentation/Splunk/latest/Search/Quickreferenceforsearchcommands" target="_blank" rel="noopener noreferrer">Command Quick Reference</a> - Quick reference for Splunk commands.</li>
              <li><a href="https://docs.splunk.com/Documentation/Splunk/latest/Report/Createandeditreports" target="_blank" rel="noopener noreferrer">Create Reports</a> - Guides on creating reports.</li>
              <li><a href="https://docs.splunk.com/Documentation/Splunk/latest/Alert/Aboutalerts" target="_blank" rel="noopener noreferrer">Getting Started with Alerts</a> - Guides on creating alerts.</li>
              <li><a href="https://docs.splunk.com/Documentation/Splunk/latest/Viz/Createandeditdashboards" target="_blank" rel="noopener noreferrer">Create Dashboards</a> - Guides on creating dashboards.</li>
              <li><a href="https://github.com/splunk/bossofsea" target="_blank" rel="noopener noreferrer">Splunk Boss of the SOC v1</a> - Competitive dataset for Splunk.</li>
              <li><a href="https://github.com/splunk/bossofsea-v2" target="_blank" rel="noopener noreferrer">Splunk Boss of the SOC v2</a> - Competitive dataset for Splunk.</li>
              <li><a href="https://github.com/splunk/bossofsea-v3" target="_blank" rel="noopener noreferrer">Splunk Boss of the SOC v3</a> - Competitive dataset for Splunk.</li>
            </ul>
          </div>
        </section>

        {/* Threat Intelligence Section */}
        <section id="threat">
          <h2>Threat Intelligence</h2>
          <div className="card">
            <h3>Frameworks</h3>
            <ul>
              <li><a href="https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html" target="_blank" rel="noopener noreferrer">Cyber Kill Chain® | Lockheed Martin</a> - Model outlining stages of a cyber attack.</li>
              <li><a href="https://unifiedkillchain.com/" target="_blank" rel="noopener noreferrer">Unified Kill Chain</a> - Evolution of the Cyber Kill Chain.</li>
              <li><a href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATT&CK®</a> - Framework documenting adversarial tactics.</li>
              <li><a href="https://d3fend.mitre.org/" target="_blank" rel="noopener noreferrer">D3FEND Matrix | MITRE D3FEND™</a> - Framework detailing defensive measures.</li>
              <li><a href="https://www.nationalisacs.org/" target="_blank" rel="noopener noreferrer">National Council of ISACs</a> - Platform for sharing threat intelligence.</li>
              <li><a href="https://www.activeresponse.org/diamond-model/" target="_blank" rel="noopener noreferrer">The Diamond Model of Intrusion Analysis</a> - Framework for intrusion analysis.</li>
              <li><a href="https://www.recordedfuture.com/blog/threat-hunting-diamond-model" target="_blank" rel="noopener noreferrer">Building Threat Hunting Strategies with the Diamond Model</a> - Resource on using the Diamond Model.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Threat Intelligence Tools</h3>
            <ul>
              <li><a href="https://www.cisco.com/c/en/us/products/security/threat-intelligence.html" target="_blank" rel="noopener noreferrer">Cisco Popularity List</a> - List of threat intelligence tools.</li>
              <li><a href="https://www.greynoise.io/" target="_blank" rel="noopener noreferrer">GreyNoise</a> - Analyzes internet-wide scan data.</li>
              <li><a href="https://www.honeydb.io/" target="_blank" rel="noopener noreferrer">HoneyDB</a> - Community-driven threat intelligence data.</li>
              <li><a href="https://www.phishtank.com/" target="_blank" rel="noopener noreferrer">PhishTank</a> - Platform for reporting phishing sites.</li>
              <li><a href="https://threatfox.abuse.ch/" target="_blank" rel="noopener noreferrer">ThreatFox</a> - Platform for sharing IOCs.</li>
              <li><a href="https://bazaar.abuse.ch/" target="_blank" rel="noopener noreferrer">Malware Bazaar</a> - Repository for malware samples.</li>
              <li><a href="https://urlhaus.abuse.ch/" target="_blank" rel="noopener noreferrer">URLHaus</a> - Project for sharing malware distribution URLs.</li>
              <li><a href="https://www.abuseipdb.com/" target="_blank" rel="noopener noreferrer">AbuseIPDB</a> - Database of reported abusive IP addresses.</li>
              <li><a href="https://www.virustotal.com/" target="_blank" rel="noopener noreferrer">VirusTotal</a> - Analyzes files and URLs for malware.</li>
              <li><a href="https://www.misp-project.org/" target="_blank" rel="noopener noreferrer">MISP Open Source Threat Intelligence Platform</a> - Platform for sharing threat information.</li>
              <li><a href="https://www.levelblue.com/open-threat-exchange" target="_blank" rel="noopener noreferrer">LevelBlue – Open Threat Exchange</a> - Collaborative platform for sharing threat intelligence.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Protocols and References</h3>
            <ul>
              <li><a href="https://nvd.nist.gov/" target="_blank" rel="noopener noreferrer">NVD (National Vulnerability Database)</a> - Repository of vulnerability data.</li>
              <li><a href="https://cve.mitre.org/" target="_blank" rel="noopener noreferrer">CVE (Common Vulnerabilities and Exposures)</a> - List of cybersecurity vulnerabilities.</li>
              <li><a href="https://www.cisa.gov/tlp" target="_blank" rel="noopener noreferrer">Traffic Light Protocol (TLP) Definitions and Usage | CISA</a> - Guidelines for using TLP.</li>
              <li><a href="https://oasis-open.github.io/cti-documentation/" target="_blank" rel="noopener noreferrer">STIX (Structured Threat Information Expression)</a> - Standardized language for sharing threat intelligence.</li>
              <li><a href="https://oasis-open.github.io/cti-documentation/taxii.html" target="_blank" rel="noopener noreferrer">TAXII™ (Trusted Automated eXchange of Indicator Information)</a> - Protocol for sharing cyber threat intelligence.</li>
            </ul>
          </div>
        </section>

        {/* Digital Forensics Section */}
        <section id="forensics">
          <h2>Digital Forensics</h2>
          <div className="card">
            <h3>Forensics Processes</h3>
            <ul>
              <li><a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf" target="_blank" rel="noopener noreferrer">NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response</a> - Guidelines for integrating forensic techniques.</li>
              <li><a href="https://digital-forensics.sans.org/blog/2011/07/25/order-of-volatility/" target="_blank" rel="noopener noreferrer">Order of Volatility</a> - Principle for data collection.</li>
              <li><a href="https://digital-forensics.sans.org/media/windows-forensic-analysis-poster.pdf" target="_blank" rel="noopener noreferrer">Windows Forensic Analysis | SANS Poster</a> - Visual guide for Windows forensic analysis.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Digital Forensics Tools</h3>
            <ul>
              <li><a href="https://github.com/EricZimmerman" target="_blank" rel="noopener noreferrer">Eric Zimmerman's Tools (GitHub)</a> - Collection of open-source forensics tools.</li>
              <li><a href="https://accessdata.com/products/ftk-imager" target="_blank" rel="noopener noreferrer">FTK Imager</a> - Forensic data imaging tool.</li>
              <li><a href="https://www.nirsoft.net/utils/win_prefetch_view.html" target="_blank" rel="noopener noreferrer">WinPrefetchView</a> - Utility for viewing prefetch files.</li>
              <li><a href="https://www.kroll.com/en/insights/tools/kroll-artifact-parser-extractor-kape" target="_blank" rel="noopener noreferrer">Kroll Artifact Parser And Extractor (KAPE)</a> - Tool for parsing and extracting artifacts.</li>
              <li><a href="https://www.volatilityfoundation.org/" target="_blank" rel="noopener noreferrer">Volatility Framework</a> - Open-source memory forensics framework.</li>
              <li><a href="https://www.autopsy.com/" target="_blank" rel="noopener noreferrer">Autopsy</a> - Digital forensics platform.</li>
              <li><a href="https://www.sleuthkit.org/" target="_blank" rel="noopener noreferrer">The Sleuth Kit (TSK) & Autopsy</a> - Open-source collection of command-line tools.</li>
              <li><a href="https://github.com/Velocidex/avml" target="_blank" rel="noopener noreferrer">AVML (Acquire Volatile Memory for Linux) (GitHub)</a> - Tool for acquiring volatile memory from Linux.</li>
              <li><a href="https://manpages.ubuntu.com/manpages/jammy/en/man1/dcfldd.1.html" target="_blank" rel="noopener noreferrer">dcfldd</a> - Enhanced version of the dd command.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Additional Resources</h3>
            <ul>
              <li><a href="https://github.com/meirwah/awesome-incident-response" target="_blank" rel="noopener noreferrer">Awesome Incident Response</a> - Curated list of incident response tools.</li>
              <li><a href="https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/windows-artifacts" target="_blank" rel="noopener noreferrer">Windows Artifacts | HackTricks</a> - Guide detailing Windows artifacts.</li>
              <li><a href="https://en.wikipedia.org/wiki/List_of_file_signatures" target="_blank" rel="noopener noreferrer">List of File Signatures (Wikipedia)</a> - Reference page listing file signatures.</li>
              <li><a href="https://learn.microsoft.com/en-us/windows/win32/fileio/file-system-functionality" target="_blank" rel="noopener noreferrer">Overview of FAT, HPFS, and NTFS File Systems | Microsoft Learn</a> - Documentation on file systems.</li>
            </ul>
          </div>
        </section>

        {/* Incident Response Section */}
        <section id="incident">
          <h2>Incident Response</h2>
          <div className="card">
            <h3>Incident Response Tools</h3>
            <ul>
              <li><a href="https://github.com/sans-blue-team/DeepBlueCLI" target="_blank" rel="noopener noreferrer">DeepBlueCLI (GitHub)</a> - Command-line interface for incident response.</li>
              <li><a href="https://github.com/Velocidex/velociraptor" target="_blank" rel="noopener noreferrer">Velociraptor (GitHub)</a> - Endpoint monitoring tool for DFIR.</li>
              <li><a href="https://github.com/Neo23x0/IR_Rescue" target="_blank" rel="noopener noreferrer">IR Rescue (GitHub)</a> - Script to collect host forensic data.</li>
              <li><a href="https://thehive-project.org/" target="_blank" rel="noopener noreferrer">TheHive</a> - Open-source incident response platform.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Incident Response Processes</h3>
            <ul>
              <li><a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf" target="_blank" rel="noopener noreferrer">Computer Security Incident Handling Guide (NIST SP 800-61 Rev. 2)</a> - Guide for handling security incidents.</li>
              <li><a href="https://www.sans.org/information-security/glossary/incident-response-cycle/" target="_blank" rel="noopener noreferrer">SANS Incident Response Cycle</a> - Framework for responding to incidents.</li>
              <li><a href="https://nvd.nist.gov/vuln/metrics" target="_blank" rel="noopener noreferrer">NVD - Vulnerability Metrics</a> - Metrics and information on vulnerabilities.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Incident Response Playbooks</h3>
            <ul>
              <li><a href="https://github.com/aws-samples/aws-incident-response-playbooks" target="_blank" rel="noopener noreferrer">AWS Incident Response Playbooks (GitHub)</a> - Playbooks for AWS environments.</li>
              <li><a href="https://github.com/counteractive/incident-response-plan-template" target="_blank" rel="noopener noreferrer">Counteractive Incident Response Plan Template (GitHub)</a> - Customizable incident response playbooks.</li>
              <li><a href="https://github.com/certsocietegenerale/IR-Playbook-Battle-Cards" target="_blank" rel="noopener noreferrer">Cyber Incident Response Team Playbook Battle Cards (GitHub)</a> - Battle cards for incident response teams.</li>
              <li><a href="https://github.com/certsocietegenerale/IR-Methodologies" target="_blank" rel="noopener noreferrer">Incident Response Methodologies 2022 (GitHub)</a> - Methodologies for incident response.</li>
              <li><a href="https://github.com/Cyb3rWard0g/ThreatHunter-Playbook" target="_blank" rel="noopener noreferrer">Threat Hunter Playbook (GitHub)</a> - Community-driven project for threat hunting.</li>
            </ul>
          </div>
        </section>

        {/* Contact Section */}
        <section id="contact" className="contact-section">
          <h2>Contact</h2>
          <div className="contact-links">
            <a href="mailto:kallabharath2004@gmail.com">
              <FontAwesomeIcon icon={faEnvelope} />
              Email
            </a>
            <a href="https://www.linkedin.com/in/kalla-akhil" target="_blank" rel="noopener noreferrer">
              <FontAwesomeIcon icon={faLinkedin} />
              LinkedIn
            </a>
            <a href="https://github.com/Akhi-hecker/Akhi-hecker" target="_blank" rel="noopener noreferrer">
              <FontAwesomeIcon icon={faGithub} />
              GitHub
            </a>
          </div>
        </section>
      </div>
    </div>
  );
}

export default App;
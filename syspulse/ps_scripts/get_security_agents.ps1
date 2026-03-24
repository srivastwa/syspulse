# get_security_agents.ps1 — Detect installed security agents and tooling
# Checks services, registry keys, file paths, and running processes.
# Outputs a single JSON object to stdout. Exits 0.

$ErrorActionPreference = 'SilentlyContinue'

# ── Tool Database ──────────────────────────────────────────────────────────────
# Each entry: Name, Category, Services[], RegKeys[], Paths[], Processes[]
# Detection priority: service → registry → file path → process
$toolDb = @(

    # ── EDR / Endpoint Protection Platform ────────────────────────────────────
    @{
        Name      = 'CrowdStrike Falcon'
        Category  = 'EDR'
        Services  = @('CSFalconService','csagent','csdevicecontrol')
        RegKeys   = @('HKLM:\SOFTWARE\CrowdStrike\Sensor Platform','HKLM:\SYSTEM\CrowdStrike')
        Paths     = @('C:\Program Files\CrowdStrike\CSFalconService.exe','C:\Windows\System32\drivers\CrowdStrike')
        Processes = @('CSFalconService','falcon-sensor')
    }
    @{
        Name      = 'SentinelOne'
        Category  = 'EDR'
        Services  = @('SentinelAgent','SentinelHelperService','SentinelStaticEngine')
        RegKeys   = @('HKLM:\SOFTWARE\Sentinel Labs','HKLM:\SOFTWARE\SentinelOne')
        Paths     = @('C:\Program Files\SentinelOne')
        Processes = @('SentinelAgent','SentinelServiceHost')
    }
    @{
        Name      = 'Microsoft Defender for Endpoint'
        Category  = 'EDR'
        Services  = @('Sense','MsSense')
        RegKeys   = @('HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection','HKLM:\SOFTWARE\Microsoft\Windows Defender Advanced Threat Protection')
        Paths     = @('C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe')
        Processes = @('MsSense','SenseIR','SenseCncProxy')
    }
    @{
        Name      = 'VMware Carbon Black'
        Category  = 'EDR'
        Services  = @('CbDefense','RepMgr','cbstream','CarbonBlack')
        RegKeys   = @('HKLM:\SOFTWARE\CarbonBlack','HKLM:\SOFTWARE\VMware, Inc.\VMware Carbon Black')
        Paths     = @('C:\Program Files\Confer','C:\Program Files\VMware\VMware Carbon Black')
        Processes = @('cbdefense','repmgr64','cbstream')
    }
    @{
        Name      = 'Cylance PROTECT'
        Category  = 'EDR'
        Services  = @('CylanceSvc')
        RegKeys   = @('HKLM:\SOFTWARE\Cylance\Desktop')
        Paths     = @('C:\Program Files\Cylance\Desktop\CylanceSvc.exe')
        Processes = @('CylanceSvc','CylanceUI')
    }
    @{
        Name      = 'Palo Alto Cortex XDR'
        Category  = 'EDR'
        Services  = @('cyserver','cyvera')
        RegKeys   = @('HKLM:\SOFTWARE\Palo Alto Networks\Traps','HKLM:\SOFTWARE\Cyvera')
        Paths     = @('C:\Program Files\Palo Alto Networks\Cortex XDR','C:\Program Files\Cyvera')
        Processes = @('cyserver','cyvera','cortex_xdr')
    }
    @{
        Name      = 'Sophos Intercept X'
        Category  = 'EDR'
        Services  = @('Sophos Endpoint Defense','SophosEDR','SophosFileScanner','SophosMCS')
        RegKeys   = @('HKLM:\SOFTWARE\Sophos','HKLM:\SOFTWARE\WOW6432Node\Sophos')
        Paths     = @('C:\Program Files\Sophos\Sophos Endpoint Agent','C:\Program Files (x86)\Sophos')
        Processes = @('SophosEDR','SophosHealth','SophosNtpService')
    }
    @{
        Name      = 'Trend Micro Apex One'
        Category  = 'EDR'
        Services  = @('TmListen','TmProxy','TmPfw','ntrtscan')
        RegKeys   = @('HKLM:\SOFTWARE\TrendMicro\PC-cillinNTCorp')
        Paths     = @('C:\Program Files\Trend Micro\Security Agent')
        Processes = @('TmListen','ntrtscan','pccntmon')
    }
    @{
        Name      = 'ESET Endpoint Security'
        Category  = 'EDR'
        Services  = @('ekrn','EraAgentSvc')
        RegKeys   = @('HKLM:\SOFTWARE\ESET\ESET Security')
        Paths     = @('C:\Program Files\ESET\ESET Security','C:\Program Files\ESET\ESET Endpoint Security')
        Processes = @('egui','ekrn')
    }
    @{
        Name      = 'Cybereason'
        Category  = 'EDR'
        Services  = @('CybereasonActiveProbe','CybereasonAntiMalware')
        RegKeys   = @('HKLM:\SOFTWARE\Cybereason')
        Paths     = @('C:\Program Files\Cybereason ActiveProbe')
        Processes = @('minionhost','CybereasonAV')
    }
    @{
        Name      = 'Malwarebytes Endpoint'
        Category  = 'EDR'
        Services  = @('MBAMService','MBAMProtection','mbamtray')
        RegKeys   = @('HKLM:\SOFTWARE\Malwarebytes','HKLM:\SOFTWARE\Malwarebytes Nebula')
        Paths     = @('C:\Program Files\Malwarebytes\Anti-Malware','C:\Program Files\Malwarebytes Endpoint Agent')
        Processes = @('MBAMService','mbam')
    }
    @{
        Name      = 'Huntress'
        Category  = 'EDR'
        Services  = @('HuntressAgent','HuntressUpdater')
        RegKeys   = @('HKLM:\SOFTWARE\Huntress Labs\Huntress')
        Paths     = @('C:\Program Files\Huntress Labs\Huntress','C:\Program Files (x86)\Huntress Labs\Huntress')
        Processes = @('HuntressAgent')
    }
    @{
        Name      = 'Bitdefender GravityZone'
        Category  = 'EDR'
        Services  = @('EPSecurityService','EPProtectedService','bdredline')
        RegKeys   = @('HKLM:\SOFTWARE\Bitdefender','HKLM:\SOFTWARE\Bitdefender SRL\Bitdefender Security')
        Paths     = @('C:\Program Files\Bitdefender\Endpoint Security')
        Processes = @('EPSecurityService','bdagent')
    }
    @{
        Name      = 'Trellix (McAfee) Endpoint'
        Category  = 'EDR'
        Services  = @('McShield','mfemms','mfevtp','masvc')
        RegKeys   = @('HKLM:\SOFTWARE\McAfee','HKLM:\SOFTWARE\Trellix')
        Paths     = @('C:\Program Files\McAfee','C:\Program Files\Trellix')
        Processes = @('McShield','mfemactl','masvc')
    }
    @{
        Name      = 'Symantec Endpoint Protection'
        Category  = 'EDR'
        Services  = @('SepMasterService','SmcService','ccSvcHst')
        RegKeys   = @('HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection')
        Paths     = @('C:\Program Files\Symantec\Symantec Endpoint Protection')
        Processes = @('ccSvcHst','smc','SmcGui')
    }
    @{
        Name      = 'Kaspersky Endpoint Security'
        Category  = 'EDR'
        Services  = @('AVP','klnagent','KLIM6')
        RegKeys   = @('HKLM:\SOFTWARE\KasperskyLab\protected\AVP')
        Paths     = @('C:\Program Files\Kaspersky Lab','C:\Program Files (x86)\Kaspersky Lab')
        Processes = @('avp','klnagent')
    }
    @{
        Name      = 'Webroot Business'
        Category  = 'EDR'
        Services  = @('WRSVC','WebrootSecureAnywhere')
        RegKeys   = @('HKLM:\SOFTWARE\WRData','HKLM:\SOFTWARE\Webroot')
        Paths     = @('C:\Program Files (x86)\Webroot\WRSA.exe','C:\Program Files\Webroot\WRSA.exe')
        Processes = @('WRSA')
    }
    @{
        Name      = 'WithSecure (F-Secure) Elements'
        Category  = 'EDR'
        Services  = @('F-Secure Network Request Broker','FSMA','fshoster32','FSORSPClient')
        RegKeys   = @('HKLM:\SOFTWARE\F-Secure','HKLM:\SOFTWARE\WithSecure')
        Paths     = @('C:\Program Files\F-Secure','C:\Program Files\WithSecure')
        Processes = @('fshoster32','fsav','fsorsp')
    }

    # ── Antivirus (standalone / not already EDR-covered) ──────────────────────
    @{
        Name      = 'Windows Defender (built-in)'
        Category  = 'AV'
        Services  = @('WinDefend','MsMpSvc','SecurityHealthService')
        RegKeys   = @('HKLM:\SOFTWARE\Microsoft\Windows Defender')
        Paths     = @('C:\Program Files\Windows Defender\MsMpEng.exe')
        Processes = @('MsMpEng','SecurityHealthService')
    }
    @{
        Name      = 'Avast Business Antivirus'
        Category  = 'AV'
        Services  = @('aswbcc','avast! Antivirus','AvastSvc')
        RegKeys   = @('HKLM:\SOFTWARE\AVAST Software\Avast')
        Paths     = @('C:\Program Files\AVAST Software\Avast')
        Processes = @('AvastSvc','AvastUI')
    }
    @{
        Name      = 'AVG Business Antivirus'
        Category  = 'AV'
        Services  = @('AVGSvc','avgwd')
        RegKeys   = @('HKLM:\SOFTWARE\AVG')
        Paths     = @('C:\Program Files\AVG\Antivirus')
        Processes = @('AVGSvc','AVGUI')
    }
    @{
        Name      = 'Norton / NortonLifeLock'
        Category  = 'AV'
        Services  = @('NortonSecurity','NortonLifeLock','ccSvcHst','ns')
        RegKeys   = @('HKLM:\SOFTWARE\Norton','HKLM:\SOFTWARE\NortonLifeLock')
        Paths     = @('C:\Program Files\Norton Security','C:\Program Files\Norton')
        Processes = @('NortonSecurity','ns')
    }

    # ── Web Proxy / SASE / Network Security ───────────────────────────────────
    @{
        Name      = 'Zscaler Client Connector'
        Category  = 'Proxy'
        Services  = @('ZSAService','ZscalerService','ZSATunnel')
        RegKeys   = @('HKLM:\SOFTWARE\Zscaler')
        Paths     = @('C:\Program Files\Zscaler\ZSAService','C:\Program Files\Zscaler')
        Processes = @('ZSAService','ZSATunnel')
    }
    @{
        Name      = 'Netskope Client'
        Category  = 'Proxy'
        Services  = @('STAgentSvc','NetskopeClient')
        RegKeys   = @('HKLM:\SOFTWARE\Netskope')
        Paths     = @('C:\Program Files\Netskope\STAgent','C:\Program Files (x86)\Netskope')
        Processes = @('STAgent','nsprocessmonitor')
    }
    @{
        Name      = 'Cisco Umbrella Roaming'
        Category  = 'Proxy'
        Services  = @('Umbrella_RC')
        RegKeys   = @('HKLM:\SOFTWARE\OpenDNS\RoamingClient','HKLM:\SOFTWARE\Cisco\Cisco Umbrella')
        Paths     = @('C:\Program Files\OpenDNS\Umbrella Roaming Client','C:\Program Files (x86)\OpenDNS')
        Processes = @('Umbrella_RC')
    }
    @{
        Name      = 'iboss Cloud Connector'
        Category  = 'Proxy'
        Services  = @('ibossPacketFilter','ibossClientConnect')
        RegKeys   = @('HKLM:\SOFTWARE\iboss')
        Paths     = @('C:\Program Files\iboss')
        Processes = @('ibossClientConnect')
    }

    # ── VPN ───────────────────────────────────────────────────────────────────
    @{
        Name      = 'Cisco AnyConnect / Secure Client'
        Category  = 'VPN'
        Services  = @('vpnagent','csc_swupdatetask_logon','Cisco AnyConnect')
        RegKeys   = @('HKLM:\SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client','HKLM:\SOFTWARE\Cisco Systems\Cisco Secure Client')
        Paths     = @('C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client','C:\Program Files\Cisco\Cisco Secure Client')
        Processes = @('vpnagent','vpnui','csc_ui')
    }
    @{
        Name      = 'Palo Alto GlobalProtect'
        Category  = 'VPN'
        Services  = @('PanGPS','PanGPA')
        RegKeys   = @('HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect')
        Paths     = @('C:\Program Files\Palo Alto Networks\GlobalProtect')
        Processes = @('PanGPS','PanGPA','pangpUI')
    }
    @{
        Name      = 'Fortinet FortiClient'
        Category  = 'VPN'
        Services  = @('FortiSSLVPNdaemon','FortiClient','fmon')
        RegKeys   = @('HKLM:\SOFTWARE\Fortinet\FortiClient')
        Paths     = @('C:\Program Files\Fortinet\FortiClient')
        Processes = @('FortiClient','FortiSSL','fmon')
    }
    @{
        Name      = 'Ivanti Secure Access (Pulse)'
        Category  = 'VPN'
        Services  = @('DsNcService','PulseSecureService')
        RegKeys   = @('HKLM:\SOFTWARE\Pulse Secure','HKLM:\SOFTWARE\Ivanti\Secure Access')
        Paths     = @('C:\Program Files (x86)\Pulse Secure\Pulse','C:\Program Files\Ivanti\Secure Access Client')
        Processes = @('PulseSecureService','JamUI')
    }
    @{
        Name      = 'Check Point Endpoint VPN'
        Category  = 'VPN'
        Services  = @('TracSrvWrapper','cprid')
        RegKeys   = @('HKLM:\SOFTWARE\CheckPoint\Endpoint Connect','HKLM:\SOFTWARE\CheckPoint\VPN-1')
        Paths     = @('C:\Program Files\CheckPoint\Endpoint Connect','C:\Program Files (x86)\CheckPoint\Endpoint Connect')
        Processes = @('TracSrvWrapper','cpbin')
    }
    @{
        Name      = 'WireGuard'
        Category  = 'VPN'
        Services  = @('WireGuard','WireGuardTunnel$')
        RegKeys   = @('HKLM:\SOFTWARE\WireGuard')
        Paths     = @('C:\Program Files\WireGuard\wireguard.exe')
        Processes = @('wireguard')
    }
    @{
        Name      = 'OpenVPN'
        Category  = 'VPN'
        Services  = @('OpenVPN','OpenVPNService')
        RegKeys   = @('HKLM:\SOFTWARE\OpenVPN')
        Paths     = @('C:\Program Files\OpenVPN\bin\openvpn.exe','C:\Program Files\OpenVPN Technologies')
        Processes = @('openvpn','openvpn-gui')
    }

    # ── MDM / UEM / Asset Management ──────────────────────────────────────────
    @{
        Name      = 'Microsoft Intune'
        Category  = 'MDM'
        Services  = @('IntuneManagementExtension','Microsoft Intune Management Extension')
        RegKeys   = @('HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension','HKLM:\SOFTWARE\Microsoft\Enrollments')
        Paths     = @('C:\Program Files (x86)\Microsoft Intune Management Extension')
        Processes = @('IntuneManagementExtension','AgentExecutor')
    }
    @{
        Name      = 'IBM / HCL BigFix'
        Category  = 'MDM'
        Services  = @('BESClient')
        RegKeys   = @('HKLM:\SOFTWARE\BigFix\EnterpriseClient','HKLM:\SOFTWARE\HCL Technologies\BigFix')
        Paths     = @('C:\Program Files\BigFix Enterprise\BES Client','C:\Program Files (x86)\BigFix Enterprise')
        Processes = @('BESClient')
    }
    @{
        Name      = 'Tanium Client'
        Category  = 'MDM'
        Services  = @('Tanium Client')
        RegKeys   = @('HKLM:\SOFTWARE\Tanium\Tanium Client')
        Paths     = @('C:\Program Files (x86)\Tanium\Tanium Client\TaniumClient.exe','C:\Program Files\Tanium\Tanium Client')
        Processes = @('TaniumClient')
    }
    @{
        Name      = 'ManageEngine Endpoint Central'
        Category  = 'MDM'
        Services  = @('ManageEngine Desktop Central - Agent','DCPlugin')
        RegKeys   = @('HKLM:\SOFTWARE\AdventNet\DesktopCentral','HKLM:\SOFTWARE\ManageEngine\DesktopCentral_Agent')
        Paths     = @('C:\Program Files\DesktopCentral_Agent')
        Processes = @('dcagentservice','dcpluginservice')
    }
    @{
        Name      = 'VMware Workspace ONE (AirWatch)'
        Category  = 'MDM'
        Services  = @('AWACMClient','AirWatchMDMService')
        RegKeys   = @('HKLM:\SOFTWARE\AirWatch','HKLM:\SOFTWARE\VMware, Inc.\VMware Workspace ONE')
        Paths     = @('C:\Program Files (x86)\AirWatch\AirWatch Agent')
        Processes = @('AWACMClient','AirWatchAgent')
    }
    @{
        Name      = 'Ivanti Endpoint Manager (LANDESK)'
        Category  = 'MDM'
        Services  = @('CBA8','SOFTMON','Ivanti Endpoint Agent')
        RegKeys   = @('HKLM:\SOFTWARE\Intel\LANDesk','HKLM:\SOFTWARE\LANDesk','HKLM:\SOFTWARE\LANDESK')
        Paths     = @('C:\Program Files\LANDESK','C:\Program Files (x86)\LANDESK','C:\Program Files\Ivanti')
        Processes = @('cba8','softmon')
    }
    @{
        Name      = 'Absolute Agent (Computrace)'
        Category  = 'MDM'
        Services  = @('AbsoluteTechnology','Absolute Software')
        RegKeys   = @('HKLM:\SOFTWARE\Absolute Software','HKLM:\SOFTWARE\Absolute')
        Paths     = @('C:\Windows\SysWOW64\AbsoluteTechnology','C:\Windows\System32\AbsoluteTechnology')
        Processes = @('rpcnet','rpcld')
    }
    @{
        Name      = 'Automox'
        Category  = 'MDM'
        Services  = @('amagent')
        RegKeys   = @('HKLM:\SOFTWARE\Automox')
        Paths     = @('C:\Program Files\Automox\amagent.exe')
        Processes = @('amagent')
    }
    @{
        Name      = 'ConnectWise Automate (LabTech)'
        Category  = 'MDM'
        Services  = @('LTService','LTSvcMon')
        RegKeys   = @('HKLM:\SOFTWARE\LabTech\Service','HKLM:\SOFTWARE\CW Automate')
        Paths     = @('C:\Windows\LTSvc\LTSVC.exe')
        Processes = @('LTSvcMon','LTTray')
    }

    # ── PAM / Privileged Access Management ────────────────────────────────────
    @{
        Name      = 'CyberArk EPM'
        Category  = 'PAM'
        Services  = @('CyberArkEPMService','CyberArk EPM Service')
        RegKeys   = @('HKLM:\SOFTWARE\CyberArk\EPM','HKLM:\SOFTWARE\Cyber-Ark')
        Paths     = @('C:\Program Files\CyberArk\Endpoint Privilege Manager')
        Processes = @('CyberArkEPMService')
    }
    @{
        Name      = 'BeyondTrust Privilege Management'
        Category  = 'PAM'
        Services  = @('BeyondTrustRemoteSupportJumpClient','Avecto Privilege Guard','PolicyAdministrationService')
        RegKeys   = @('HKLM:\SOFTWARE\Avecto\Defendpoint Client','HKLM:\SOFTWARE\BeyondTrust\Privilege Management')
        Paths     = @('C:\Program Files\Avecto\Privilege Guard Client','C:\Program Files\BeyondTrust\Privilege Management')
        Processes = @('privilegeguard','pgclient')
    }
    @{
        Name      = 'Delinea / Thycotic Privilege Manager'
        Category  = 'PAM'
        Services  = @('ThycoticAgent','DelineaAgent')
        RegKeys   = @('HKLM:\SOFTWARE\Thycotic','HKLM:\SOFTWARE\Delinea')
        Paths     = @('C:\Program Files\Thycotic\Privilege Manager Agent','C:\Program Files\Delinea')
        Processes = @('ThycoticAgent')
    }

    # ── SIEM / Monitoring Agents ───────────────────────────────────────────────
    @{
        Name      = 'Splunk Universal Forwarder'
        Category  = 'SIEM'
        Services  = @('SplunkForwarder')
        RegKeys   = @('HKLM:\SOFTWARE\Splunk','HKLM:\SOFTWARE\SplunkUniversalForwarder')
        Paths     = @('C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe')
        Processes = @('splunkd')
    }
    @{
        Name      = 'Elastic Agent'
        Category  = 'SIEM'
        Services  = @('Elastic Agent','elastic-agent')
        RegKeys   = @('HKLM:\SOFTWARE\Elastic\Agent')
        Paths     = @('C:\Program Files\Elastic\Agent\elastic-agent.exe','C:\Program Files\Elastic\beats')
        Processes = @('elastic-agent','filebeat','winlogbeat','metricbeat')
    }
    @{
        Name      = 'Tenable Nessus Agent'
        Category  = 'SIEM'
        Services  = @('Tenable Nessus Agent','NessusAgent')
        RegKeys   = @('HKLM:\SOFTWARE\Tenable\Nessus Agent')
        Paths     = @('C:\Program Files\Tenable\Nessus Agent\nessus-agent.exe')
        Processes = @('nessus-agent','nessusd')
    }
    @{
        Name      = 'Rapid7 Insight Agent'
        Category  = 'SIEM'
        Services  = @('ir_agent')
        RegKeys   = @('HKLM:\SOFTWARE\Rapid7\Insight Agent')
        Paths     = @('C:\Program Files\Rapid7\Insight Agent\ir_agent.exe')
        Processes = @('ir_agent')
    }
    @{
        Name      = 'Wazuh Agent'
        Category  = 'SIEM'
        Services  = @('WazuhSvc','OssecSvc')
        RegKeys   = @('HKLM:\SOFTWARE\Wazuh','HKLM:\SOFTWARE\ossec')
        Paths     = @('C:\Program Files (x86)\ossec-agent\ossec-agent.exe','C:\Program Files\ossec-agent')
        Processes = @('wazuh-agent','ossec-agent')
    }
    @{
        Name      = 'Qualys Cloud Agent'
        Category  = 'SIEM'
        Services  = @('QualysAgent')
        RegKeys   = @('HKLM:\SOFTWARE\Qualys\QualysAgent')
        Paths     = @('C:\Program Files (x86)\Qualys\QualysAgent\QualysAgent.exe')
        Processes = @('QualysAgent')
    }
    @{
        Name      = 'Datadog Agent'
        Category  = 'SIEM'
        Services  = @('DatadogAgent')
        RegKeys   = @('HKLM:\SOFTWARE\Datadog\Datadog Agent')
        Paths     = @('C:\Program Files\Datadog\Datadog Agent\bin\agent.exe')
        Processes = @('agent','trace-agent','process-agent')
    }

    # ── DLP ───────────────────────────────────────────────────────────────────
    @{
        Name      = 'Broadcom / Symantec DLP'
        Category  = 'DLP'
        Services  = @('edpa','vontu','VontuMonitor')
        RegKeys   = @('HKLM:\SOFTWARE\Symantec\Symantec Data Loss Prevention','HKLM:\SOFTWARE\Vontu')
        Paths     = @('C:\Program Files\Manufacturer\Symantec DLP','C:\Program Files\Vontu')
        Processes = @('edpa','vontumonitor')
    }
    @{
        Name      = 'Digital Guardian Agent'
        Category  = 'DLP'
        Services  = @('DgService','DigitalGuardianService')
        RegKeys   = @('HKLM:\SOFTWARE\Verdasys','HKLM:\SOFTWARE\Digital Guardian')
        Paths     = @('C:\Program Files\Digital Guardian\Agent')
        Processes = @('DgService')
    }
    @{
        Name      = 'CoSoSys Endpoint Protector'
        Category  = 'DLP'
        Services  = @('EppService','EPPService')
        RegKeys   = @('HKLM:\SOFTWARE\CoSoSys\Endpoint Protector')
        Paths     = @('C:\Program Files\CoSoSys\Endpoint Protector')
        Processes = @('EPPService')
    }
    @{
        Name      = 'Forcepoint DLP Endpoint'
        Category  = 'DLP'
        Services  = @('EIPService','fpeca')
        RegKeys   = @('HKLM:\SOFTWARE\Websense\Websense Endpoint','HKLM:\SOFTWARE\Forcepoint\DLP')
        Paths     = @('C:\Program Files (x86)\Websense\Websense Endpoint')
        Processes = @('EIPService','fpeca')
    }

    # ── Identity / MFA ────────────────────────────────────────────────────────
    @{
        Name      = 'Okta Verify'
        Category  = 'Identity'
        Services  = @('OktaVerifyService','OktaService')
        RegKeys   = @('HKLM:\SOFTWARE\Okta\Okta Verify')
        Paths     = @('C:\Program Files\Okta\Okta Verify')
        Processes = @('OktaVerify')
    }
    @{
        Name      = 'Duo Device Health'
        Category  = 'Identity'
        Services  = @('DuoDeviceHealth')
        RegKeys   = @('HKLM:\SOFTWARE\Duo Security\DuoDeviceHealth')
        Paths     = @('C:\Program Files\Duo Security\DuoDeviceHealth\DuoDeviceHealth.exe')
        Processes = @('DuoDeviceHealth')
    }
    @{
        Name      = 'Microsoft Authenticator (AAD MFA)'
        Category  = 'Identity'
        Services  = @()
        RegKeys   = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8AF662BF-65A0-4D0A-A540-A338A999D36F}')
        Paths     = @()
        Processes = @()
    }
)

# ── Detection Logic ───────────────────────────────────────────────────────────
$detected = [System.Collections.Generic.List[hashtable]]::new()

# Pre-fetch all services and processes once (faster than per-tool queries)
$allServices = @{}
try {
    Get-Service -ErrorAction SilentlyContinue | ForEach-Object { $allServices[$_.Name.ToLower()] = $_ }
} catch {}

$allProcesses = @{}
try {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not $allProcesses.ContainsKey($_.Name.ToLower())) {
            $allProcesses[$_.Name.ToLower()] = $_
        }
    }
} catch {}

foreach ($tool in $toolDb) {
    $detectedBy = $null
    $indicator  = $null
    $status     = 'installed'
    $version    = $null

    # 1. Services (most reliable: installed + status)
    foreach ($svcName in $tool.Services) {
        $s = $allServices[$svcName.ToLower()]
        if ($s) {
            $detectedBy = 'service'
            $indicator  = $svcName
            $status     = if ($s.Status -eq 'Running') { 'running' } else { $s.Status.ToString().ToLower() }
            try {
                $imgPath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)" -ErrorAction SilentlyContinue).ImagePath
                if ($imgPath) {
                    $exe = $imgPath -replace '^"?([^"]+\.exe).*', '$1'
                    if (Test-Path $exe) {
                        $fi = (Get-Item $exe -ErrorAction SilentlyContinue).VersionInfo
                        if ($fi -and $fi.FileVersion) { $version = $fi.FileVersion }
                    }
                }
            } catch {}
            break
        }
    }

    # 2. Registry (indicates installation even if service not present)
    if (-not $detectedBy) {
        foreach ($rk in $tool.RegKeys) {
            if (Test-Path $rk) {
                $detectedBy = 'registry'
                $indicator  = $rk
                break
            }
        }
    }

    # 3. File path
    if (-not $detectedBy) {
        foreach ($fp in $tool.Paths) {
            if (Test-Path $fp) {
                $detectedBy = 'file'
                $indicator  = $fp
                try {
                    if ($fp -like '*.exe') {
                        $fi = (Get-Item $fp -ErrorAction SilentlyContinue).VersionInfo
                        if ($fi -and $fi.FileVersion) { $version = $fi.FileVersion }
                    }
                } catch {}
                break
            }
        }
    }

    # 4. Process (transient, but positive signal if running)
    if (-not $detectedBy) {
        foreach ($procName in $tool.Processes) {
            $p = $allProcesses[$procName.ToLower()]
            if ($p) {
                $detectedBy = 'process'
                $indicator  = $procName
                $status     = 'running'
                break
            }
        }
    }

    if ($detectedBy) {
        $detected.Add(@{
            name        = $tool.Name
            category    = $tool.Category
            detected_by = $detectedBy
            indicator   = $indicator
            status      = $status
            version     = $version
        })
    }
}

@{ security_agents = @($detected | Sort-Object { $_['category'] }, { $_['name'] }) } | ConvertTo-Json -Depth 3

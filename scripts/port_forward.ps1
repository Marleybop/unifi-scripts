<#
UniFi Network – Create Port Forward (NAT) Rule via API
-----------------------------------------------------
• PowerShell 7+ compatible
• UniFi OS (443) and legacy controller (8443) supported
• Configuration lives at the top of the file

Edit only the USER CONFIGURATION section.
#>

# ============================
# USER CONFIGURATION
# ============================

# UniFi controller
$ConsoleHost   = "x.x.x.x"      # IP or DNS of UniFi console
$UseUnifiOS    = $true           # $true = UniFi OS (443), $false = legacy controller (8443)
$Site          = "default"       # UniFi site name

# Credentials (leave blank to be prompted)
$Username      = "legacyapi"
$Password      = "Marmite2025!"              # Plaintext is supported; prompting is recommended

# Port forward rule
$RuleName      = "Name of Rule"

# Source restriction (internet side)
$SourceIp      = "any"           # "any", single IP, or CIDR (e.g. 203.0.113.0/24)

# WAN interface
# • "wan" / "wan2"  = specific WAN
# • "all"           = all WANs (matches GUI behaviour in your HAR)
$WanInterface  = "all"           # wan | wan2 | all
$AllWanList    = @("wan","wan2") # used only when $WanInterface = "all"

# Protocol
$Protocol      = "tcp"           # tcp | udp | tcp_udp

# Ports
$WanPort       = "xxxx"          # External/WAN port (or "start-end")
$ForwardPort   = "xxxx"          # Internal port (or "start-end")

# Internal destination
$ForwardIp     = "x.x.x.x"

# Rule behaviour
$EnableRule    = $true
$EnableLogging = $true           # Enables UniFi rule logging (not syslog export)
$Debug         = $true           # Prints auth and CSRF diagnostics

# TLS handling
$SkipCertCheck = $true           # Required for self-signed UniFi certs

# ============================
# DO NOT EDIT BELOW
# ============================

$ErrorActionPreference = "Stop"

if ($SkipCertCheck) {
    $PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
}

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

function Get-CookiesForUrl {
    param([string]$Url)
    try { $session.Cookies.GetCookies([Uri]$Url) } catch { @() }
}

function Get-UniFiCsrfToken {
    param($LoginResponse, $BaseUrl)

    if ($LoginResponse.Headers["X-CSRF-Token"]) {
        return $LoginResponse.Headers["X-CSRF-Token"]
    }

    foreach ($c in (Get-CookiesForUrl $BaseUrl)) {
        if ($c.Name -match 'csrf') { return $c.Value }
    }

    return $null
}

function Invoke-UniFiJson {
    param(
        [ValidateSet("GET","POST","PUT","DELETE")] [string]$Method,
        [string]$Url,
        [object]$Body = $null,
        [hashtable]$Headers = @{}
    )

    $params = @{
        Method      = $Method
        Uri         = $Url
        WebSession  = $session
        Headers     = $Headers
        ContentType = "application/json"
    }

    if ($null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 20 -Compress)
    }

    try {
        $resp = Invoke-WebRequest @params
    } catch {
        $status = $null
        $respBody = $null
        try { $status = $_.Exception.Response.StatusCode.value__ } catch { }
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            $respBody = (New-Object IO.StreamReader($stream)).ReadToEnd()
        } catch { }
        $msg = "HTTP $Method $Url failed"
        if ($status)   { $msg += " ($status)" }
        if ($respBody) { $msg += "`n$respBody" }
        throw $msg
    }

    if (-not $resp.Content) { return $null }
    return $resp.Content | ConvertFrom-Json
}

# Build controller URLs
if ($UseUnifiOS) {
    $BaseUrl  = "https://$ConsoleHost"
    $LoginUrl = "$BaseUrl/api/auth/login"
    $PfUrl    = "$BaseUrl/proxy/network/api/s/$Site/rest/portforward"
    $SelfUrl  = "$BaseUrl/proxy/network/api/self"
} else {
    $BaseUrl  = "https://$ConsoleHost`:8443"
    $LoginUrl = "$BaseUrl/api/login"
    $PfUrl    = "$BaseUrl/api/s/$Site/rest/portforward"
    $SelfUrl  = "$BaseUrl/api/self"
}

# Prompt for credentials if not set
if ([string]::IsNullOrWhiteSpace($Username)) {
    $Username = Read-Host -Prompt "UniFi Username"
}
if ([string]::IsNullOrWhiteSpace($Password)) {
    $sec = Read-Host -Prompt "UniFi Password" -AsSecureString
    $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    )
}

# Authenticate (cookies stored in session)
$loginResp = Invoke-WebRequest `
    -Method POST `
    -Uri $LoginUrl `
    -WebSession $session `
    -ContentType "application/json" `
    -Body (@{ username=$Username; password=$Password } | ConvertTo-Json -Compress)

# Headers expected by UniFi Network app
$headers = @{
    Origin  = $BaseUrl
    Referer = "$BaseUrl/"
    Accept  = "application/json"
}

# CSRF token (if required)
$csrf = Get-UniFiCsrfToken $loginResp $BaseUrl
if ($csrf) { $headers["X-CSRF-Token"] = $csrf }

# Debug output
if ($Debug) {
    Write-Host "Login status:" $loginResp.StatusCode
    $cookieNames = (Get-CookiesForUrl $BaseUrl | ForEach-Object Name | Sort-Object -Unique)
    Write-Host "Cookies:" ($cookieNames -join ", ")
    Write-Host "CSRF token present:" ([bool]$csrf)
}

# Sanity check – confirms Network app access
if ($Debug) {
    $self = Invoke-UniFiJson GET $SelfUrl $null $headers
    if ($self?.data?.email) { Write-Host "Authenticated as:" $self.data.email }
}

# Build destination_ips (GUI-style for "all")
$destinationIps = @()
if ($WanInterface -eq "all") {
    foreach ($wan in $AllWanList) {
        $destinationIps += @{ interface = $wan; destination_ip = $SourceIp }
    }
}

# Create port forward payload
# • When $WanInterface = "all": send pfwd_interface="all" + destination_ips[] (matches your HAR)
# • When $WanInterface = "wan"/"wan2": send destination_ip + empty destination_ips
$payload = @{
    enabled              = [bool]$EnableRule
    name                 = $RuleName
    pfwd_interface       = $WanInterface
    dst_port             = "$WanPort"
    fwd                  = $ForwardIp
    fwd_port             = "$ForwardPort"
    proto                = $Protocol
    src_limiting_enabled = $false
    log                  = [bool]$EnableLogging
}

if ($WanInterface -eq "all") {
    $payload.destination_ips = $destinationIps
} else {
    $payload.destination_ip  = $SourceIp
    $payload.destination_ips = @()
}

# Submit rule
$result = Invoke-UniFiJson POST $PfUrl $payload $headers

if (-not $result -or $result.meta.rc -ne "ok") {
    throw "Port forward creation failed:`n$($result | ConvertTo-Json -Depth 20)"
}

# Output result
$rule = $result.data[0]
Write-Host "Port forward created:"
$rule | Select-Object `
    name,
    _id,
    proto,
    dst_port,
    fwd,
    fwd_port,
    pfwd_interface,
    destination_ip,
    destination_ips,
    enabled,
    log |
Format-List

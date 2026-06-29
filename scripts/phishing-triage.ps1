<#
.SYNOPSIS
    Phishing email triage helper — extracts the actionable elements from an .eml file.

.DESCRIPTION
    Runs the first-pass structural sweep a SOC analyst performs on a suspicious email:
    links, image/tracker sources, raw URLs, and attachment flags. Optionally produces a
    sanitized HTML render of the body with tracking pixels neutralized.

    Searches for STRUCTURE (href=, src=, https://), never for specific wording — so it
    works on any email regardless of brand, language, or button text.

.PARAMETER Sample
    Path to the .eml file to analyze.

.PARAMETER SafeRender
    If set, writes a sanitized lure.html (tracking pixels removed) next to the sample.

.EXAMPLE
    .\phishing-triage.ps1 -Sample .\sample-10.eml
    .\phishing-triage.ps1 -Sample .\sample-12.eml -SafeRender

.NOTES
    SOC Detection Series — Lab 5 (Phishing & Email Analysis). Personal lab.
    Windows 11 / PowerShell. Author: Sean White.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Sample,

    [switch]$SafeRender
)

if (-not (Test-Path $Sample)) {
    Write-Error "Sample not found: $Sample"
    exit 1
}

function Write-Section($title) {
    Write-Host ""
    Write-Host ("=" * 64) -ForegroundColor DarkCyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host ("=" * 64) -ForegroundColor DarkCyan
}

# --- 1. LINKS -----------------------------------------------------------------
# Every clickable destination. [^"]* = any run of non-quote chars; -AllMatches
# catches multiple links per line; $_.Matches.Value unwraps to plain text.
Write-Section "HREF links (clicks / mailto)"
Select-String -Path $Sample -Pattern 'href="[^"]*"' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# --- 2. IMAGE / TRACKER SOURCES ----------------------------------------------
# src= catches remote images and 1x1 tracking pixels that href= would miss.
Write-Section "SRC sources (images / tracking pixels)"
Select-String -Path $Sample -Pattern 'src="[^"]*"' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# --- 3. RAW URLS --------------------------------------------------------------
# Plain-text URLs with no HTML wrapper (common in plain-text phishing).
Write-Section "Raw URLs (unwrapped http/https)"
Select-String -Path $Sample -Pattern 'https?://\S+' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# --- 4. ATTACHMENTS -----------------------------------------------------------
# The other half of T1566 — spearphishing attachment.
Write-Section "Attachment indicators"
$att = Select-String -Path $Sample -Pattern 'Content-Disposition:\s*attachment'
if ($att) { $att } else { Write-Host "  (none found)" -ForegroundColor DarkGray }

# --- 5. KEY HEADERS -----------------------------------------------------------
# Pull the fields that carry the auth verdict and sender story. -Encoding UTF8
# avoids mojibake (garbled accented characters from codepage mismatches).
Write-Section "Key headers (auth + sender)"
Get-Content $Sample -Encoding UTF8 |
    Select-String -Pattern '^(Authentication-Results|Received-SPF|From|Reply-To|Return-Path|Subject):' |
    ForEach-Object { $_.Line }

# --- 6. OPTIONAL: SAFE RENDER -------------------------------------------------
# Strips tracking pixels BEFORE writing an HTML the analyst can open in a browser.
# Works on a copy; never touches the original evidence file.
if ($SafeRender) {
    Write-Section "Safe render -> lure.html (tracking pixels removed)"
    $dir  = Split-Path -Parent (Resolve-Path $Sample)
    $copy = Join-Path $dir "_working.eml"
    Copy-Item $Sample $copy -Force

    $raw  = Get-Content $copy -Raw -Encoding UTF8
    $body = ($raw -split "`r`n`r`n", 2)[1]
    if (-not $body) { $body = ($raw -split "`n`n", 2)[1] }   # fallback for LF-only files

    $bodySafe = $body -replace '<img[^>]*track[^>]*>', '<!-- tracking pixel removed for safe viewing -->'
    $out = Join-Path $dir "lure.html"
    Set-Content -Path $out -Value $bodySafe -Encoding UTF8

    Remove-Item $copy -Force
    Write-Host "  Wrote: $out" -ForegroundColor Green
    Write-Host "  Open it manually in a browser; the beacon has been neutralized." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Triage complete. Submit any extracted URLs to VirusTotal (URL tab) — never visit them directly." -ForegroundColor Yellow

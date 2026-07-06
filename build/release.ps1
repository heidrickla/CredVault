<#
.SYNOPSIS
    Builds, signs, and packages a CredVault release.

.DESCRIPTION
    Pipeline: dotnet publish (self-contained single-file win-x64)
              -> Authenticode-sign the exe (cert looked up by thumbprint in
                 CurrentUser\My; skipped with a warning if not present, so
                 anyone can still produce an unsigned build)
              -> zip + SHA-256 into .\dist\

    The default thumbprint is the "Lewis Heidrick Code Signing" certificate
    issued by the UCM Homelab Root CA (UCM cert id 10). A thumbprint is
    public information - the private key lives only in the Windows cert
    store (DPAPI) and in UCM.

.EXAMPLE
    .\build\release.ps1 -Version v1.0.1
#>
param(
    [string]$Version = "dev",
    [string]$CertThumbprint = "6A90D69C7414AA29D7FECD23E8806C06CCE4DFA3",
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$publishDir = Join-Path $root "CredVault\bin\Release\net10.0-windows\win-x64\publish"
$distDir = Join-Path $root "dist"

Write-Host "== publish =="
dotnet publish (Join-Path $root "CredVault\CredVault.csproj") -c Release -r win-x64 `
    --self-contained -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
if ($LASTEXITCODE -ne 0) { throw "publish failed" }

$exe = Join-Path $publishDir "CredVault.exe"
if (-not (Test-Path $exe)) { throw "publish output not found: $exe" }

Write-Host "== sign =="
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq $CertThumbprint
if ($cert) {
    $sig = Set-AuthenticodeSignature -FilePath $exe -Certificate $cert `
        -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    if ($sig.Status -ne "Valid") { throw "signing failed: $($sig.Status) - $($sig.StatusMessage)" }
    Write-Host "signed: $($sig.SignerCertificate.Subject)"
} else {
    Write-Warning "code-signing cert $CertThumbprint not in CurrentUser\My - producing UNSIGNED build"
}

Write-Host "== package =="
New-Item -ItemType Directory -Force $distDir | Out-Null
$zip = Join-Path $distDir "CredVault-$Version-win-x64.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $exe -DestinationPath $zip
$sha = (Get-FileHash $zip -Algorithm SHA256).Hash
$sha | Out-File "$zip.sha256" -NoNewline

Write-Host "artifact: $zip ($([math]::Round((Get-Item $zip).Length/1MB,1)) MB)"
Write-Host "sha256:   $sha"

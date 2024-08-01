param (
    [Parameter(Mandatory=$true)]

    # client id
    [string]$ClientId,
    [string]$TenantId,
    [string]$UserPrincipalName,
    [string]$OutputDir
)

Write-Output "Starting office365 scan..."
$CertificateThumbprint = $Env:CERTIFICATE_THUMBPRINT
$Organization = $UserPrincipalName.Split("@")[-1]


# Connect to exchange online 
Connect-ExchangeOnline -CertificateThumbPrint $CertificateThumbprint  -AppID $ClientId -Organization "crosslaketestlabs.com"

# Connect to Microsoft Graph 
Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint

cd C://app//inspect
.\365Inspect.ps1 -OutPath $OutputDir -UserPrincipalName $UserPrincipalName -Auth ALREADY_AUTHED

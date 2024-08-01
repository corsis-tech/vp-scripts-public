param (
    [Parameter(Mandatory=$true)]

    # client id
    [string]$ClientId,
    [string]$TenantId,
    [string]$UserPrincipalName,
    [string]$CertificateThumbprint,
    [string]$OutputDir
)

$path = "./365Inspect"
If(!(test-path -PathType container $path))
{
      git clone https://github.com/soteria-security/365Inspect.git $path
}

Write-Output "Starting office365 scan..."
$Organization = $UserPrincipalName.Split("@")[-1]


# Connect to exchange online 
Connect-ExchangeOnline -CertificateThumbPrint $CertificateThumbprint  -AppID $ClientId -Organization $Organization

# Connect to Microsoft Graph 
Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint

cd $path
.\365Inspect.ps1 -OutPath $OutputDir -UserPrincipalName $UserPrincipalName -Auth ALREADY_AUTHED

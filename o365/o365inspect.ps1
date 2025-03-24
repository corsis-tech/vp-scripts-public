param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType 'Container' })]
    [string]$OutputDir
)

# Required modules
$requiredModules = @(
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Identity.Governance',
    'ExchangeOnlineManagement'
)

foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Output "Installing $module..."
        try {
            Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to install module ${module}: $_"
            exit 1
        }
    }
    Import-Module $module
}

# Check if git is installed
if (!(Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "Git is not installed. Please install git and try again."
    exit 1
}

# Clone 365Inspect if not exists
$path = "./365Inspect"
if (!(Test-Path -PathType Container $path)) {
    Write-Output "Cloning 365Inspect repository..."
    try {
        git clone https://github.com/soteria-security/365Inspect.git $path
    }
    catch {
        Write-Error "Failed to clone 365Inspect repository: $_"
        exit 1
    }
}

# Create self-signed certificate
function New-SelfSignedCertificateWithPrivateKey {
    $certName = "365InspectCert-$(Get-Random)"
    try {
        $cert = New-SelfSignedCertificate -Subject "CN=$certName" -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA `
            -HashAlgorithm SHA256 -NotAfter (Get-Date).AddMonths(12) -ErrorAction Stop
        return $cert
    }
    catch {
        Write-Error "Failed to create self-signed certificate: $_"
        exit 1
    }
}

# Convert hex string to byte array
function ConvertFrom-HexString {
    param (
        [string]$HexString
    )
    try {
        $Bytes = [byte[]]::new($HexString.Length / 2)
        for ($i = 0; $i -lt $HexString.Length; $i += 2) {
            $Bytes[$i / 2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
        }
        return $Bytes
    }
    catch {
        Write-Error "Failed to convert hex string to byte array: $_"
        exit 1
    }
}

# Get permission IDs
function Get-PermissionIds {
    # Microsoft Graph Resource ID
    $graphResourceId = "00000003-0000-0000-c000-000000000000"
    # Exchange Online Resource ID
    $exchangeResourceId = "00000002-0000-0ff1-ce00-000000000000"
    
    $permissionsList = @()
    
    # Get Graph service principal
    try {
        $graphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$graphResourceId'" -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to get Microsoft Graph service principal: $_"
        exit 1
    }
    $graphPermissions = $graphServicePrincipal.AppRoles
    
    # Get Exchange Online service principal
    try {
        $exchangeServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$exchangeResourceId'" -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to get Exchange Online service principal: $_"
        exit 1
    }
    $exchangePermissions = $exchangeServicePrincipal.AppRoles
    
    # List of required Graph permissions (ensure this list is up-to-date for 365Inspect)
    $requiredGraphPermissions = @(
        'User.Read.All', 'Calendars.Read', 'Mail.Read', 'Contacts.Read', 'TeamMember.Read.All',
        'Place.Read.All', 'Chat.UpdatePolicyViolation.All', 'Policy.Read.ConditionalAccess',
        'AppCatalog.Read.All', 'TeamsAppInstallation.ReadForUser.All', 'eDiscovery.Read.All',
        'UserShiftPreferences.Read.All', 'CustomSecAttributeDefinition.Read.All', 'AgreementAcceptance.Read.All',
        'ExternalConnection.Read.All', 'EduRoster.Read.All', 'ServicePrincipalEndpoint.Read.All',
        'CloudPC.Read.All', 'DeviceManagementManagedDevices.Read.All', 'OnlineMeetings.Read.All',
        'Device.Read.All', 'TeamsTab.Read.All', 'DelegatedAdminRelationship.Read.All',
        'UserAuthenticationMethod.Read.All', 'TeamsActivity.Read.All', 'Printer.Read.All',
        'OrgContact.Read.All', 'TeamsAppInstallation.ReadForChat.All', 'Policy.Read.PermissionGrant',
        'OnlineMeetingArtifact.Read.All', 'SharePointTenantSettings.Read.All', 'ChannelSettings.Read.All',
        'SecurityEvents.Read.All', 'DelegatedPermissionGrant.ReadWrite.All', 'OnlineMeetingRecording.Read.All',
        'IdentityRiskyServicePrincipal.Read.All', 'CrossTenantUserProfileSharing.Read.All',
        'Mail.ReadBasic.All', 'PrivilegedAccess.Read.AzureAD', 'RoleManagement.Read.Directory',
        'Channel.ReadBasic.All', 'People.Read.All', 'SecurityAlert.Read.All', 'Group.Read.All',
        'AdministrativeUnit.Read.All', 'MailboxSettings.Read', 'CrossTenantInformation.ReadBasic.All',
        'EduAdministration.Read.All', 'Sites.Read.All', 'PrintJob.Read.All',
        'DeviceManagementServiceConfig.Read.All', 'ServiceMessage.Read.All', 'PrintSettings.Read.All',
        'DirectoryRecommendations.Read.All', 'Notes.Read.All', 'EntitlementManagement.Read.All',
        'CallRecords.Read.All', 'IdentityUserFlow.Read.All', 'ChatMessage.Read.All',
        'Directory.Read.All', 'ConsentRequest.Read.All', 'RoleManagement.Read.All',
        'CallRecord-PstnCalls.Read.All', 'PrivilegedAccess.Read.AzureResources', 'Domain.Read.All',
        'EduAssignments.ReadBasic.All', 'EduRoster.ReadBasic.All', 'Agreement.Read.All',
        'OnlineMeetingTranscript.Read.All', 'ChannelMember.Read.All', 'Schedule.Read.All',
        'SecurityIncident.Read.All', 'GroupMember.Read.All', 'DeviceManagementRBAC.Read.All',
        'RoleManagement.Read.CloudPC', 'Files.Read.All', 'CustomSecAttributeAssignment.Read.All',
        'SearchConfiguration.Read.All', 'DeviceManagementConfiguration.Read.All', 'Team.ReadBasic.All',
        'APIConnectors.Read.All', 'Chat.Read.All', 'ExternalItem.Read.All', 'ChannelMessage.Read.All',
        'EduAssignments.Read.All', 'SecurityActions.Read.All', 'ThreatAssessment.Read.All',
        'IdentityProvider.Read.All', 'TeamSettings.Read.All', 'IdentityRiskyUser.Read.All',
        'AccessReview.Read.All', 'LicenseAssignment.ReadWrite.All', 'TermStore.Read.All',
        'TeamworkTag.Read.All', 'PrivilegedAccess.Read.AzureADGroup', 'InformationProtectionPolicy.Read.All',
        'Organization.Read.All', 'IdentityRiskEvent.Read.All', 'Mail.ReadBasic', 'AuditLog.Read.All',
        'Policy.Read.All', 'Policy.ReadWrite.CrossTenantAccess', 'Member.Read.Hidden',
        'Chat.ReadBasic.All', 'Application.Read.All', 'ProgramControl.Read.All', 'ServiceHealth.Read.All',
        'ChatMember.Read.All', 'DeviceManagementApps.Read.All', 'ThreatIndicators.Read.All',
        'TeamsAppInstallation.ReadForTeam.All', 'ShortNotes.Read.All', 'Reports.Read.All',
        'PrintJob.ReadBasic.All', 'TrustFrameworkKeySet.Read.All', 'ThreatHunting.Read.All',
        'TeamworkDevice.Read.All', 'Synchronization.Read.All', 'AuthenticationContext.Read.All',
        'CustomAuthenticationExtension.Read.All', 'ThreatSubmission.Read.All', 'LifecycleWorkflows.Read.All',
        'ReportSettings.Read.All', 'RecordsManagement.Read.All', 'RoleManagementAlert.Read.Directory'
    )

    # Add Graph permissions
    $graphPermissionIds = @()
    foreach ($permissionName in $requiredGraphPermissions) {
        $permission = $graphPermissions | Where-Object { $_.Value -eq $permissionName }
        if ($permission) {
            $graphPermissionIds += @{
                "id"   = $permission.Id
                "type" = "Role"
            }
        }
        else {
            Write-Warning "Graph permission not found: $permissionName"
        }
    }

    # Add Exchange permission
    $exchangePermission = $exchangePermissions | Where-Object { $_.Value -eq "Exchange.ManageAsApp" }
    if ($exchangePermission) {
        $permissionsList += @{
            "resourceAppId"  = $exchangeResourceId
            "resourceAccess" = @(
                @{
                    "id"   = $exchangePermission.Id
                    "type" = "Role"
                }
            )
        }
    }
    else {
        Write-Error "Required Exchange.ManageAsApp permission not found"
        exit 1
    }

    # Add Graph permissions to the list
    $permissionsList += @{
        "resourceAppId"  = $graphResourceId
        "resourceAccess" = $graphPermissionIds
    }

    return $permissionsList
}

# Create Azure AD application
function New-AzureADApplication {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # Get required permissions
    $requiredResourceAccess = Get-PermissionIds

    # Create new application
    $displayName = "365Inspect-Automation-$(Get-Random)"
    try {
        $app = New-MgApplication -DisplayName $displayName `
            -SignInAudience "AzureADMyOrg" `
            -RequiredResourceAccess $requiredResourceAccess -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to create Azure AD application: $_"
        exit 1
    }

    try {
        $thumbprintBytes = ConvertFrom-HexString -HexString $Certificate.Thumbprint

        # Create a key credential object
        $keyCredential = New-Object -TypeName Microsoft.Graph.PowerShell.Models.MicrosoftGraphKeyCredential
        $keyCredential.CustomKeyIdentifier = $thumbprintBytes
        $keyCredential.Type = "AsymmetricX509Cert"
        $keyCredential.Usage = "Verify"
        $keyCredential.Key = $Certificate.RawData
        $keyCredential.StartDateTime = $Certificate.NotBefore
        $keyCredential.EndDateTime = $Certificate.NotAfter
        $keyCredential.DisplayName = "CN=$($Certificate.Subject)"

        Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential) -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to add certificate to application: $_"
        exit 1
    }

    return $app
}

try {
    Write-Output "Starting 365Inspect setup..."

    # Connect to Microsoft Graph with interactive login
    try {
        Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory" -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }
    $context = Get-MgContext
    $tenantId = $context.TenantId
    
    # Create certificate
    Write-Output "Creating self-signed certificate..."
    $cert = New-SelfSignedCertificateWithPrivateKey
    $certThumbprint = $cert.Thumbprint
    
    # Create Azure AD application
    Write-Output "Creating Azure AD application..."
    $app = New-AzureADApplication -Certificate $cert
    $clientId = $app.AppId

    # Create service principal for the application
    Write-Output "Creating service principal..."
    try {
        $sp = New-MgServicePrincipal -AppId $clientId -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to create service principal: $_"
        exit 1
    }

    # Get Exchange Online service principal
    try {
        $exchangeSp = Get-MgServicePrincipal -Filter "appId eq '00000002-0000-0ff1-ce00-000000000000'" -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to get Exchange Online service principal: $_"
        exit 1
    }
    $exchangeSpId = $exchangeSp.Id
    
    # Get the Exchange.ManageAsApp role
    $exchangeRole = $exchangeSp.AppRoles | Where-Object { $_.Value -eq "Exchange.ManageAsApp" }
    if ($null -eq $exchangeRole) {
        Write-Error "Exchange.ManageAsApp role not found"
        exit 1
    }

    # Assign Exchange.ManageAsApp role to the application
    Write-Output "Assigning Exchange.ManageAsApp role..."
    try {
        $params = @{
            PrincipalId = $sp.Id
            ResourceId  = $exchangeSpId
            AppRoleId   = $exchangeRole.Id
        }
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -BodyParameter $params -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to assign Exchange.ManageAsApp role: $_"
        exit 1
    }

    # Assign Exchange Administrator role
    Write-Output "Assigning Exchange Administrator role..."
    
    # Get Exchange Administrator role template
    try {
        $exchangeAdminRoleTemplate = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq 'Exchange Administrator' } -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to get Exchange Administrator role template: $_"
        exit 1
    }
    
    # Check if the role is already activated
    $exchangeAdminRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq '$($exchangeAdminRoleTemplate.Id)'" -ErrorAction SilentlyContinue
    if ($null -eq $exchangeAdminRole) {
        # Activate the role
        try {
            $exchangeAdminRole = New-MgDirectoryRole -RoleTemplateId $exchangeAdminRoleTemplate.Id -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to activate Exchange Administrator role: $_"
            exit 1
        }
    }

    # Create role assignment
    try {
        $roleAssignmentParams = @{
            "@odata.type"     = "#microsoft.graph.unifiedRoleAssignment"
            RoleDefinitionId  = $exchangeAdminRoleTemplate.Id
            PrincipalId       = $sp.Id
            DirectoryScopeId  = "/"
        }
        New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $roleAssignmentParams -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to assign Exchange Administrator role: $_"
        exit 1
    }

    # Get user information
    try {
        $user = Get-MgUser -Filter "userPrincipalName eq '$($context.Account)'" -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to get user information: $_"
        exit 1
    }
    $userPrincipalName = $user.UserPrincipalName
    $organization = $userPrincipalName.Split("@")[-1]

    Write-Output "Waiting for Azure AD application and permissions to propagate..."
    Start-Sleep -Seconds 60

    Write-Output "IMPORTANT: Please visit https://entra.microsoft.com/. Then Applications > App registrations > All Applications. And grant admin consent for the application (under API permissions) in the Azure Portal."
    Write-Output "Application ID: $clientId"
    Write-Output "Press Enter once admin consent has been granted..."
    Read-Host

    # Connect to required services
    Write-Output "Connecting to Exchange Online..."
    try {
        Connect-ExchangeOnline -CertificateThumbPrint $certThumbprint -AppID $clientId -Organization $organization -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to connect to Exchange Online: $_"
        exit 1
    }

    Write-Output "Connecting to Microsoft Graph..."
    try {
        Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $certThumbprint -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }

    # Run 365Inspect
    Write-Output "Starting 365Inspect scan..."
    Set-Location $path
    .\365Inspect.ps1 -OutPath $OutputDir -UserPrincipalName $userPrincipalName -Auth ALREADY_AUTHED

}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
finally {
    # Cleanup
    Write-Output "Cleaning up resources..."
    
    # Get and remove role assignments
    Write-Output "Removing role assignments..."
    try {
        $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($sp.Id)'" -ErrorAction SilentlyContinue
        foreach ($assignment in $roleAssignments) {
            Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignment.Id -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Warning "Failed to remove role assignments: $_"
    }
    
    # Disconnect from services
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    
    # Remove Azure AD application and service principal
    if ($sp) {
        try {
            Remove-MgServicePrincipal -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Failed to remove service principal: $_"
        }
    }
    if ($app) {
        try {
            Remove-MgApplication -ApplicationId $app.Id -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Failed to remove application: $_"
        }
    }
    
    # Remove certificate
    if ($certThumbprint) {
        try {
            Get-ChildItem "Cert:\CurrentUser\My\$certThumbprint" | Remove-Item -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Failed to remove certificate: $_"
        }
    }
    
    # Return to original directory
    Set-Location ..
}

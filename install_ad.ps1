# Install AD DS role if not already installed
if (-not (Get-WindowsFeature -Name AD-Domain-Services).Installed) {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
}

# Check if the server is already a domain controller
\$isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4

if (-not \$isDC) {
    # Configure AD DS
    Import-Module ADDSDeployment
    \$params = @{
        CreateDnsDelegation = \$false
        DatabasePath = "C:\Windows\NTDS"
        DomainMode = "WinThreshold"
        DomainName = "$domainName"
        DomainNetbiosName = "${domainName%%.*}"
        ForestMode = "WinThreshold"
        InstallDns = \$true
        LogPath = "C:\Windows\NTDS"
        NoRebootOnCompletion = \$false
        SysvolPath = "C:\Windows\SYSVOL"
        Force = \$true
        SafeModeAdministratorPassword = (ConvertTo-SecureString "$adminPassword" -AsPlainText -Force)
    }
    
    try {
        Install-ADDSForest @params
        Write-Output "AD DS configured successfully. Server will reboot."
    } catch {
        Write-Output "Error configuring AD DS: \$(\$_.Exception.Message)"
        exit 1
    }
} else {
    Write-Output "Server is already a domain controller."
}

# Function to create OU if it doesn't exist
function Create-OUIfNotExists {
    param (
        [string]\$OUName,
        [string]\$Path
    )
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '\$OUName'" -SearchBase \$Path -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
        try {
            New-ADOrganizationalUnit -Name \$OUName -Path \$Path
            Write-Output "Created OU: \$OUName"
        } catch {
            Write-Output "Error creating OU \$OUName: \$(\$_.Exception.Message)"
        }
    } else {
        Write-Output "OU \$OUName already exists."
    }
}

# Create OUs
\$domainDN = "DC=" + (\$env:USERDNSDOMAIN -replace '\\.', ',DC=')
Create-OUIfNotExists -OUName "IT" -Path \$domainDN
Create-OUIfNotExists -OUName "Users" -Path \$domainDN
Create-OUIfNotExists -OUName "Groups" -Path \$domainDN
Create-OUIfNotExists -OUName "Computers" -Path \$domainDN

# Create admin user if it doesn't exist
\$adminUser = "adadmin"
if (-not (Get-ADUser -Filter "SamAccountName -eq '\$adminUser'" -ErrorAction SilentlyContinue)) {
    try {
        New-ADUser -Name \$adminUser `
                   -UserPrincipalName "\$adminUser@\$env:USERDNSDOMAIN" `
                   -SamAccountName \$adminUser `
                   -Path "OU=IT,\$domainDN" `
                   -AccountPassword (ConvertTo-SecureString "$adminPassword" -AsPlainText -Force) `
                   -Enabled \$true `
                   -PasswordNeverExpires \$true `
                   -ChangePasswordAtLogon \$false
        Write-Output "Created admin user: \$adminUser"

        # Add user to Domain Admins group
        Add-ADGroupMember -Identity "Domain Admins" -Members \$adminUser
        Write-Output "Added \$adminUser to Domain Admins group"
    } catch {
        Write-Output "Error creating admin user: \$(\$_.Exception.Message)"
    }
} else {
    Write-Output "Admin user \$adminUser already exists."
}

Write-Output "AD configuration completed."
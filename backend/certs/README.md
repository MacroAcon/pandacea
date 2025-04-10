# Certificate Management

This directory contains TLS certificates for secure communication.

## Directory Structure

- `public/` - Contains public certificates that can be committed to Git
- `private/` - Contains private keys and should NEVER be committed to Git

## Security Guidelines

1. **NEVER commit private keys to Git**
2. Private keys in the `private/` directory are ignored by Git (.gitignore)
3. For development, use the provided certificates
4. For production, replace with proper CA-signed certificates
5. Set the PANDACEA_CERT_PASSWORD environment variable for certificate passwords
6. Rotate certificates regularly

## Generating New Certificates

To generate a new certificate:

```powershell
# Set a secure password as an environment variable first
$env:PANDACEA_CERT_PASSWORD="your_secure_random_password"

# Generate a new self-signed certificate
$cert = New-SelfSignedCertificate -DnsName "pandacea.local" -CertStoreLocation "Cert:\CurrentUser\My" -KeyAlgorithm RSA -KeyLength 4096 -NotAfter (Get-Date).AddYears(2) -FriendlyName "Pandacea Certificate"

# Export the certificate with private key (PFX)
$pwd = ConvertTo-SecureString -String $env:PANDACEA_CERT_PASSWORD -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath backend\certs\private\pandacea.pfx -Password $pwd

# Export the public certificate
Export-Certificate -Cert $cert -FilePath backend\certs\public\pandacea.crt
```

## Certificate Rotation

Rotate certificates at least once a year or immediately if private keys are compromised. 
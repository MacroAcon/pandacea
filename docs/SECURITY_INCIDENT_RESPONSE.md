# Security Incident Response

This document outlines steps to take if you discover or suspect a security incident such as exposed credentials or keys.

## Immediate Actions

1. **Revoke Compromised Credentials**
   - Immediately revoke or rotate any exposed API keys, passwords, or secrets
   - Generate new certificates to replace any compromised ones

2. **Remove Sensitive Data**
   - Remove any sensitive data from the Git history using tools like `git-filter-repo`
   - Force push the cleaned history to all repositories

3. **Assess Impact**
   - Determine what systems may have been affected
   - Check access logs for suspicious activities
   - Review recent changes to sensitive systems

## Certificate Rotation Procedure

If you need to rotate certificates:

1. Set a new secure password in your environment variables:
   ```bash
   export PANDACEA_CERT_PASSWORD="new_secure_random_password"
   ```
   
2. Run the certificate generation script:
   ```bash
   cd backend/certs
   ./generate_certs.ps1  # For Windows
   # or
   bash generate_certs.sh  # For Linux/Mac
   ```

3. Update any systems using the old certificates

## Secret Management Best Practices

1. **Never commit secrets to Git**
   - Use environment variables for sensitive data
   - Store secrets in a vault service (HashiCorp Vault, AWS Secrets Manager, etc.)

2. **Use .gitignore properly**
   - Ensure private key directories and credential files are in .gitignore
   - Regularly audit that no secrets are committed

3. **Implement least privilege**
   - Only grant access to secrets to those who need them
   - Rotate credentials regularly 
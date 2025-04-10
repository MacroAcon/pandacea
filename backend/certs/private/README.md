# Private Certificate Directory

This directory is intended for private key files that should **NEVER** be committed to Git.

## Important Security Notes

1. All files in this directory (except this README) are ignored by Git
2. Private keys should be generated locally and never shared
3. Store your private keys here securely with proper permissions (chmod 600 on Linux/Mac)
4. For development, use the certificate generation script with your environment variables

## Using Private Keys

To generate new certificates:

1. Set the environment variable: `export PANDACEA_CERT_PASSWORD="your_secure_password"`
2. Run the certificate generation script from the parent directory

For production environments, consider using a secrets management solution like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault. 
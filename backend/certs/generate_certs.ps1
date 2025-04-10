# Generate self-signed certificates for Pandacea testing
Write-Host "Generating self-signed certificates for Pandacea testing..."

# Check for environment variable
if (-not [Environment]::GetEnvironmentVariable("PANDACEA_CERT_PASSWORD")) {
    Write-Host "ERROR: PANDACEA_CERT_PASSWORD environment variable not set" -ForegroundColor Red
    Write-Host "Please set a secure password with: `$env:PANDACEA_CERT_PASSWORD='your_secure_password'" -ForegroundColor Yellow
    exit 1
}

# Create directories if they don't exist
New-Item -ItemType Directory -Path "private" -Force | Out-Null
New-Item -ItemType Directory -Path "public" -Force | Out-Null

# Create a root CA
Write-Host "Creating root CA..."
openssl req -x509 -nodes -new -sha256 -days 365 -newkey rsa:4096 -keyout private/ca.key -out public/ca.pem -subj "/C=US/ST=CA/L=SanFrancisco/O=PandaceaCA/CN=pandacea-root-ca"

# Create server certificate
Write-Host "Creating server certificate..."
openssl req -new -nodes -newkey rsa:4096 -keyout private/server.key -out private/server.csr -subj "/C=US/ST=CA/L=SanFrancisco/O=Pandacea/CN=localhost"
openssl x509 -req -sha256 -days 365 -in private/server.csr -CA public/ca.pem -CAkey private/ca.key -CAcreateserial -out public/server.pem

# Create client certificate
Write-Host "Creating client certificate..."
openssl req -new -nodes -newkey rsa:4096 -keyout private/client.key -out private/client.csr -subj "/C=US/ST=CA/L=SanFrancisco/O=Pandacea/CN=pandacea-client"
openssl x509 -req -sha256 -days 365 -in private/client.csr -CA public/ca.pem -CAkey private/ca.key -CAcreateserial -out public/client.pem

# Copy the files to the expected locations
Copy-Item -Path "public/server.pem" -Destination "cert.pem" -Force

# Set permissions to ensure only the owner can read private keys
if ($IsLinux -or $IsMacOS) {
    chmod 600 private/*.key
}

Write-Host "Certificates generated successfully."
Write-Host "Files created:"
Write-Host "  - public/ca.pem, private/ca.key: Root CA certificate and key"
Write-Host "  - cert.pem: Server certificate used by default"
Write-Host "  - private/*.key: Private keys (NEVER commit these to Git)"
Write-Host ""
Write-Host "IMPORTANT: These are self-signed certificates for testing only."
Write-Host "           Ensure private keys are not committed to Git." 
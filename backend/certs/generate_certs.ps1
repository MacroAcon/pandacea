# Generate self-signed certificates for Pandacea testing
Write-Host "Generating self-signed certificates for Pandacea testing..."

# Create a root CA
Write-Host "Creating root CA..."
openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout ca.key -out ca.pem -subj "/C=US/ST=CA/L=SanFrancisco/O=PandaceaCA/CN=pandacea-root-ca"

# Create server certificate
Write-Host "Creating server certificate..."
openssl req -new -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj "/C=US/ST=CA/L=SanFrancisco/O=Pandacea/CN=localhost"
openssl x509 -req -sha256 -days 1024 -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem

# Create client certificate
Write-Host "Creating client certificate..."
openssl req -new -nodes -newkey rsa:2048 -keyout client.key -out client.csr -subj "/C=US/ST=CA/L=SanFrancisco/O=Pandacea/CN=pandacea-client"
openssl x509 -req -sha256 -days 1024 -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem

# Copy the files to the expected locations
Copy-Item -Path "server.pem" -Destination "cert.pem"
Copy-Item -Path "server.key" -Destination "key.pem"

Write-Host "Certificates generated successfully."
Write-Host "Files created:"
Write-Host "  - ca.pem, ca.key: Root CA certificate and key"
Write-Host "  - cert.pem, key.pem: Server certificate and key used by default"
Write-Host "  - client.pem, client.key: Client certificate and key"
Write-Host ""
Write-Host "Note: These are self-signed certificates for testing only." 
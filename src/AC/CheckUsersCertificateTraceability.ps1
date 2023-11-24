param (
    [string]$username
)

# Ruta de OpenSSL
$opensslPath = "C:\Program Files\OpenSSL-Win64\bin\openssl"

# Directorio de salida para los resultados
$outputDirectory = "ACCEPTED_CSR_OUTPUTS"

# Crear el directorio de salida si no existe
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

# Generar el nombre del archivo CSR
$csrFileName = "${username}_CSR.pem"

# Visualizar el CSR y redirigir la salida al archivo
& $opensslPath req -in "CSR/$csrFileName" -text -noout > "$outputDirectory\csr_output_$username.txt"

# Firmar el CSR
& $opensslPath x509 -req -in "CSR/$csrFileName" -CA ac_cert.pem -CAkey ac_private_key.pem -out "USERS_CERTIFICATES/${username}_CERT.pem" -days 365 -sha256

# Visualizar el certificado y redirigir la salida al archivo
& $opensslPath x509 -in "USERS_CERTIFICATES/${username}_CERT.pem" -text -noout > "$outputDirectory\cert_verification_output_$username.txt"

Write-Host "Proceso completado. Resultados guardados en $outputDirectory"


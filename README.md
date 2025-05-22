# Greengrass Certificate Installer

This utility retrieves self-signed certificates for a Greengrass device and installs them in the local truststore. It can either save the certificates to a specified directory or install them directly into the Windows certificate store.

## Prerequisites

- Python 3.6 or later
- AWS IoT Device SDK for Python v2
- AWS credentials configured
- For Windows certificate store installation: Windows OS

## Installation

1. Ensure you have the AWS IoT Device SDK for Python v2 installed:
   ```
   pip install awsiotsdk
   ```

2. Make the script executable (Unix-like systems):
   ```
   chmod +x greengrass_cert_installer.py
   ```

## Usage

```
python greengrass_cert_installer.py --certificate <path> --private-key <path> --thing-name <name> [options]
```

### Required Arguments

- `--certificate`, `-c`: Path to the client certificate file
- `--private-key`, `-k`: Path to the client private key file
- `--thing-name`, `-t`: The name of the IoT thing

### Optional Arguments

- `--region`, `-r`: AWS region (default: us-east-1)
- `--endpoint`, `-e`: Custom endpoint override (optional)
- `--port`, `-p`: Port to use for discovery (default: 8443)
- `--output-dir`, `-o`: Directory to save certificates (default: current directory)
- `--install-windows-store`, `-w`: Install certificates to Windows certificate store (Windows only)
- `--verbose`, `-v`: Enable verbose logging

## Examples

### Save certificates to a specific directory

```
python greengrass_cert_installer.py --certificate my-cert.pem --private-key my-key.pem --thing-name my-thing --output-dir /path/to/certs
```

### Install certificates to Windows certificate store

```
python greengrass_cert_installer.py --certificate my-cert.pem --private-key my-key.pem --thing-name my-thing --install-windows-store
```

### Use a custom region and endpoint

```
python greengrass_cert_installer.py --certificate my-cert.pem --private-key my-key.pem --thing-name my-thing --region us-west-2 --endpoint custom.endpoint.com
```

## Notes

- On Windows, installing certificates to the certificate store requires administrative privileges.
- The certificates are installed in the ROOT certificate store on Windows.
- On non-Windows systems, the certificates are only saved to the specified directory.

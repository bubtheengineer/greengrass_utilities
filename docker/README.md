# Greengrass Container Entrypoint Script

This script serves as the entrypoint for AWS IoT Greengrass V2 in a containerized environment. It handles the installation, configuration, and startup of the Greengrass nucleus with support for automatic deployment (and automatic re-deployment)

## Features

- Automated Greengrass V2 installation and configuration
- Environment variable configuration support
- Certificate and private key management
- Proxy support with optional CA certificate
- Docker integration for component execution
- Automatic deployment via thing group membership
- Logging and error handling
- Force redeployment capability

## Prerequisites

- Docker environment with access to docker.sock
- Docker Swarm enabled for stack deployment
- AWS IoT Core setup with:
  - IoT Thing
  - IoT Role Alias
  - Certificates and private key
  - Thing Group for deployment (if using auto-deploy)

## Setup Instructions

### 1. AWS Account Setup

Before deploying the container, follow the AWS IoT Greengrass V2 developer guide for manual resource provisioning:

1. Follow the [Install AWS IoT Greengrass Core software with manual resource provisioning](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html) guide through the "Download certificates to the device" section.
   
   This process will:
   - Create an IoT thing for your Greengrass core device
   - Create and download device certificates
   - Create the necessary IAM role and role alias
   - Provide you with the IoT data endpoint and credentials endpoint

2. After completing the provisioning steps:
   - Create a Thing Group in IoT Core
   - Create a deployment targeting this Thing Group
   - Configure the deployment with your desired components

### 2. Local Environment Setup

1. Create a Docker volume for Greengrass data:
   ```bash
   docker volume create greengrass_data
   ```

2. Create docker-compose.yml:
   ```yaml
   version: '3.7'
   
   services:
     greengrass:
       image: amazonlinux:2
       volumes:
         - greengrass_data:/data
         - /var/run/docker.sock:/var/run/docker.sock
       environment:
         - AWS_REGION=us-east-1
         - IOT_THING_NAME=your-thing-name
         - IOT_ROLE_ALIAS=GreengrassCoreTokenExchangeRoleAlias
         - IOT_DATA_ENDPOINT=your-iot-data-endpoint
         - IOT_CRED_ENDPOINT=your-iot-credential-endpoint
         # Certificate contents are passed directly as environment variables
         - IOT_CERTIFICATE_PEM=<contents-of-device.pem.crt>
         - IOT_PRIVATE_KEY=<contents-of-private.pem.key>
         - AUTO_DEPLOY=true
         - THING_GROUP=your-thing-group
       entrypoint: ["/data/greengrass_entrypoint.sh"]
       deploy:
         mode: replicated
         replicas: 1
         restart_policy:
           condition: any
   
   volumes:
     greengrass_data:
       external: true
   ```

Note: The certificate and private key contents should be passed as environment variables (`IOT_CERTIFICATE_PEM` and `IOT_PRIVATE_KEY`). The script will handle writing these to the appropriate files within the container.

### 3. Deploy the Stack

Deploy the Greengrass container using Docker stack:
```bash
docker stack deploy -c docker-compose.yml greengrass
```

## Environment Variables

### Required Variables
- `AWS_REGION` - AWS region (default: 'us-east-1')
- `IOT_THING_NAME` - Name of the IoT thing (default: 'GatewayGreengrassCoreDevice')
- `IOT_ROLE_ALIAS` - IoT role alias for token exchange (default: 'GreengrassCoreTokenExchangeRoleAlias')
- `IOT_DATA_ENDPOINT` - IoT data endpoint
- `IOT_CRED_ENDPOINT` - IoT credentials endpoint
- `IOT_CERTIFICATE_PEM` - IoT certificate contents in PEM format
- `IOT_PRIVATE_KEY` - IoT private key contents

### Optional Variables
- `PROXY_URL` - Proxy URL in format (http|https)://[username[:password]@]host[:port]
- `NO_PROXY_ADDRESSES` - Comma-separated list of addresses to bypass proxy (default: 'localhost,127.0.0.1')
- `PROXY_CA_CERT_PATH` - Path to proxy CA certificate (only for HTTPS proxies)
- `JAVASTOREPASS` - Java keystore password (default: 'changeit')
- `FORCE_REDEPLOY` - Force reinstallation if true (default: 'false')
- `VERBOSE` - Enable verbose logging (default: 'false')
- `AUTO_DEPLOY` - Enable automatic deployment (default: 'true')
- `THING_GROUP` - Thing group name for deployment (default: 'deployment_test')
- `GREENGRASS_RELEASE_VERSION` - Greengrass version to install (default: 'latest')

## Directory Structure

- `/data/greengrass` - Main Greengrass installation directory
- `/data/logs` - Log files directory
- `/data/greengrass.env` - Optional environment file location

## Features in Detail

### Automatic Deployment
When `AUTO_DEPLOY=true`, the script will:
1. Configure AWS credentials using IoT role credentials
2. Remove the thing from its group (if present)
3. Re-add it to trigger deployment

### Force Redeployment
Set `FORCE_REDEPLOY=true` to:
- Remove existing Greengrass installation
- Perform fresh installation
- Trigger new deployment

### Proxy Support
Configure proxy settings with:
- `PROXY_URL` for proxy server
- `NO_PROXY_ADDRESSES` for bypass addresses
- `PROXY_CA_CERT_PATH` for HTTPS proxy certificates

## Logging

- Logs are stored in `/data/logs/swe-install-{timestamp}.log`
- Enable verbose logging with `VERBOSE=true`
- All operations are timestamped in logs

## Security Features

- Automatic clearing of sensitive environment variables after writing to disk
- Proper file permissions for generated certificate files
- Support for secure proxy configurations
- Integration with Docker socket for secure component execution

## Error Handling

The script includes comprehensive error handling:
- Validation of required variables
- Certificate validation
- Network connectivity checks
- Deployment verification
- Clear error messages with appropriate exit codes

## Troubleshooting

1. Check container logs:
   ```bash
   docker service logs greengrass_greengrass
   ```

2. Check Greengrass status:
   ```bash
   docker exec $(docker ps -q -f name=greengrass) /data/greengrass/v2/alts/current/distro/bin/loader status
   ```

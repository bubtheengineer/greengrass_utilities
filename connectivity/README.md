# AWS Greengrass V2 Endpoint Connectivity Test

This tool tests connectivity to all required endpoints for AWS Greengrass V2 deployments. It helps identify network configuration issues that might prevent Greengrass core devices from communicating with AWS services.

## Features

- Tests connectivity to all required AWS Greengrass V2 endpoints
- Verifies DNS resolution, TCP connectivity, and TLS handshakes
- Supports custom AWS IoT endpoints
- Configurable connection timeout
- Detailed reporting with color-coded output
- Network diagnostics in verbose mode
- Comprehensive summary with troubleshooting suggestions

## Prerequisites

The script requires the following tools:
- `curl` - For testing HTTPS connections
- `nc` (netcat) - For testing TCP connectivity
- `dig` - For DNS resolution testing
- `aws` (AWS CLI) - For retrieving account-specific endpoints (optional)

## Usage

### Basic Usage

```bash
./check_greengrass_endpoints.sh --region us-east-1
```

### With Custom IoT Endpoints

```bash
./check_greengrass_endpoints.sh --region us-east-1 \
  --data-endpoint abcdef-ats.iot.us-east-1.amazonaws.com \
  --cred-endpoint abcdef.credentials.iot.us-east-1.amazonaws.com
```

### With AWS Profile

```bash
AWS_PROFILE=your-profile ./check_greengrass_endpoints.sh --region us-east-1
```

### With Verbose Diagnostics

```bash
./check_greengrass_endpoints.sh --region us-east-1 --verbose
```

## Options

| Option | Description |
|--------|-------------|
| `-r, --region REGION` | AWS region to test (default: us-east-1) |
| `-t, --timeout SECONDS` | Connection timeout in seconds (default: 5) |
| `-d, --data-endpoint URL` | Custom AWS IoT data endpoint |
| `-c, --cred-endpoint URL` | Custom AWS IoT credentials endpoint |
| `-v, --verbose` | Enable verbose output with additional diagnostics |
| `-h, --help` | Display help message |

## Endpoints Tested

### Basic Operation Endpoints
- Greengrass data plane operations
- AWS IoT Core MQTT
- AWS IoT Core HTTPS
- AWS IoT credentials provider
- Amazon S3 endpoints

### Automatic Provisioning Endpoints
- AWS IoT control plane
- AWS IAM
- AWS STS
- AWS Greengrass control plane

### Common AWS-Provided Component Endpoints
- AWS Systems Manager (Stream Manager)
- Amazon Kinesis (Stream Manager)
- AWS IoT SiteWise
- AWS Secrets Manager
- Amazon CloudWatch Logs

## Troubleshooting

If the script reports connectivity issues:

1. **Check your internet connection**
   - Verify that your device has internet access

2. **Verify firewall or security group rules**
   - Ensure outbound traffic is allowed to AWS endpoints on ports 443, 8443, and 8883

3. **Configure network proxy settings**
   - If using a proxy, configure Greengrass accordingly

4. **Ensure DNS resolution is working properly**
   - Verify that your DNS servers can resolve AWS domains

5. **TLS/SSL Issues**
   - Update your system's CA certificates
   - Ensure TLS 1.2 support is available

6. **Port 443 Alternative**
   - If ports 8883 and 8443 are blocked, configure Greengrass to use port 443 with ALPN

## AWS IoT Endpoint Discovery

To find your account-specific AWS IoT endpoints:

```bash
# Get AWS IoT data endpoint
aws iot describe-endpoint --endpoint-type iot:Data-ATS

# Get AWS IoT credentials endpoint
aws iot describe-endpoint --endpoint-type iot:CredentialProvider
```

## References

- [AWS Greengrass V2 Documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/what-is-iot-greengrass.html)
- [Allow device traffic through a proxy or firewall](https://docs.aws.amazon.com/greengrass/v2/developerguide/allow-device-traffic.html)
- [Configure the AWS IoT Greengrass Core software](https://docs.aws.amazon.com/greengrass/v2/developerguide/configure-greengrass-core-v2.html)

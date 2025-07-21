#!/bin/bash
#
# AWS Greengrass V2 Endpoint Connectivity Test Script
# This script tests connectivity to all required endpoints for AWS Greengrass V2
#

# Text formatting
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

# Default values
DEFAULT_REGION="us-east-1"
DEFAULT_TIMEOUT=5
DEFAULT_PORT=443

# Initialize variables
REGION=${DEFAULT_REGION}
TIMEOUT=${DEFAULT_TIMEOUT}
CUSTOM_IOT_DATA_ENDPOINT=""
CUSTOM_IOT_CRED_ENDPOINT=""
VERBOSE=false

# Function to display usage information
usage() {
    echo -e "${BOLD}Usage:${RESET} $0 [options]"
    echo
    echo "This script tests connectivity to all required endpoints for AWS Greengrass V2."
    echo
    echo -e "${BOLD}Options:${RESET}"
    echo "  -r, --region REGION         AWS region to test (default: ${DEFAULT_REGION})"
    echo "  -t, --timeout SECONDS       Connection timeout in seconds (default: ${DEFAULT_TIMEOUT})"
    echo "  -d, --data-endpoint URL     Custom AWS IoT data endpoint"
    echo "  -c, --cred-endpoint URL     Custom AWS IoT credentials endpoint"
    echo "  -v, --verbose               Enable verbose output"
    echo "  -h, --help                  Display this help message"
    echo
    echo -e "${BOLD}Example:${RESET}"
    echo "  $0 --region us-west-2 --data-endpoint abcdef-ats.iot.us-west-2.amazonaws.com"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -d|--data-endpoint)
            CUSTOM_IOT_DATA_ENDPOINT="$2"
            shift 2
            ;;
        -c|--cred-endpoint)
            CUSTOM_IOT_CRED_ENDPOINT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${RESET}"
            usage
            ;;
    esac
done

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
for cmd in curl nc dig aws; do
    if ! command_exists "$cmd"; then
        echo -e "${RED}Error: Required command '$cmd' not found. Please install it and try again.${RESET}"
        case "$cmd" in
            curl)
                echo "Install curl: sudo apt-get install curl (Debian/Ubuntu) or brew install curl (macOS)"
                ;;
            nc)
                echo "Install netcat: sudo apt-get install netcat (Debian/Ubuntu) or brew install netcat (macOS)"
                ;;
            dig)
                echo "Install dig: sudo apt-get install dnsutils (Debian/Ubuntu) or brew install bind (macOS)"
                ;;
            aws)
                echo "Install AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
                ;;
        esac
        exit 1
    fi
done

# Function to print section header
print_header() {
    echo -e "\n${BOLD}${BLUE}$1${RESET}"
    echo -e "${BLUE}$(printf '=%.0s' {1..80})${RESET}"
}

# Function to test endpoint connectivity
test_endpoint() {
    local endpoint=$1
    local port=$2
    local description=$3
    local required=$4
    local protocol=${5:-"https"}
    
    echo -n "Testing ${endpoint}:${port} (${description})... "
    
    # Test DNS resolution
    if ! dig +short "$endpoint" > /dev/null; then
        if [ "$required" = "Yes" ]; then
            echo -e "${RED}FAILED (DNS resolution failed)${RESET}"
            return 1
        else
            echo -e "${YELLOW}WARNING (DNS resolution failed, but endpoint is optional)${RESET}"
            return 0
        fi
    fi
    
    # Test connectivity
    if nc -z -w "$TIMEOUT" "$endpoint" "$port" 2>/dev/null; then
        # If protocol is https, also test TLS handshake
        if [ "$protocol" = "https" ]; then
            if curl -s --head --connect-timeout "$TIMEOUT" "https://${endpoint}:${port}" >/dev/null; then
                echo -e "${GREEN}SUCCESS${RESET}"
                return 0
            else
                if [ "$required" = "Yes" ]; then
                    echo -e "${RED}FAILED (TLS handshake failed)${RESET}"
                    return 1
                else
                    echo -e "${YELLOW}WARNING (TLS handshake failed, but endpoint is optional)${RESET}"
                    return 0
                fi
            fi
        else
            echo -e "${GREEN}SUCCESS${RESET}"
            return 0
        fi
    else
        if [ "$required" = "Yes" ]; then
            echo -e "${RED}FAILED (Connection refused or timed out)${RESET}"
            return 1
        else
            echo -e "${YELLOW}WARNING (Connection refused or timed out, but endpoint is optional)${RESET}"
            return 0
        fi
    fi
}

# Function to get AWS IoT endpoints if not provided
get_iot_endpoints() {
    print_header "Retrieving AWS IoT endpoints"
    
    if [ -z "$CUSTOM_IOT_DATA_ENDPOINT" ]; then
        echo "Getting AWS IoT data endpoint for region ${REGION}..."
        if ! command_exists aws; then
            echo -e "${YELLOW}AWS CLI not found. Using default endpoint format.${RESET}"
            IOT_DATA_ENDPOINT="prefix-ats.iot.${REGION}.amazonaws.com"
        else
            IOT_DATA_ENDPOINT=$(aws iot describe-endpoint --endpoint-type iot:Data-ATS --region "$REGION" --query 'endpointAddress' --output text 2>/dev/null)
            if [ $? -ne 0 ] || [ -z "$IOT_DATA_ENDPOINT" ]; then
                echo -e "${YELLOW}Failed to get AWS IoT data endpoint. Using default endpoint format.${RESET}"
                IOT_DATA_ENDPOINT="prefix-ats.iot.${REGION}.amazonaws.com"
            else
                echo -e "AWS IoT data endpoint: ${GREEN}${IOT_DATA_ENDPOINT}${RESET}"
            fi
        fi
    else
        IOT_DATA_ENDPOINT="$CUSTOM_IOT_DATA_ENDPOINT"
        echo -e "Using custom AWS IoT data endpoint: ${GREEN}${IOT_DATA_ENDPOINT}${RESET}"
    fi
    
    if [ -z "$CUSTOM_IOT_CRED_ENDPOINT" ]; then
        echo "Getting AWS IoT credentials endpoint for region ${REGION}..."
        if ! command_exists aws; then
            echo -e "${YELLOW}AWS CLI not found. Using default endpoint format.${RESET}"
            IOT_CRED_ENDPOINT="prefix.credentials.iot.${REGION}.amazonaws.com"
        else
            IOT_CRED_ENDPOINT=$(aws iot describe-endpoint --endpoint-type iot:CredentialProvider --region "$REGION" --query 'endpointAddress' --output text 2>/dev/null)
            if [ $? -ne 0 ] || [ -z "$IOT_CRED_ENDPOINT" ]; then
                echo -e "${YELLOW}Failed to get AWS IoT credentials endpoint. Using default endpoint format.${RESET}"
                IOT_CRED_ENDPOINT="prefix.credentials.iot.${REGION}.amazonaws.com"
            else
                echo -e "AWS IoT credentials endpoint: ${GREEN}${IOT_CRED_ENDPOINT}${RESET}"
            fi
        fi
    else
        IOT_CRED_ENDPOINT="$CUSTOM_IOT_CRED_ENDPOINT"
        echo -e "Using custom AWS IoT credentials endpoint: ${GREEN}${IOT_CRED_ENDPOINT}${RESET}"
    fi
}

# Function to test basic operation endpoints
test_basic_operation_endpoints() {
    print_header "Testing endpoints for basic operation"
    
    local failed=0
    
    # Test Greengrass data plane endpoint
    test_endpoint "greengrass-ats.iot.${REGION}.amazonaws.com" 443 "Greengrass data plane operations" "Yes"
    failed=$((failed + $?))
    test_endpoint "greengrass-ats.iot.${REGION}.amazonaws.com" 8443 "Greengrass data plane operations (alt port)" "No"
    
    # Test IoT data endpoint
    test_endpoint "$IOT_DATA_ENDPOINT" 8883 "AWS IoT Core MQTT" "Yes"
    failed=$((failed + $?))
    test_endpoint "$IOT_DATA_ENDPOINT" 443 "AWS IoT Core MQTT (alt port)" "No"
    
    # Test IoT data endpoint (HTTPS)
    test_endpoint "$IOT_DATA_ENDPOINT" 8443 "AWS IoT Core HTTPS" "Yes"
    failed=$((failed + $?))
    test_endpoint "$IOT_DATA_ENDPOINT" 443 "AWS IoT Core HTTPS (alt port)" "No"
    
    # Test IoT credentials endpoint
    test_endpoint "$IOT_CRED_ENDPOINT" 443 "AWS IoT credentials provider" "Yes"
    failed=$((failed + $?))
    
    # Test S3 endpoints
    test_endpoint "s3.${REGION}.amazonaws.com" 443 "Amazon S3 regional endpoint" "Yes"
    failed=$((failed + $?))
    test_endpoint "s3.amazonaws.com" 443 "Amazon S3 global endpoint" "Yes"
    failed=$((failed + $?))
    
    # Test IoT data endpoint for proxy configurations
    test_endpoint "data.iot.${REGION}.amazonaws.com" 443 "AWS IoT Core data endpoint (for proxy)" "No"
    
    if [ $failed -eq 0 ]; then
        echo -e "\n${GREEN}All required basic operation endpoints are reachable.${RESET}"
    else
        echo -e "\n${RED}${failed} required basic operation endpoint(s) are not reachable.${RESET}"
    fi
    
    return $failed
}

# Function to test automatic provisioning endpoints
test_auto_provisioning_endpoints() {
    print_header "Testing endpoints for automatic provisioning"
    
    local failed=0
    
    # Test IoT control plane endpoint
    test_endpoint "iot.${REGION}.amazonaws.com" 443 "AWS IoT control plane" "Yes"
    failed=$((failed + $?))
    
    # Test IAM endpoint
    test_endpoint "iam.amazonaws.com" 443 "AWS IAM" "Yes"
    failed=$((failed + $?))
    
    # Test STS endpoint
    test_endpoint "sts.${REGION}.amazonaws.com" 443 "AWS STS" "Yes"
    failed=$((failed + $?))
    
    # Test Greengrass control plane endpoint
    test_endpoint "greengrass.${REGION}.amazonaws.com" 443 "AWS Greengrass control plane" "No"
    
    if [ $failed -eq 0 ]; then
        echo -e "\n${GREEN}All required automatic provisioning endpoints are reachable.${RESET}"
    else
        echo -e "\n${RED}${failed} required automatic provisioning endpoint(s) are not reachable.${RESET}"
    fi
    
    return $failed
}

# Function to test common AWS-provided component endpoints
test_common_component_endpoints() {
    print_header "Testing endpoints for common AWS-provided components"
    
    local failed=0
    
    # Test AWS Systems Manager endpoint (for Stream Manager)
    test_endpoint "ssm.${REGION}.amazonaws.com" 443 "AWS Systems Manager (Stream Manager)" "No"
    
    # Test Kinesis endpoint (for Stream Manager)
    test_endpoint "kinesis.${REGION}.amazonaws.com" 443 "Amazon Kinesis (Stream Manager)" "No"
    
    # Test IoT SiteWise endpoint (for IoT SiteWise component)
    test_endpoint "iotsitewise.${REGION}.amazonaws.com" 443 "AWS IoT SiteWise" "No"
    
    # Test Secrets Manager endpoint (for Secret Manager component)
    test_endpoint "secretsmanager.${REGION}.amazonaws.com" 443 "AWS Secrets Manager" "No"
    
    # Test CloudWatch Logs endpoint (for Log Manager component)
    test_endpoint "logs.${REGION}.amazonaws.com" 443 "Amazon CloudWatch Logs" "No"
    
    echo -e "\n${YELLOW}Note: Component-specific endpoints are only required if you use those components.${RESET}"
    
    return 0
}

# Function to perform additional network diagnostics
perform_diagnostics() {
    print_header "Network Diagnostics"
    
    # Check internet connectivity
    echo "Checking general internet connectivity..."
    if ping -c 3 8.8.8.8 >/dev/null 2>&1; then
        echo -e "Internet connectivity: ${GREEN}OK${RESET}"
    else
        echo -e "Internet connectivity: ${RED}FAILED${RESET}"
    fi
    
    # Check DNS resolution
    echo "Checking DNS resolution..."
    if dig +short amazon.com >/dev/null 2>&1; then
        echo -e "DNS resolution: ${GREEN}OK${RESET}"
    else
        echo -e "DNS resolution: ${RED}FAILED${RESET}"
    fi
    
    # Check for proxy settings
    echo "Checking for proxy settings..."
    if [ -n "$http_proxy" ] || [ -n "$https_proxy" ]; then
        echo -e "Proxy detected: ${YELLOW}Yes${RESET}"
        echo "  HTTP_PROXY=$http_proxy"
        echo "  HTTPS_PROXY=$https_proxy"
        echo "  NO_PROXY=$no_proxy"
        echo -e "${YELLOW}Note: If using a proxy, make sure to configure Greengrass accordingly.${RESET}"
    else
        echo -e "Proxy detected: ${GREEN}No${RESET}"
    fi
    
    # Check TLS/SSL capabilities
    echo "Checking TLS/SSL capabilities..."
    if curl -s --tlsv1.2 https://www.howsmyssl.com/a/check | grep -q "TLS 1.2"; then
        echo -e "TLS 1.2 support: ${GREEN}OK${RESET}"
    else
        echo -e "TLS 1.2 support: ${RED}FAILED${RESET}"
    fi
}

# Function to print summary
print_summary() {
    local basic_failed=$1
    local auto_failed=$2
    
    print_header "Summary"
    
    if [ $basic_failed -eq 0 ] && [ $auto_failed -eq 0 ]; then
        echo -e "${GREEN}All required endpoints are reachable. Your network appears to be correctly configured for AWS Greengrass V2.${RESET}"
    else
        echo -e "${RED}Some required endpoints are not reachable. Please check your network configuration.${RESET}"
        
        if [ $basic_failed -gt 0 ]; then
            echo -e "${RED}- $basic_failed basic operation endpoint(s) failed${RESET}"
        fi
        
        if [ $auto_failed -gt 0 ]; then
            echo -e "${RED}- $auto_failed automatic provisioning endpoint(s) failed${RESET}"
        fi
        
        echo -e "\n${YELLOW}Possible solutions:${RESET}"
        echo "1. Check your internet connection"
        echo "2. Verify firewall or security group rules"
        echo "3. Configure network proxy settings if needed"
        echo "4. Ensure DNS resolution is working properly"
        echo "5. Verify the AWS region is correct"
    fi
    
    echo -e "\n${BOLD}AWS IoT Endpoints for Greengrass configuration:${RESET}"
    echo -e "AWS IoT Data Endpoint:       ${BLUE}${IOT_DATA_ENDPOINT}${RESET}"
    echo -e "AWS IoT Credentials Endpoint: ${BLUE}${IOT_CRED_ENDPOINT}${RESET}"
    
    echo -e "\n${YELLOW}For more information, visit:${RESET}"
    echo "https://docs.aws.amazon.com/greengrass/v2/developerguide/allow-device-traffic.html"
}

# Main execution
echo -e "${BOLD}AWS Greengrass V2 Endpoint Connectivity Test${RESET}"
echo "Region: $REGION"
echo "Timeout: $TIMEOUT seconds"

# Get AWS IoT endpoints
get_iot_endpoints

# Test endpoints
test_basic_operation_endpoints
BASIC_FAILED=$?

test_auto_provisioning_endpoints
AUTO_FAILED=$?

test_common_component_endpoints

# Perform additional diagnostics if verbose mode is enabled
if [ "$VERBOSE" = true ]; then
    perform_diagnostics
fi

# Print summary
print_summary $BASIC_FAILED $AUTO_FAILED

# Exit with error code if any required endpoints failed
if [ $BASIC_FAILED -gt 0 ] || [ $AUTO_FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi

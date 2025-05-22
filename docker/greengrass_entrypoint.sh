#!/usr/bin/env bash

# Default values for environment variables
AWS_REGION=${AWS_REGION:-'us-east-1'}
IOT_THING_NAME=${IOT_THING_NAME:-'GatewayGreengrassCoreDevice'}
IOT_ROLE_ALIAS=${IOT_ROLE_ALIAS:-'GreengrassCoreTokenExchangeRoleAlias'}
IOT_DATA_ENDPOINT=${IOT_DATA_ENDPOINT:-''}
IOT_CRED_ENDPOINT=${IOT_CRED_ENDPOINT:-''}
IOT_CERTIFICATE_PEM=${IOT_CERTIFICATE_PEM:-''}
IOT_PRIVATE_KEY=${IOT_PRIVATE_KEY:-''}
PROXY_URL=${PROXY_URL:-''}
NO_PROXY_ADDRESSES=${NO_PROXY_ADDRESSES:-'localhost,127.0.0.1'}
PROXY_CA_CERT_PATH=${PROXY_CA_CERT_PATH:-''}
JAVASTOREPASS=${JAVASTOREPASS:-'changeit'}
FORCE_REDEPLOY=${FORCE_REDEPLOY:-'false'}
VERBOSE=${VERBOSE:-'false'}
AUTO_DEPLOY=${AUTO_DEPLOY:-'true'}  # Default to auto-deployment
THING_GROUP=${THING_GROUP:-'deployment_test'}  # Thing group with base deployment
GREENGRASS_RELEASE_VERSION=${GREENGRASS_RELEASE_VERSION:-'latest'}

# Fixed variables
GREENGRASS_FOLDER="/data/greengrass"
LOG_DIR="/data/logs"
VERSION="1.0.326.0-container"
GREENGRASS_ZIP_FILE=greengrass-${GREENGRASS_RELEASE_VERSION}.zip
GREENGRASS_RELEASE_URI=https://d2s8p88vqu9w66.cloudfront.net/releases/${GREENGRASS_ZIP_FILE}

function loadEnvFile() {
    local env_file="/data/greengrass.env"
    
    if [ -f "$env_file" ]; then
        echo "Loading environment variables from $env_file"
        # Source the env file to load variables into environment
        set -a
        source "$env_file"
        set +a
        showWarningOnFailure "Error loading environment file"
    else
        echo "Environment file $env_file not found, using container environment variables."
    fi
}

function setupLogging() {
    mkdir -p ${LOG_DIR}
    local log_file="${LOG_DIR}/swe-install-$(date +'%Y%m%d%H%M%S').log"
    touch ${log_file}
    
    echo "The SiteWise Edge installation log is available at: ${log_file}"
    
    # store the stdout descriptor for redirect
    exec 5>&1
    # quiet logging
    exec 4> >(sed "s/^/$(date '+[%F %T]'): /" >> ${log_file})
    # stdout and then log
    exec 1> >(tee /dev/fd/5 1>&4)
    
    # print errors and hidden messages in verbose mode
    if [[ $VERBOSE == "true" ]]
    then
        exec 3>&1 2>&1
    else
        exec 3>&4 2>&4
    fi
}

function logOuput() {
    "$@" >&3
}

function showWarning() {
    echo -e "\e[93mWarning:\e[0m $*"
}

function showError() {
    echo -e "\e[91mError:\e[0m $*"
    exit 1
}

function showWarningOnFailure() {
    if [[ $? -ne 0 ]]
    then
        showWarning "$*"
    fi
}

function showErrorOnFailure() {
    if [[ $? -ne 0 ]]
    then
        showError "$*"
    fi
}

function validateEnvVariables() {
    local missing_vars=()
    
    [[ -z "$AWS_REGION" ]] && missing_vars+=("AWS_REGION")
    [[ -z "$IOT_THING_NAME" ]] && missing_vars+=("IOT_THING_NAME")
    [[ -z "$IOT_ROLE_ALIAS" ]] && missing_vars+=("IOT_ROLE_ALIAS")
    [[ -z "$IOT_DATA_ENDPOINT" ]] && missing_vars+=("IOT_DATA_ENDPOINT")
    [[ -z "$IOT_CRED_ENDPOINT" ]] && missing_vars+=("IOT_CRED_ENDPOINT")
    [[ -z "$IOT_CERTIFICATE_PEM" ]] && missing_vars+=("IOT_CERTIFICATE_PEM")
    [[ -z "$IOT_PRIVATE_KEY" ]] && missing_vars+=("IOT_PRIVATE_KEY")
    
    if [ ${#missing_vars[@]} -ne 0 ]; then
        echo "The following environment variables are required:"
        printf "* %s\n" "${missing_vars[@]}"
        showError "Please set these environment variables in /data/greengrass.env file or as container environment variables."
    fi
    
    # Validate proxy URL format if provided
    if [ -n "$PROXY_URL" ]; then
        if ! [[ $PROXY_URL =~ ^(https?)://([^/]+@)?[^/:]+(:?[0-9]+)?$ ]]; then
            showError "Invalid proxy URL. Format must be (http|https)://[username[:password]@]host[:port]"
        fi
        
        local scheme=${BASH_REMATCH[1]}
        if [ -n "$PROXY_CA_CERT_PATH" ] && [ "$scheme" != "https" ]; then
            showError "Proxy CA certificate can only be used with HTTPS proxy"
        fi
    fi
}

function createTempFolder() {
    # Create temporary folder for downloads
    temp_install_dir="$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')"
    # Auto destroy the folder on exit
    trap 'rm -rf -- "$temp_install_dir"' EXIT
    cd $temp_install_dir
    echo "Created temporary installation directory $temp_install_dir"
}

function installDependencies() {
    echo "Installing dependencies..."
    
    # Update package list
    yum update -y
    showWarningOnFailure "Failed to update package list"
    
    # Install essential packages
    yum install -y unzip procps jq sudo less python3-pip which shadow-utils java-11-amazon-corretto-headless openssl
    showErrorOnFailure "Failed to install essential packages"
    
    # Configure sudoers to allow passwordless sudo for component execution
    echo "Configuring sudo for Greengrass components..."
    # Grab the line number for the root user entry
    ROOT_LINE_NUM=$(grep -n "^root" /etc/sudoers | cut -d : -f 1)

    # Check if the root user is already configured to execute commands as other users
    if sudo sed -n "${ROOT_LINE_NUM}p" /etc/sudoers | grep -q "ALL=(ALL:ALL)" ; then
      echo "Root user is already configured to execute commands as other users."
    else
        # Replace `ALL=(ALL)` with `ALL=(ALL:ALL)` to allow the root user to execute commands as other users
        sudo sed -i "$ROOT_LINE_NUM s/ALL=(ALL)/ALL=(ALL:ALL)/" /etc/sudoers
        showErrorOnFailure "Failed to update sudoers"

        echo "Successfully modified /etc/sudoers. Root user is now configured to execute commands as other users."
    fi
    
    # Install AWS CLI
    if ! command -v aws &> /dev/null; then
        echo "Installing AWS CLI..."
        curl "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o "awscliv2.zip"
        unzip awscliv2.zip
        ./aws/install
        showWarningOnFailure "Failed to install AWS CLI"
    fi
    
    # Install Docker CLI
    echo "Installing Docker CLI..."
    
    # Install docker package which contains the CLI
    yum install -y docker
    showErrorOnFailure "Failed to install docker package"
    
    # Prevent the docker daemon from starting in the container
    if command -v systemctl &> /dev/null; then
        systemctl mask docker.service
        systemctl mask docker.socket
    fi
    
    # Check if docker socket is accessible
    if [ ! -e "/var/run/docker.sock" ]; then
        showError "Docker socket not found. Make sure to mount it when running the container (-v /var/run/docker.sock:/var/run/docker.sock)"
    else
        echo "Docker socket found at /var/run/docker.sock"
        docker version --format '{{.Client.Version}}' || showWarning "Docker CLI installed but cannot connect to Docker socket. Check permissions."
    fi
}

function createGreengrassFolder() {
    if [[ "$FORCE_REDEPLOY" == "true" ]] && [[ -d "$GREENGRASS_FOLDER" ]]; then
        echo "Force redeploy requested, removing existing Greengrass installation..."
        rm -rf $GREENGRASS_FOLDER
    fi
    
    mkdir -p $GREENGRASS_FOLDER/v2
    showErrorOnFailure "Failed to create path $GREENGRASS_FOLDER/v2"
    
    chmod 755 $GREENGRASS_FOLDER
    showErrorOnFailure "Failed to set the permissions to $GREENGRASS_FOLDER"
}

function downloadGreengrassNucleus() {
    local greengrass_package=greengrass-nucleus-latest.zip
    
    echo "Downloading Greengrass nucleus..."
    curl --retry 10 -s $GREENGRASS_RELEASE_URI -o $greengrass_package
    showErrorOnFailure "Failed to download $greengrass_package. Please check your internet connection and retry."
    
    unzip -o $greengrass_package -d $GREENGRASS_FOLDER/v2/GreengrassCore
    showErrorOnFailure "Failed to unzip $greengrass_package."
}

function createGreengrassConfigFile() {
    local config_path="$1"
    echo "Creating Greengrass configuration file: $config_path"
    
    local config_content="---
system:
  certificateFilePath: \"$GREENGRASS_FOLDER/v2/device.pem.crt\"
  privateKeyPath: \"$GREENGRASS_FOLDER/v2/private.pem.key\"
  rootCaPath: \"$GREENGRASS_FOLDER/v2/AmazonRootCA1.pem\"
  rootpath: \"$GREENGRASS_FOLDER/v2\"
  thingName: \"$IOT_THING_NAME\"
  ipcSocketPath: \"/var/run/greengrass/ipc.sock\"
services:
  aws.greengrass.Nucleus:
    componentType: \"NUCLEUS\"
    configuration:
      awsRegion: \"$AWS_REGION\"
      iotRoleAlias: \"$IOT_ROLE_ALIAS\"
      iotDataEndpoint: \"$IOT_DATA_ENDPOINT\"
      iotCredEndpoint: \"$IOT_CRED_ENDPOINT\"
      runWithDefault:
        posixUser: \"ggc_user:ggc_group\""
    
    if [ -n "$PROXY_URL" ]; then
        config_content="$config_content
      networkProxy:
        noProxyAddresses: \"$NO_PROXY_ADDRESSES\"
        proxy:
          url: \"$PROXY_URL\""
    fi
    
    echo "$config_content" > "$config_path"
    showErrorOnFailure "Failed to create the Greengrass configuration file $config_path"
}

function installCertificates() {
    echo "Installing certificates..."
    
    curl --retry 10 -s https://www.amazontrust.com/repository/AmazonRootCA1.pem -o $GREENGRASS_FOLDER/v2/AmazonRootCA1.pem
    showErrorOnFailure "Failed to download AmazonRootCA1.pem. Please check your internet connection and retry."
    
    # Handle certificates from environment variables, using echo -e to interpret any \n escapes
    echo -e "${IOT_CERTIFICATE_PEM}" > $GREENGRASS_FOLDER/v2/device.pem.crt
    showErrorOnFailure "Failed to create IoT certificate file $GREENGRASS_FOLDER/v2/device.pem.crt"
    
    echo -e "${IOT_PRIVATE_KEY}" > $GREENGRASS_FOLDER/v2/private.pem.key
    showErrorOnFailure "Failed to create IoT private key $GREENGRASS_FOLDER/v2/private.pem.key"
    
    # Verify certificates are valid
    if ! openssl x509 -noout -in $GREENGRASS_FOLDER/v2/device.pem.crt 2>/dev/null; then
        showError "The certificate appears to be invalid. Please check your IOT_CERTIFICATE_PEM environment variable format."
    fi
    
    if ! openssl rsa -noout -in $GREENGRASS_FOLDER/v2/private.pem.key 2>/dev/null; then
        showError "The private key appears to be invalid. Please check your IOT_PRIVATE_KEY environment variable format."
    fi
    
    if [ -n "$PROXY_CA_CERT_PATH" ] && [ -f "$PROXY_CA_CERT_PATH" ]; then
        # Append proxy CA cert to root CA
        echo >> $GREENGRASS_FOLDER/v2/AmazonRootCA1.pem
        cat "$PROXY_CA_CERT_PATH" >> $GREENGRASS_FOLDER/v2/AmazonRootCA1.pem
        showErrorOnFailure "Failed to append proxy CA certificate to root CA"
        
        # Add to Java keystore
        keytool -import -trustcacerts -cacerts -storepass "${JAVASTOREPASS}" -noprompt -alias proxyCert -file "$PROXY_CA_CERT_PATH"
        showWarningOnFailure "Failed to import proxy CA certificate to Java keystore."
    fi
}

function clearSensitiveEnv() {
    echo "Clearing sensitive environment variables for security..."
    # Unset sensitive environment variables
    unset IOT_CERTIFICATE_PEM
    unset IOT_PRIVATE_KEY
    
    # Verify they're cleared - for security conscious environments
    if [[ -n "$IOT_CERTIFICATE_PEM" ]] || [[ -n "$IOT_PRIVATE_KEY" ]]; then
        showWarning "Failed to fully clear sensitive environment variables"
    fi
}

function setCertificatesACL() {
    chmod 400 $GREENGRASS_FOLDER/v2/AmazonRootCA1.pem
    showErrorOnFailure "Failed to modify ACL of file $GREENGRASS_FOLDER/v2/AmazonRootCA1.pem"
    
    chmod 400 $GREENGRASS_FOLDER/v2/device.pem.crt
    showErrorOnFailure "Failed to modify ACL of file $GREENGRASS_FOLDER/v2/device.pem.crt"
    
    chmod 400 $GREENGRASS_FOLDER/v2/private.pem.key
    showErrorOnFailure "Failed modify ACL of file $GREENGRASS_FOLDER/v2/private.pem.key"
}

function installGreengrass() {
    echo "Installing Greengrass..."
    
    # Create ggc_user if it doesn't exist
    if ! id -u ggc_user >/dev/null 2>&1; then
        groupadd -r ggc_group
        useradd -r -m -N -g ggc_group -s /bin/bash ggc_user
        showErrorOnFailure "Failed to create ggc_user"
    fi
    
    # Ensure ggc_user can access docker socket
    if [ -e "/var/run/docker.sock" ]; then
        DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
        if [ "$DOCKER_GID" != "0" ]; then
            # Create a group with the same GID as docker.sock
            groupadd -g $DOCKER_GID docker_socket_access 2>/dev/null || true
            # Add ggc_user to this group
            usermod -a -G $DOCKER_GID ggc_user
            showWarningOnFailure "Failed to give ggc_user access to docker.sock"
        fi
    fi
    
    # Initialize Greengrass
    local config_path="$GREENGRASS_FOLDER/v2/config.yaml"
    createGreengrassConfigFile $config_path
    
    java -Droot="${GREENGRASS_FOLDER}/v2" -Dlog.store=FILE \
        -jar $GREENGRASS_FOLDER/v2/GreengrassCore/lib/Greengrass.jar \
        --init-config $config_path \
        --component-default-user ggc_user:ggc_group \
        --setup-system-service false \
        --deploy-dev-tools true \
        --start false
    
    showErrorOnFailure "Failed to execute Greengrass installation"
    
}

function configureAwsCredentials() {
    echo "Configuring AWS credentials for deployment automation..."
    
    # Create credentials directory
    mkdir -p /root/.aws
    
    # Set up AWS config for region
    cat > /root/.aws/config << EOF
[default]
region = $AWS_REGION
output = json
EOF

    # Wait for credentials to be available through token exchange
    local max_attempts=5
    local attempt=1
    local success=false
    local wait_time=5
    
    echo "Waiting for AWS credentials via IoT Role Alias..."
    
    while [ $attempt -le $max_attempts ] && [ "$success" = false ]; do
        echo "Attempt $attempt of $max_attempts..."
        
        # IoT credentials endpoint polling
        local credentials_response=$(curl --silent --connect-timeout 5 \
            --cert $GREENGRASS_FOLDER/v2/device.pem.crt \
            --key $GREENGRASS_FOLDER/v2/private.pem.key \
            --cacert $GREENGRASS_FOLDER/v2/AmazonRootCA1.pem \
            "https://${IOT_CRED_ENDPOINT}/role-aliases/${IOT_ROLE_ALIAS}/credentials")
        
        if [ $? -eq 0 ] && [ -n "$credentials_response" ]; then
            # Extract credentials
            local accessKeyId=$(echo $credentials_response | jq -r '.credentials.accessKeyId')
            local secretAccessKey=$(echo $credentials_response | jq -r '.credentials.secretAccessKey')
            local sessionToken=$(echo $credentials_response | jq -r '.credentials.sessionToken')
            
            if [ -n "$accessKeyId" ] && [ "$accessKeyId" != "null" ]; then
                # Write credentials file
                cat > /root/.aws/credentials << EOF
[default]
aws_access_key_id = $accessKeyId
aws_secret_access_key = $secretAccessKey
aws_session_token = $sessionToken
EOF
                success=true
                echo "AWS credentials configured successfully."
            fi
        fi
        
        if [ "$success" = false ]; then
            echo "Failed to obtain credentials. Retrying in $wait_time seconds..."
            sleep $wait_time
            attempt=$((attempt + 1))
            wait_time=$((wait_time * 2))  # Exponential backoff
        fi
    done
    
    if [ "$success" = false ]; then
        showWarning "Failed to obtain AWS credentials. Auto-deployment may not work."
        return 1
    fi
    
    return 0
}

function forceRedeploy() {
    echo "Forcing redeployment via thing group manipulation..."
    
    # Step 1: Verify AWS CLI is working with credentials
    if ! aws sts get-caller-identity &>/dev/null; then
        showWarning "AWS CLI not configured with valid credentials. Skipping auto-deployment."
        return 1
    fi
    
    # Get the thing's ARN
    local thing_arn="arn:aws:iot:${AWS_REGION}:$(aws sts get-caller-identity --query Account --output text):thing/${IOT_THING_NAME}"
    
    echo "Checking if $IOT_THING_NAME is in thing group $THING_GROUP..."
    
    # Check if the thing is already in the group
    local in_group=false
    if aws iot list-things-in-thing-group --thing-group-name "$THING_GROUP" --query "things[?@=='$IOT_THING_NAME']" --output text | grep -q "$IOT_THING_NAME"; then
        in_group=true
        echo "Thing $IOT_THING_NAME is currently in thing group $THING_GROUP"
        
        # Remove from thing group
        echo "Removing $IOT_THING_NAME from thing group $THING_GROUP..."
        aws iot remove-thing-from-thing-group \
            --thing-name "$IOT_THING_NAME" \
            --thing-group-name "$THING_GROUP"
        showWarningOnFailure "Failed to remove thing from thing group"
        
        # Wait briefly to allow AWS to process the removal
        echo "Waiting for removal to be processed..."
        sleep 5
    else
        echo "Thing $IOT_THING_NAME is not currently in thing group $THING_GROUP"
    fi
    
    # Add to thing group
    echo "Adding $IOT_THING_NAME to thing group $THING_GROUP..."
    aws iot add-thing-to-thing-group \
        --thing-name "$IOT_THING_NAME" \
        --thing-group-name "$THING_GROUP"
    showWarningOnFailure "Failed to add thing to thing group"
    
    echo "Deployment triggered. The device will receive the deployment soon."
    return 0
}

function startGreengrass() {
    echo "Starting Greengrass..."
    exec $GREENGRASS_FOLDER/v2/alts/current/distro/bin/loader
}

function main() {
    echo "Starting Greengrass container setup (version $VERSION)..."
    
    # Load environment variables from file first
    loadEnvFile
    
    setupLogging
    validateEnvVariables
    installDependencies
    createTempFolder

    # Only perform installation steps if Greengrass is not already set up
    # or if force redeploy is requested
    if [[ "$FORCE_REDEPLOY" == "true" ]] || [[ ! -d "$GREENGRASS_FOLDER/v2/GreengrassCore" ]]; then
        createGreengrassFolder
        downloadGreengrassNucleus
        installCertificates
        clearSensitiveEnv  # Clear sensitive environment variables after writing to disk
        setCertificatesACL
        
        # If auto-deploy is enabled, configure AWS and run deployment
        if [[ "$AUTO_DEPLOY" == "true" ]]; then
            # Wait a bit for things to initialize
            sleep 10
            configureAwsCredentials
            forceRedeploy
        fi
        installGreengrass
    else
        echo "Greengrass already installed. Skipping installation steps."
        clearSensitiveEnv  # Always clear sensitive variables even on skip
        
        # We should still auto-deploy on restart if enabled
        if [[ "$AUTO_DEPLOY" == "true" ]]; then
            configureAwsCredentials
            forceRedeploy
        fi
    fi
    
    startGreengrass
}

main

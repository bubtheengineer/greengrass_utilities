#!/usr/bin/env python3
"""
Greengrass Certificate Installer - Standalone Version

This utility retrieves self-signed certificates for a Greengrass device and installs them
in the local truststore. It can either save the certificates to a specified directory
or install them directly into the Windows certificate store.

Dependencies:
- AWS IoT Device SDK for Python v2 (awsiotsdk)
"""

import os
import sys
import argparse
import platform
import subprocess
from typing import List, Optional, Tuple

# Check for required dependencies
try:
    import awscrt.auth
    import awscrt.io
    from awsiot.greengrass_discovery import DiscoveryClient
except ImportError:
    print("ERROR: Required dependencies not found.")
    print("Please install the AWS IoT Device SDK for Python v2:")
    print("pip install awsiotsdk")
    sys.exit(1)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Retrieve and install Greengrass self-signed certificates"
    )
    
    parser.add_argument("--certificate", "-c", required=True,
                        help="Path to the client certificate file")
    parser.add_argument("--private-key", "-k", required=True,
                        help="Path to the client private key file")
    parser.add_argument("--thing-name", "-t", required=True,
                        help="The name of the IoT thing")
    parser.add_argument("--region", "-r", default="us-east-1",
                        help="AWS region (default: us-east-1)")
    parser.add_argument("--endpoint", "-e", default=None,
                        help="Custom endpoint override (optional)")
    parser.add_argument("--port", "-p", type=int, default=8443,
                        help="Port to use for discovery (default: 8443)")
    parser.add_argument("--output-dir", "-o", default=None,
                        help="Directory to save certificates (default: current directory)")
    parser.add_argument("--install-windows-store", "-w", action="store_true",
                        help="Install certificates to Windows certificate store (Windows only)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging")
    
    return parser.parse_args()

def validate_args(args) -> bool:
    """Validate command line arguments."""
    # Check if certificate file exists
    if not os.path.isfile(args.certificate):
        print(f"ERROR: Certificate file not found: {args.certificate}")
        return False
    
    # Check if private key file exists
    if not os.path.isfile(args.private_key):
        print(f"ERROR: Private key file not found: {args.private_key}")
        return False
    
    # Check if output directory exists or can be created
    if args.output_dir and not os.path.exists(args.output_dir):
        try:
            os.makedirs(args.output_dir)
        except OSError as e:
            print(f"ERROR: Cannot create output directory: {args.output_dir}")
            print(f"       {e}")
            return False
    
    # Check if Windows store installation is requested on non-Windows system
    if args.install_windows_store and platform.system() != "Windows":
        print("WARNING: Windows certificate store installation is only available on Windows.")
        print("         Certificates will be saved to the specified directory instead.")
    
    return True

def setup_discovery_client(args):
    """Set up the Greengrass discovery client."""
    # Configure logging
    log_level = awscrt.io.LogLevel.Debug if args.verbose else awscrt.io.LogLevel.Info
    awscrt.io.init_logging(log_level, 'stderr')

    # Create IoT client configuration
    event_loop_group = awscrt.io.EventLoopGroup(1)
    host_resolver = awscrt.io.DefaultHostResolver(event_loop_group)
    client_bootstrap = awscrt.io.ClientBootstrap(event_loop_group, host_resolver)
    socket_options = awscrt.io.SocketOptions()

    # Set up TLS context with client certificate
    try:
        tls_context = awscrt.io.ClientTlsContext(
            awscrt.io.TlsContextOptions.create_client_with_mtls_from_path(
                args.certificate,
                args.private_key
            )
        )
    except Exception as e:
        print(f"ERROR: Failed to create TLS context with provided certificates:")
        print(f"       {e}")
        sys.exit(1)

    # Create discovery client
    discovery_client = DiscoveryClient(
        bootstrap=client_bootstrap,
        socket_options=socket_options,
        tls_context=tls_context,
        region=args.region,
        gg_server_name=args.endpoint
    )

    # Specify different port if needed
    if args.port != 8443 and args.port != 443:
        discovery_client.port = args.port
        
    return discovery_client

def save_certificates(gg_groups, output_dir=None) -> List[str]:
    """Save certificates to the specified directory."""
    saved_certs = []
    
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    for gg_group in gg_groups:
        print(f"\nGreengrass Group: {gg_group.gg_group_id}")

        # Save CA certificates
        for i, ca_cert in enumerate(gg_group.certificate_authorities):
            cert_filename = f"{gg_group.gg_group_id}_{i}.pem"
            if output_dir:
                cert_path = os.path.join(output_dir, cert_filename)
            else:
                cert_path = cert_filename
                
            try:
                with open(cert_path, 'w') as f:
                    f.write(ca_cert)
                print(f"Saved CA certificate to: {cert_path}")
                saved_certs.append(cert_path)
            except IOError as e:
                print(f"ERROR: Failed to save certificate to {cert_path}: {e}")

        # Print connectivity info
        for core in gg_group.cores:
            print(f"  Core: {core.thing_arn}")
            for conn in core.connectivity:
                print(f"    Endpoint: {conn.host_address}:{conn.port}")
                if conn.metadata:
                    print(f"    Metadata: {conn.metadata}")
    
    return saved_certs

def is_admin() -> bool:
    """Check if the script is running with administrative privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def install_windows_certificates(cert_paths: List[str]) -> bool:
    """Install certificates into the Windows certificate store."""
    if platform.system() != "Windows":
        print("Windows certificate store installation is only available on Windows")
        return False
    
    if not is_admin():
        print("WARNING: Administrative privileges are required to install certificates to the Windows store.")
        print("         Please run this script as an administrator.")
        return False
    
    try:
        for cert_path in cert_paths:
            # Use certutil to add the certificate to the Windows Root CA store
            cmd = ["certutil", "-addstore", "ROOT", cert_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"Successfully installed certificate {cert_path} to Windows certificate store")
            else:
                print(f"Failed to install certificate {cert_path}: {result.stderr}")
                return False
        return True
    except Exception as e:
        print(f"Error installing certificates to Windows store: {e}")
        return False

def perform_discovery(discovery_client, thing_name) -> Tuple[bool, Optional[object]]:
    """Perform Greengrass discovery and return the result."""
    try:
        # Perform discovery
        future_response = discovery_client.discover(thing_name)
        
        # Block until discovery is complete
        discovery_result = future_response.result()
        
        if discovery_result and discovery_result.gg_groups:
            return True, discovery_result
        else:
            print("No Greengrass groups found in discovery response")
            return False, None
    except Exception as e:
        print(f"ERROR: Discovery failed: {e}")
        return False, None

def main():
    """Main function."""
    args = parse_args()
    
    # Validate arguments
    if not validate_args(args):
        return 1
    
    print(f"Performing discovery for thing: {args.thing_name}")
    print(f"Using client certificate: {args.certificate}")
    print(f"Using private key: {args.private_key}")
    
    # Create discovery client
    discovery_client = setup_discovery_client(args)
    
    # Perform discovery
    success, discovery_result = perform_discovery(discovery_client, args.thing_name)
    if not success:
        return 1
    
    print("\nDiscovery successful!")
    
    # Save certificates to the specified directory
    cert_paths = save_certificates(discovery_result.gg_groups, args.output_dir)
    
    if not cert_paths:
        print("ERROR: No certificates were saved")
        return 1
    
    # Install certificates to Windows store if requested
    if args.install_windows_store:
        if platform.system() == "Windows":
            success = install_windows_certificates(cert_paths)
            if success:
                print("All certificates successfully installed to Windows certificate store")
            else:
                print("Failed to install some certificates to Windows certificate store")
        else:
            print("Windows certificate store installation is only available on Windows")
    
    print("\nDiscovery and certificate installation complete")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {e}")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)

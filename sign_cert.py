#!/usr/bin/env python3
"""
Certificate Signing Script
Signs Certificate Signing Requests (CSR) using an existing Root CA
Supports both end-entity certificates and Sub CA (intermediate) certificates
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime

def sign_certificate(
    csr_path,
    ca_cert_path,
    ca_key_path,
    output_cert_path,
    validity_days=365,
    ca_key_password=None,
    is_ca=False,
    path_length=None
):
    """
    Sign a CSR with a Root CA certificate and private key.
    
    Args:
        csr_path: Path to the CSR file
        ca_cert_path: Path to the CA certificate file
        ca_key_path: Path to the CA private key file
        output_cert_path: Path where signed certificate will be saved
        validity_days: Number of days the certificate is valid (default: 365)
        ca_key_password: Password for the CA private key (if encrypted)
        is_ca: Whether this is a CA certificate (Sub CA/Intermediate)
        path_length: Maximum number of CAs that can follow this CA (None = unlimited)
    """
    
    # Load the CSR
    with open(csr_path, 'rb') as f:
        csr = x509.load_pem_x509_csr(f.read(), default_backend())
    
    # Load the CA certificate
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # Load the CA private key
    with open(ca_key_path, 'rb') as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=ca_key_password.encode() if ca_key_password else None,
            backend=default_backend()
        )
    
    # Build the certificate
    builder = x509.CertificateBuilder()
    
    # Set subject from CSR
    builder = builder.subject_name(csr.subject)
    
    # Set issuer from CA certificate
    builder = builder.issuer_name(ca_cert.subject)
    
    # Set public key from CSR
    builder = builder.public_key(csr.public_key())
    
    # Generate serial number
    builder = builder.serial_number(x509.random_serial_number())
    
    # Set validity period
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
    )
    
    # Add extensions based on certificate type
    if is_ca:
        # Sub CA Certificate Extensions
        print("🏛️  Creating Sub CA (Intermediate) Certificate")
        
        # Basic Constraints (critical for CA)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True
        )
        
        # Key Usage for CA
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,  # Can sign certificates
                crl_sign=True,       # Can sign CRLs
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
    else:
        # End-Entity Certificate Extensions
        print("📄 Creating End-Entity Certificate")
        
        # Subject Alternative Name (if present in CSR)
        try:
            san_extension = csr.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            builder = builder.add_extension(
                san_extension.value,
                critical=san_extension.critical
            )
        except x509.ExtensionNotFound:
            pass
        
        # Basic Constraints (not a CA)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        
        # Key Usage for end-entity
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Extended Key Usage (for server/client authentication)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False
        )
    
    # Add Subject Key Identifier (common for both)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False
    )
    
    # Add Authority Key Identifier (common for both)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False
    )
    
    # Sign the certificate
    certificate = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    # Write the signed certificate to file
    with open(output_cert_path, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"✅ Certificate signed successfully!")
    print(f"📄 Output: {output_cert_path}")
    print(f"📅 Valid for: {validity_days} days")
    print(f"🔑 Serial Number: {certificate.serial_number}")
    if is_ca:
        path_info = f"path_length={path_length}" if path_length is not None else "unlimited"
        print(f"🏛️  CA Certificate: {path_info}")

def create_csr(
    common_name,
    output_csr_path,
    output_key_path,
    country=None,
    state=None,
    locality=None,
    organization=None,
    organizational_unit=None,
    san_dns=None,
    key_size=2048,
    key_password=None
):
    """
    Create a new CSR and private key.
    
    Args:
        common_name: Common Name (CN) for the certificate
        output_csr_path: Path to save the CSR
        output_key_path: Path to save the private key
        country: Country (C)
        state: State or Province (ST)
        locality: Locality (L)
        organization: Organization (O)
        organizational_unit: Organizational Unit (OU)
        san_dns: List of DNS names for Subject Alternative Name
        key_size: RSA key size (default: 2048)
        key_password: Password to encrypt the private key (optional)
    """
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Build subject name
    subject_components = [
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ]
    
    if country:
        subject_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    if organization:
        subject_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if organizational_unit:
        subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
    
    subject = x509.Name(subject_components)
    
    # Build CSR
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    
    # Add SAN if provided
    if san_dns:
        san_list = [x509.DNSName(dns) for dns in san_dns]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
    
    # Sign CSR with private key
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    
    # Save CSR
    with open(output_csr_path, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    
    # Save private key
    encryption = serialization.BestAvailableEncryption(key_password.encode()) if key_password else serialization.NoEncryption()
    
    with open(output_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        ))
    
    print(f"✅ CSR and private key created successfully!")
    print(f"📄 CSR: {output_csr_path}")
    print(f"🔑 Private Key: {output_key_path}")

def main():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Sign CSRs or create new CSRs with a Root CA certificate',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sign an end-entity certificate
  python sign_cert.py sign --csr server.csr --ca-cert ca.crt --ca-key ca.key --output server.crt
  
  # Sign a Sub CA certificate
  python sign_cert.py sign --csr subca.csr --ca-cert rootca.crt --ca-key rootca.key --output subca.crt --sub-ca --path-length 0
  
  # Create a new CSR
  python sign_cert.py create-csr --cn "example.com" --output-csr server.csr --output-key server.key --san example.com --san www.example.com
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Sign command
    sign_parser = subparsers.add_parser('sign', help='Sign a CSR')
    sign_parser.add_argument('--csr', required=True, help='Path to CSR file')
    sign_parser.add_argument('--ca-cert', required=True, help='Path to CA certificate')
    sign_parser.add_argument('--ca-key', required=True, help='Path to CA private key')
    sign_parser.add_argument('--output', required=True, help='Output certificate path')
    sign_parser.add_argument('--days', type=int, default=365, help='Validity in days (default: 365)')
    sign_parser.add_argument('--password', help='CA key password (if encrypted)')
    sign_parser.add_argument('--sub-ca', action='store_true', help='Create a Sub CA (intermediate) certificate')
    sign_parser.add_argument('--path-length', type=int, help='Path length constraint for Sub CA (0 = no further CAs)')
    
    # Create CSR command
    csr_parser = subparsers.add_parser('create-csr', help='Create a new CSR and private key')
    csr_parser.add_argument('--cn', required=True, help='Common Name (CN)')
    csr_parser.add_argument('--output-csr', required=True, help='Output CSR path')
    csr_parser.add_argument('--output-key', required=True, help='Output private key path')
    csr_parser.add_argument('--country', help='Country (C)')
    csr_parser.add_argument('--state', help='State or Province (ST)')
    csr_parser.add_argument('--locality', help='Locality (L)')
    csr_parser.add_argument('--org', help='Organization (O)')
    csr_parser.add_argument('--ou', help='Organizational Unit (OU)')
    csr_parser.add_argument('--san', action='append', help='Subject Alternative Name (DNS). Can be used multiple times')
    csr_parser.add_argument('--key-size', type=int, default=2048, help='RSA key size (default: 2048)')
    csr_parser.add_argument('--key-password', help='Password to encrypt the private key')
    
    args = parser.parse_args()
    
    if args.command == 'sign':
        sign_certificate(
            csr_path=args.csr,
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            output_cert_path=args.output,
            validity_days=args.days,
            ca_key_password=args.password,
            is_ca=args.sub_ca,
            path_length=args.path_length
        )
    elif args.command == 'create-csr':
        create_csr(
            common_name=args.cn,
            output_csr_path=args.output_csr,
            output_key_path=args.output_key,
            country=args.country,
            state=args.state,
            locality=args.locality,
            organization=args.org,
            organizational_unit=args.ou,
            san_dns=args.san,
            key_size=args.key_size,
            key_password=args.key_password
        )
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
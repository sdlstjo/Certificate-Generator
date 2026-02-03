#!/usr/bin/env python3
"""
Certificate Signing Script
Signs a Certificate Signing Request (CSR) using an existing Root CA
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
    ca_key_password=None
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
    
    # Add extensions
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
    
    # Add Basic Constraints (not a CA)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    
    # Add Key Usage
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
    
    # Add Extended Key Usage (for server/client authentication)
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        ]),
        critical=False
    )
    
    # Add Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False
    )
    
    # Add Authority Key Identifier
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

def main():
    """Example usage"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Sign a CSR with a Root CA certificate'
    )
    parser.add_argument('--csr', required=True, help='Path to CSR file')
    parser.add_argument('--ca-cert', required=True, help='Path to CA certificate')
    parser.add_argument('--ca-key', required=True, help='Path to CA private key')
    parser.add_argument('--output', required=True, help='Output certificate path')
    parser.add_argument('--days', type=int, default=365, help='Validity in days')
    parser.add_argument('--password', help='CA key password (if encrypted)')
    
    args = parser.parse_args()
    
    sign_certificate(
        csr_path=args.csr,
        ca_cert_path=args.ca_cert,
        ca_key_path=args.ca_key,
        output_cert_path=args.output,
        validity_days=args.days,
        ca_key_password=args.password
    )

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
Root CA and Subordinate CA Generator

This script creates a root Certificate Authority (CA) and a subordinate CA
with proper certificate chain relationships.

Requirements: pip install cryptography
"""

import os
import json
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from argparse import ArgumentParser, SUPPRESS
from sys import platform
from colorama import init
from termcolor import cprint, colored
from pyfiglet import figlet_format, Figlet

parser = ArgumentParser()
parser.add_argument("-hn", "--host_name", default="host", help="End entity host name")
parser.add_argument("-dn1", "--domain_name_1", default="domain.com", help="Root Domain name")
parser.add_argument("-dn2", "--domain_name_2", default="pki.domain.com", help="Sub Domain Name")
parser.add_argument("-ip", "--host_ip_address", default="", help="Host IP Address")

parser.add_argument("--support_dir", default="support_files", help=SUPPRESS)
parser.add_argument("--ca_dir", default="pki", help=SUPPRESS)
parser.add_argument("--config_file", default="certificate_config_bb.json", help=SUPPRESS)
parser.add_argument("--debug", action="store_true", help=SUPPRESS)

if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)
args = parser.parse_args()
config = vars(args)
script_name="SJ Cert-Tool" 
script_version="2025-09-30v01"
init(strip=not sys.stdout.isatty()) # strip colors if stdout is redirected
cwd = os.getcwd()  # Current working directory, change if you want files somewhere else

if platform == "linux" or platform == "linux2":
    divider="/"
elif platform == "darwin":
    divider="/"
elif platform == "win32":
    divider='\''
else:
    divider="/"


try:
    with open(cwd + divider + config['support_dir'] + divider + config['config_file']) as f:
        conf_dict = json.load(f)
        f.close()
except Exception as e:
    print(e, f)

# Read config file to dict



class CAGenerator:
    def __init__(self, output_dir=config['ca_dir']):
        """Initialize the CA generator with output directory."""
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_private_key(self, key_size=2048):
        """Generate an RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
    
    def create_root_ca(self, 
                       common_name=conf_dict['organization_name'] + "Root CA",
                       country=conf_dict['country_name'],
                       state=conf_dict['state_or_province_name'], 
                       city=conf_dict['locality_name'],
                       organization=conf_dict['organization_name'],
                       validity_days=conf_dict['ca_validity_age']):
        """Create a root CA certificate and private key."""
        
        root_key_path = os.path.join(self.output_dir, conf_dict['ca_private_key_path'])
        root_cert_path = os.path.join(self.output_dir, conf_dict['ca_certificate_path'])
        if not os.path.exists(root_cert_path):
            print("Generating Root CA...")
            
            # Generate private key for root CA
            root_key = self.generate_private_key()
            
            # Create certificate subject
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, city),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
            
            # Create root CA certificate
            root_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                root_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=validity_days)
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).sign(root_key, hashes.SHA256())
            
            # Save root CA private key
            with open(root_key_path, "wb") as f:
                f.write(root_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save root CA certificate
            with open(root_cert_path, "wb") as f:
                f.write(root_cert.public_bytes(serialization.Encoding.PEM))
            
            print(f"Root CA private key saved to: {root_key_path}")
            print(f"Root CA certificate saved to: {root_cert_path}")

        else:
            print("Loading Root CA...")
            with open(root_cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                root_cert = x509.load_pem_x509_certificate(cert_data)
                print(f"Root CA certificate loaded succesfully from: {root_cert_path}")

            with open(root_key_path, 'rb') as key_file:
                key_data = key_file.read()
                root_key = load_pem_private_key(key_data, password=None)
                print(f"Root CA private key loaded succesfully from: {root_key_path}")

        return root_key, root_cert
    
    def create_subordinate_ca(self,
                              root_key,
                              root_cert,
                              common_name=conf_dict['organization_name'] + "Subordinate CA",
                              country=conf_dict['country_name'],
                              state=conf_dict['state_or_province_name'], 
                              city=conf_dict['locality_name'],
                              organization=conf_dict['organization_name'],
                              organizational_unit=conf_dict['organization_unitname'],
                              validity_days=conf_dict['sub_ca_validity_age']):
        
        """Create a subordinate CA signed by the root CA."""
        sub_key_path = os.path.join(self.output_dir, conf_dict['sub_ca_private_key_path'])
        sub_cert_path = os.path.join(self.output_dir, conf_dict['sub_ca_certificate_path'])
        chain_path = os.path.join(self.output_dir, conf_dict['ca_chain_path'])
        if not os.path.exists(sub_cert_path):
            print("Generating Subordinate CA...")

            # Generate private key for subordinate CA
            sub_key = self.generate_private_key()
            
            # Create certificate subject
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, city),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
            
            # Create subordinate CA certificate (signed by root CA)
            sub_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                root_cert.subject
            ).public_key(
                sub_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=validity_days)
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(sub_key.public_key()),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=0),  # Path length 0 means no sub-CAs
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).sign(root_key, hashes.SHA256())  # Signed by root CA private key
            
            # Save subordinate CA private key
            with open(sub_key_path, "wb") as f:
                f.write(sub_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save subordinate CA certificate
            with open(sub_cert_path, "wb") as f:
                f.write(sub_cert.public_bytes(serialization.Encoding.PEM))
            
            # Create certificate chain file (subordinate + root)
            with open(chain_path, "wb") as f:
                f.write(sub_cert.public_bytes(serialization.Encoding.PEM))
                f.write(root_cert.public_bytes(serialization.Encoding.PEM))
            
            print(f"Subordinate CA private key saved to: {sub_key_path}")
            print(f"Subordinate CA certificate saved to: {sub_cert_path}")
            print(f"Certificate chain saved to: {chain_path}")
        else:
            print("Loading Subordinate CA...")
            with open(sub_cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                sub_cert = x509.load_pem_x509_certificate(cert_data)
                print(f"Subordinate CA certificate loaded successfully from: {sub_cert_path}")

            with open(sub_key_path, 'rb') as key_file:
                key_data = key_file.read()
                sub_key = load_pem_private_key(key_data, password=None)
                print(f"Subordinate CA private key loaded successfully from: {sub_cert_path}")

        
        return sub_key, sub_cert
    
    def create_end_entity_cert(self,
                               sub_key,
                               sub_cert,
                               common_name="www.example.com",
                               sans=None,
                               country=conf_dict['country_name'],
                               state=conf_dict['state_or_province_name'], 
                               city=conf_dict['locality_name'],
                               organization=conf_dict['organization_name'],
                               organizational_unit=conf_dict['organization_unitname'],
                               validity_days=conf_dict['host_validity_age']):
        """Create an end-entity certificate signed by the subordinate CA."""
        
        entity_key_path = os.path.join(self.output_dir, common_name, f"{common_name}_private_key.pem")
        entity_cert_path = os.path.join(self.output_dir, common_name, f"{common_name}_certificate.pem")
        if not os.path.exists(entity_cert_path):
            if not os.path.exists(os.path.join(self.output_dir, common_name)):
                os.mkdir(os.path.join(self.output_dir, common_name))
            print(f"Generating end-entity certificate for {common_name}...")
            
            # Generate private key for end-entity certificate
            entity_key = self.generate_private_key()
            
            # Create certificate subject
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, city),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
            
            # Create certificate builder
            builder = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                sub_cert.subject
            ).public_key(
                entity_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=validity_days)
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(entity_key.public_key()),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(sub_key.public_key()),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=True,
            )
            
            # Add Subject Alternative Names if provided
            if sans:
                san_list = []
                for san in sans:
                    if san.startswith('*.') or '.' in san:
                        san_list.append(x509.DNSName(san))
                    else:
                        san_list.append(x509.IPAddress(san))
                
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False,
                )
            
            # Sign the certificate with subordinate CA
            entity_cert = builder.sign(sub_key, hashes.SHA256())
            
            # Save end-entity private key
            with open(entity_key_path, "wb") as f:
                f.write(entity_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save end-entity certificate
            with open(entity_cert_path, "wb") as f:
                f.write(entity_cert.public_bytes(serialization.Encoding.PEM))
            
            print(f"End-entity private key saved to: {entity_key_path}")
            print(f"End-entity certificate saved to: {entity_cert_path}")
            return entity_key, entity_cert

        if os.path.exists(entity_cert_path):
            print(f"end-entity certificate {common_name} already exists ...")




def main():
    """Main function to demonstrate CA creation."""
    
    print("=== Certificate Authority Generator ===\n")
    
    # Initialize CA generator
    ca_gen = CAGenerator()
    
    # Create root CA
    root_key, root_cert = ca_gen.create_root_ca(
        common_name="The Johansson Root CA",
        organization="The Johansson Corporation",
        validity_days=3650  # 10 years
    )
    
    print()
    
    # Create subordinate CA
    sub_key, sub_cert = ca_gen.create_subordinate_ca(
        root_key,
        root_cert,
        common_name="The Johansson Subordinate CA",
        organization="The Johansson",
        organizational_unit="Margarita Loop",
        validity_days=1825  # 5 years
    )
    
    print()
    
    # Create an example end-entity certificate
    if config['host_ip_address'] == "":
        ca_gen.create_end_entity_cert(
            sub_key,
            sub_cert,
            common_name=config['host_name'] + "." + conf_dict['sub_domain_name'],
            sans=[conf_dict['root_domain_name'], conf_dict['sub_domain_name'], "*." + conf_dict['sub_domain_name']],
            validity_days=365
        )
    else:
        ca_gen.create_end_entity_cert(
            sub_key,
            sub_cert,
            common_name=config['host_name'] + "." + conf_dict['sub_domain_name'],
            sans=[conf_dict['root_domain_name'], conf_dict['sub_domain_name'], "*." + conf_dict['sub_domain_name'], config['host_ip_address']],
            validity_days=365
        )

    # print("\n=== Certificate Generation Complete ===")
    # print(f"All certificates and keys have been saved to/loaded from the '{ca_gen.output_dir}' directory.")
    # print("\nCertificate chain hierarchy:")
    # print("1. Root CA (self-signed)")
    # print("2. Subordinate CA (signed by Root CA)")
    # print("3. End-entity certificate (signed by Subordinate CA)")
    
    # print("\nFiles created:")
    # for file in os.listdir(ca_gen.output_dir):
    #     print(f"  - {file}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Root CA and Subordinate CA Generator

This script creates a root Certificate Authority (CA) and a subordinate CA
with proper certificate chain relationships.

Requirements: pip install cryptography
"""
import os

class CAGenerator:
    def create_root_ca(self, 
                        common_name="Root CA",
                        country="US",
                        state="State", 
                        city="City",
                        organization="Company",
                        validity_days=3650):
            """Create a root CA certificate and private key."""
            
            root_key_path = os.path.join(self.output_dir, "/Path/", "Test")
            print(root_key_path)

print("Before Function")
CAGenerator.create_root_ca()
print("After Function")

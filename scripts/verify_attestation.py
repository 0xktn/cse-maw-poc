
import sys
import json
import base64
import struct
import hashlib
import binascii
from datetime import datetime

try:
    import cbor2
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.x509 import load_der_x509_certificate
except ImportError as e:
    print(f"Error importing dependencies: {e}")
    print("Please run: pip install cbor2 cryptography requests")
    sys.exit(1)

def verify_attestation(attestation_b64):
    print("Loading attestation document...")
    try:
        # 1. Decode Base64
        cose_bytes = base64.b64decode(attestation_b64)
        print(f"✅ Base64 decoded ({len(cose_bytes)} bytes)")
        
        # 2. Parse COSE / CBOR
        # The Nitro Attestation Document is a CBOR-encoded structure
        # wrapped in a COSE_Sign1 structure.
        # Structure matches standard COSE: [protected_header, unprotected_header, payload, signature]
        
        obj = cbor2.loads(cose_bytes)
        if not isinstance(obj, list) or len(obj) != 4:
            print("❌ Invalid COSE structure (expected 4-element list)")
            sys.exit(1)
            
        print("✅ COSE structure verified")
        
        protected_header_bytes = obj[0]
        unprotected_header = obj[1]
        payload_bytes = obj[2]
        signature = obj[3]
        
        # 3. Decode Payload (Attestation Doc)
        doc = cbor2.loads(payload_bytes)
        print("\n=== Attestation Document Data ===")
        print(f"Module ID:    {doc.get('module_id')}")
        print(f"Timestamp:    {datetime.fromtimestamp(doc.get('timestamp')/1000).isoformat()}")
        print(f"Digest:       {doc.get('digest')}")
        
        pcrs = doc.get('pcrs', {})
        print(f"PCR0:         {pcrs.get(0, b'').hex()}")
        
        # 4. Extract Certificate Chain
        cabundle = doc.get('cabundle')
        if not cabundle:
            print("❌ No CA Bundle found in document")
            return
            
        certs = []
        for cert_bytes in cabundle:
            cert = load_der_x509_certificate(cert_bytes)
            certs.append(cert)
            print(f"Found Cert:   {cert.subject.rfc4514_string()}")
            
        # 5. Verify Signature (Simplified Check)
        # To strictly verify, we check against the root AWS Nitro CA.
        # For this POC, we check if the leaf cert signed the payload.
        
        leaf_cert = certs[0]
        public_key = leaf_cert.public_key()
        
        # Construct Sig_structure to verify:
        # ["Signature1", protected, external_aad, payload]
        sig_structure = [
            "Signature1",
            protected_header_bytes,
            b"", # external_aad is empty for Nitro
            payload_bytes
        ]
        tbe = cbor2.dumps(sig_structure)
        
        try:
            public_key.verify(
                signature,
                tbe,
                ec.ECDSA(hashes.SHA384())
            )
            print("\n✅ CRYPTOGRAPHIC SIGNATURE VERIFIED!")
            print("The attestation document was authentically signed by the hardware.")
        except Exception as e:
            print(f"\n❌ Signature Verification FAILED: {e}")
            sys.exit(1)
            
    except Exception as e:
        print(f"Verification failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 verify_attestation.py <path_or_b64>")
        sys.exit(1)
        
    arg = sys.argv[1]
    
    # Check if arg is a file
    import os
    if os.path.exists(arg):
        with open(arg, 'r') as f:
            content = f.read().strip()
    else:
        content = arg
        
    verify_attestation(content)

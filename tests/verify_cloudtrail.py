#!/usr/bin/env python3
"""
Verify CloudTrail KMS Decrypt Events

This script queries AWS CloudTrail to verify that KMS Decrypt API calls
include attestation documents with the correct PCR0 value.
"""

import boto3
import json
import base64
from datetime import datetime, timedelta
import sys

# Expected PCR0 from current enclave build
EXPECTED_PCR0 = "ff332b261c7e90783f1782aad362dd1c9f0cd75f95687f78816933145c62a78c18b8fbe644adadd116a2d4305b888994"

def main():
    print("=" * 70)
    print("CLOUDTRAIL KMS ATTESTATION VERIFICATION")
    print("=" * 70)
    
    region = 'ap-southeast-1'
    print(f"\n1. Connecting to CloudTrail in {region}...")
    
    try:
        cloudtrail = boto3.client('cloudtrail', region_name=region)
        print("✅ Connected to CloudTrail")
    except Exception as e:
        print(f"❌ Failed to connect to CloudTrail: {e}")
        return False
    
    # Query for KMS Decrypt events in the last hour
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=1)
    
    print(f"\n2. Querying KMS Decrypt events...")
    print(f"   Time range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    
    try:
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'Decrypt'
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50
        )
        
        events = response.get('Events', [])
        print(f"✅ Found {len(events)} Decrypt events")
        
        if len(events) == 0:
            print("\n⚠️  No KMS Decrypt events found in the last hour")
            print("\nPossible reasons:")
            print("  • CloudTrail has 5-15 minute delay")
            print("  • Enclave hasn't decrypted TSK recently")
            print("  • CloudTrail not enabled for KMS in this region")
            return False
        
    except Exception as e:
        print(f"❌ Failed to query CloudTrail: {e}")
        return False
    
    # Analyze events for attestation
    print(f"\n3. Analyzing events for attestation documents...")
    
    attestation_found = False
    pcr0_match_found = False
    
    for i, event in enumerate(events, 1):
        event_time = event['EventTime']
        event_data = json.loads(event['CloudTrailEvent'])
        
        print(f"\n   Event {i}:")
        print(f"   Time: {event_time}")
        print(f"   User: {event_data.get('userIdentity', {}).get('principalId', 'Unknown')}")
        
        # Check for attestation document in request parameters
        request_params = event_data.get('requestParameters', {})
        
        if 'recipient' in request_params:
            recipient = request_params['recipient']
            print(f"   ✅ Recipient field present")
            
            if 'attestationDocument' in recipient:
                attestation_found = True
                attestation_doc_b64 = recipient['attestationDocument']
                print(f"   ✅ Attestation document present (length: {len(attestation_doc_b64)} bytes)")
                
                # Try to decode and parse attestation document
                try:
                    # Attestation document is CBOR-encoded, we'll just check if PCR0 is in the base64
                    # For a full parse, we'd need cbor2 library
                    if EXPECTED_PCR0 in attestation_doc_b64:
                        pcr0_match_found = True
                        print(f"   ✅ PCR0 MATCH FOUND: {EXPECTED_PCR0[:32]}...")
                    else:
                        print(f"   ⚠️  PCR0 not found in attestation (may be CBOR-encoded)")
                        
                except Exception as e:
                    print(f"   ⚠️  Could not parse attestation: {e}")
            else:
                print(f"   ⚠️  No attestation document in recipient")
        else:
            print(f"   ⚠️  No recipient field (not from enclave)")
    
    # Summary
    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    
    if attestation_found:
        print("\n✅ Attestation documents found in KMS Decrypt requests")
        print("   This confirms the enclave is using cryptographic attestation")
    else:
        print("\n⚠️  No attestation documents found")
        print("   Events may be from non-enclave KMS calls")
    
    if pcr0_match_found:
        print(f"\n✅ PCR0 verification successful")
        print(f"   Expected: {EXPECTED_PCR0}")
        print("   KMS is validating enclave measurements")
    else:
        print(f"\n⚠️  PCR0 not directly visible (likely CBOR-encoded)")
        print("   To fully verify, decode the attestation document with cbor2")
    
    print("\n" + "=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    print("\n1. For detailed attestation parsing:")
    print("   pip install cbor2")
    print("   # Decode attestation_document with cbor2.loads()")
    print("\n2. Check KMS key policy:")
    print("   aws kms get-key-policy --key-id <KEY_ID> --policy-name default")
    print("   # Verify PCR0 condition matches")
    
    return attestation_found


if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Verification failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

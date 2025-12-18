"""
Test Elasticsearch connection for SIEM integration.
Run this script to verify connectivity before starting the server.
"""

import httpx
import asyncio
import sys

# Elasticsearch configuration
ES_URL = "https://10.10.4.151:9200"
ES_USERNAME = "elastic"
ES_PASSWORD = "5y1TPgd1u16uJIGMm2nL"

async def test_connection():
    """Test basic Elasticsearch connectivity."""
    print(f"Testing connection to: {ES_URL}")
    print(f"Username: {ES_USERNAME}")
    print("-" * 50)
    
    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            auth=(ES_USERNAME, ES_PASSWORD),
            verify=False  # Disable TLS verification for self-signed certs
        ) as client:
            # Test cluster health
            print("\n1. Testing cluster health...")
            response = await client.get(f"{ES_URL}/_cluster/health")
            if response.status_code == 200:
                health = response.json()
                print(f"   ✅ Cluster: {health.get('cluster_name', 'unknown')}")
                print(f"   ✅ Status: {health.get('status', 'unknown')}")
                print(f"   ✅ Nodes: {health.get('number_of_nodes', 0)}")
            else:
                print(f"   ❌ Failed: HTTP {response.status_code}")
                print(f"   Response: {response.text[:500]}")
                return False
            
            # Test index creation for ueba-alerts
            print("\n2. Testing ueba-alerts index...")
            response = await client.head(f"{ES_URL}/ueba-alerts-*")
            if response.status_code == 200:
                print("   ✅ ueba-alerts index pattern exists")
            else:
                print("   ⚠️ ueba-alerts index pattern not found (will be created on first alert)")
            
            # Test index creation for ueba-events
            print("\n3. Testing ueba-events index...")
            response = await client.head(f"{ES_URL}/ueba-events-*")
            if response.status_code == 200:
                print("   ✅ ueba-events index pattern exists")
            else:
                print("   ⚠️ ueba-events index pattern not found (will be created on first event)")
            
            # Test bulk API permission
            print("\n4. Testing bulk API permission...")
            test_doc = {
                "@timestamp": "2024-01-01T00:00:00Z",
                "test": True,
                "message": "UEBA connection test"
            }
            bulk_body = '{"index": {"_index": "ueba-test"}}\n' + \
                       '{"@timestamp": "2024-01-01T00:00:00Z", "test": true}\n'
            
            response = await client.post(
                f"{ES_URL}/_bulk",
                content=bulk_body,
                headers={"Content-Type": "application/x-ndjson"}
            )
            if response.status_code == 200:
                result = response.json()
                if not result.get("errors"):
                    print("   ✅ Bulk API working")
                    # Clean up test index
                    await client.delete(f"{ES_URL}/ueba-test")
                    print("   ✅ Cleaned up test index")
                else:
                    print(f"   ⚠️ Bulk API returned errors: {result}")
            else:
                print(f"   ❌ Bulk API failed: HTTP {response.status_code}")
                print(f"   Response: {response.text[:500]}")
            
            print("\n" + "=" * 50)
            print("✅ Elasticsearch connection test PASSED!")
            print("=" * 50)
            print("\nTo start the server with SIEM export, set these environment variables:")
            print(f"  set ES_USERNAME={ES_USERNAME}")
            print(f"  set ES_PASSWORD={ES_PASSWORD}")
            print("\nOr add them to your start script.")
            return True
            
    except httpx.ConnectError as e:
        print(f"\n❌ Connection Error: Cannot reach {ES_URL}")
        print(f"   Error: {e}")
        print("\nCheck:")
        print("  1. Elasticsearch is running on 10.10.4.151:9200")
        print("  2. Network connectivity (firewall, VPN)")
        print("  3. Port 9200 is open")
        return False
    except httpx.HTTPStatusError as e:
        print(f"\n❌ HTTP Error: {e.response.status_code}")
        if e.response.status_code == 401:
            print("   Authentication failed - check username/password")
        elif e.response.status_code == 403:
            print("   Access forbidden - check user permissions")
        print(f"   Response: {e.response.text[:500]}")
        return False
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        return False

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")  # Suppress SSL warnings
    
    success = asyncio.run(test_connection())
    sys.exit(0 if success else 1)

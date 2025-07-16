import asyncio
import pytest  # Using pytest for potential future expansion, but basic asserts work fine
from rpc_helper.rpc import RpcHelper
from rpc_helper.utils.models.settings_model import RPCConfigBase

# Configuration for the RPC Helper
rpc_config_dict = {
    "full_nodes": [{
        # Replace with your actual RPC URL
        "url": "https://eth.llamarpc.com"
    }],
    "retry": 3,
    "request_time_out": 10, # Increased timeout slightly for potentially slower calls
    "connection_limits":{
        "max_connections": 100,
        "max_keepalive_connections": 50,
        "keepalive_expiry": 300
    }
}

# --- Test Function ---

async def test_get_transaction_receipt_json():
    """Tests the get_transaction_receipt_json method."""

    # --- Setup ---
    rpc_config = RPCConfigBase(**rpc_config_dict)
    rpc_helper = RpcHelper(rpc_config)
    await rpc_helper.init()

    # --- Test Data ---
    # Replace with a valid transaction hash from the network specified in rpc_config_dict
    # Example hash (replace if this network/tx is not suitable):
    test_tx_hash = "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675"

    print(f"Fetching receipt for tx: {test_tx_hash}")

    # --- Call the method ---
    try:
        receipt = await rpc_helper.get_transaction_receipt_json(test_tx_hash)
        print(f"Received receipt: {receipt}")

        # --- Assertions ---
        assert receipt is not None, "Receipt should not be None"
        assert isinstance(receipt, dict), "Receipt should be a dictionary"

        # Check for essential keys (adjust based on expected JSON structure)
        assert "transactionHash" in receipt, "Receipt missing 'transactionHash' key"
        assert "blockNumber" in receipt, "Receipt missing 'blockNumber' key"
        assert "status" in receipt, "Receipt missing 'status' key"
        assert "from" in receipt, "Receipt missing 'from' key"
        assert "to" in receipt, "Receipt missing 'to' key"

        # Verify the transaction hash matches (case-insensitive)
        assert receipt["transactionHash"].lower() == test_tx_hash.lower(), \
               f"Receipt txHash ({receipt['transactionHash']}) does not match requested txHash ({test_tx_hash})"

        # Check status (usually '0x1' for success, '0x0' for failure)
        assert receipt["status"] in ["0x1", "0x0"], f"Unexpected status value: {receipt['status']}"

        print("Test passed!")

    except Exception as e:
        print(f"Test failed with exception: {e}")
        pytest.fail(f"An exception occurred: {e}")

# --- Run the Test --- (if running the script directly)

if __name__ == "__main__":
    print("Running test_get_transaction_receipt_json...")
    asyncio.run(test_get_transaction_receipt_json())
    print("Test finished.")

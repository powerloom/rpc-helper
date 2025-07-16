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

# Test the RPC Helper with isolated logging

from rpc_helper.utils.default_logger import get_logger, cleanup_rpc_helper_logging
from rpc_helper.utils.models.settings_model import LoggingConfig

# Test 1: Default RPC Helper logger (with file logging)
print("=== Test 1: Default RPC Helper Logger ===")
rpc_logger = get_logger()
rpc_logger.info("This is an RPC Helper info message")
rpc_logger.warning("This is an RPC Helper warning message")

# Test 2: Demonstrate that subsequent get_logger calls use the same configuration
print("\n=== Test 2: Subsequent Logger Calls (Same Config) ===")
rpc_logger2 = get_logger()  # This won't reconfigure
rpc_logger2.info("This uses the same configuration as the first logger")

# Test 3: Test with file logging disabled (requires cleanup first)
print("\n=== Test 3: Cleanup and Reconfigure Without File Logging ===")
cleanup_rpc_helper_logging()  # Remove existing handlers

config_no_files = LoggingConfig(
    module_name="RpcHelper_NoFiles",
    enable_file_logging=False  # Disable file logging
)
rpc_logger_no_files = get_logger(config_no_files)
rpc_logger_no_files.info("This should only appear in console, not files")
rpc_logger_no_files.error("This error should only appear in console")

# Test 4: Simulate external loguru usage (this should not interfere)
print("\n=== Test 4: External Loguru Usage ===")
from loguru import logger as external_logger

# Add a handler for external logs (simulating what other services might do)
external_logger.add("logs/external_service.log", filter=lambda record: not record.get("extra", {}).get("rpc_helper"))

external_logger.info("This is an external service log")
external_logger.warning("This external warning should not go to RPC Helper logs")

# Test 5: Verify RPC Helper logs still work after external logger setup
print("\n=== Test 5: RPC Helper Logs After External Setup ===")
rpc_logger_no_files.debug("RPC Helper debug message")
rpc_logger_no_files.success("RPC Helper success message")

print("\nCheck the logs/ directory to verify:")
print("- RPC Helper logs should NOT be in files (file logging disabled)")
print("- External logs should be in logs/external_service.log")
print("- No cross-contamination should occur")
print("- Console should show RPC Helper logs with proper formatting")

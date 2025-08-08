"""
Integration tests for RPCHelper with real Ethereum RPC endpoints.

These tests verify the library's functionality against real Ethereum networks.
They are marked as 'network' tests and can be skipped when network access is unavailable.

Tests cover all public methods that make external RPC calls using reliable contracts:
- WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
- USDC: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
- Uniswap V3 Factory: 0x1F98431c8aD98523631AE4a59f267346ea31F984
"""

import asyncio
import os

import httpx
import pytest

from rpc_helper.rpc import RpcHelper, get_contract_abi_dict
from rpc_helper.utils.exceptions import RPCException
from rpc_helper.utils.models.settings_model import RPCConfigBase, RPCNodeConfig

# Well-known Ethereum mainnet contract addresses
WETH_ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
UNISWAP_V3_FACTORY = "0x1F98431c8aD98523631AE4a59f267346ea31F984"
VITALIK_ADDRESS = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
KNOWN_TX_HASH = "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060"  # First ETH transaction
UNISWAP_V2_FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"

# Common ABIs for testing
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
]

UNISWAP_V3_FACTORY_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "tokenA", "type": "address"},
            {"internalType": "address", "name": "tokenB", "type": "address"},
            {"internalType": "uint24", "name": "fee", "type": "uint24"},
        ],
        "name": "getPool",
        "outputs": [{"internalType": "address", "name": "pool", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    }
]

# ERC20 Transfer event ABI for event log testing
TRANSFER_EVENT_ABI = {
    "anonymous": False,
    "inputs": [
        {"indexed": True, "name": "from", "type": "address"},
        {"indexed": True, "name": "to", "type": "address"},
        {"indexed": False, "name": "value", "type": "uint256"},
    ],
    "name": "Transfer",
    "type": "event",
}


class TestRpcIntegration:
    """Integration tests for RPCHelper."""

    @pytest.fixture(scope="class")
    def integration_config(self):
        """Provide configuration for integration tests."""
        # Use environment variables for RPC URLs to avoid hardcoding
        rpc_url = os.getenv("TEST_RPC_URL", "https://eth.llamarpc.com")

        return RPCConfigBase(
            full_nodes=[RPCNodeConfig(url=rpc_url)],
            archive_nodes=[RPCNodeConfig(url=rpc_url)],
            retry=2,
            request_time_out=30,
            connection_limits={
                "max_connections": 10,
                "max_keepalive_connections": 5,
                "keepalive_expiry": 60,
            },
        )

    # Block and Basic RPC Operations Tests
    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_get_current_block_number_real(self, integration_config):
        """Test getting current block number from real RPC endpoint."""
        helper = RpcHelper(integration_config)
        await helper.init()

        block_number = await helper.get_current_block_number()

        assert isinstance(block_number, int)
        assert block_number > 18_000_000  # Well past any reasonable mainnet block
        assert block_number < 999_999_999  # Reasonable upper bound

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_get_current_block_alternative(self, integration_config):
        """Test the alternative get_current_block method."""
        helper = RpcHelper(integration_config)
        await helper.init()

        block_number = await helper.get_current_block()

        assert isinstance(block_number, int)
        assert block_number > 18_000_000
        assert block_number < 999_999_999

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_eth_get_block_real(self, integration_config):
        """Test getting block data from real RPC endpoint."""
        helper = RpcHelper(integration_config)
        await helper.init()

        # Get a recent block
        current_block = await helper.get_current_block_number()
        test_block = max(1, current_block - 10)

        block_data = await helper.eth_get_block(test_block)

        assert block_data is not None
        assert isinstance(block_data, dict)
        assert "number" in block_data
        assert "hash" in block_data
        assert "timestamp" in block_data
        assert block_data["number"] == hex(test_block)

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_eth_get_block_latest(self, integration_config):
        """Test getting latest block."""
        helper = RpcHelper(integration_config)
        await helper.init()

        block_data = await helper.eth_get_block()  # No parameter = latest

        assert block_data is not None
        assert isinstance(block_data, dict)
        assert "number" in block_data
        assert "hash" in block_data
        assert "timestamp" in block_data

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_batch_eth_get_block_real(self, integration_config):
        """Test batch block retrieval from real RPC endpoint."""
        helper = RpcHelper(integration_config)
        await helper.init()

        current_block = await helper.get_current_block_number()
        from_block = max(1, current_block - 2)  # Last 3 blocks
        to_block = current_block

        blocks = await helper.batch_eth_get_block(from_block, to_block)

        assert isinstance(blocks, list)
        assert len(blocks) == to_block - from_block + 1

        for block in blocks:
            assert isinstance(block, dict)
            assert "number" in block["result"]
            assert "hash" in block["result"]
            assert "timestamp" in block["result"]

    # Transaction Tests
    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_get_transaction_from_hash_real(self, integration_config):
        """Test getting transaction details from real transaction hash."""
        helper = RpcHelper(integration_config)
        await helper.init()

        transaction = await helper.get_transaction_from_hash(KNOWN_TX_HASH)

        assert transaction is not None
        assert hasattr(transaction, "hash") or "hash" in transaction
        assert hasattr(transaction, "blockNumber") or "blockNumber" in transaction
        assert hasattr(transaction, "from") or "from" in transaction
        assert hasattr(transaction, "to") or "to" in transaction

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_get_transaction_receipt_real(self, integration_config):
        """Test getting transaction receipt from real transaction."""
        helper = RpcHelper(integration_config)
        await helper.init()

        receipt = await helper.get_transaction_receipt(KNOWN_TX_HASH)

        assert receipt is not None
        assert hasattr(receipt, "transactionHash") or "transactionHash" in receipt
        assert hasattr(receipt, "blockNumber") or "blockNumber" in receipt
        assert hasattr(receipt, "status") or "status" in receipt

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_get_transaction_receipt_json_real(self, integration_config):
        """Test getting transaction receipt in JSON format."""
        helper = RpcHelper(integration_config)
        await helper.init()

        receipt = await helper.get_transaction_receipt_json(KNOWN_TX_HASH)

        assert receipt is not None
        assert isinstance(receipt, dict)
        assert receipt["transactionHash"].lower() == KNOWN_TX_HASH.lower()
        assert "blockNumber" in receipt
        assert "status" in receipt
        assert receipt["status"] in ["0x0", "0x1"]

    # Balance Tests
    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_real(self, integration_config):
        """Test batch balance retrieval from real RPC endpoint."""
        helper = RpcHelper(integration_config)
        await helper.init()

        # Get current block
        current_block = await helper.get_current_block_number()
        from_block = max(1, current_block - 5)  # Last 5 blocks
        to_block = current_block

        balances = await helper.batch_eth_get_balance_on_block_range(
            address=VITALIK_ADDRESS, from_block=from_block, to_block=to_block
        )

        assert isinstance(balances, list)
        assert len(balances) == to_block - from_block + 1
        assert all(isinstance(balance, int) for balance in balances)
        assert all(balance >= 0 for balance in balances)

    # Web3 Call Tests
    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_web3_call_erc20_balance(self, integration_config):
        """Test web3_call with ERC20 balanceOf function."""
        helper = RpcHelper(integration_config)
        await helper.init()

        # Test WETH balance of a known address
        tasks = [("balanceOf", [VITALIK_ADDRESS])]

        results = await helper.web3_call(tasks=tasks, contract_addr=WETH_ADDRESS, abi=ERC20_ABI)

        assert isinstance(results, list)
        assert len(results) == 1
        assert isinstance(results[0], int)
        assert results[0] >= 0

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_web3_call_multiple_functions(self, integration_config):
        """Test web3_call with multiple ERC20 functions."""
        helper = RpcHelper(integration_config)
        await helper.init()

        tasks = [("symbol", []), ("decimals", []), ("totalSupply", [])]

        results = await helper.web3_call(tasks=tasks, contract_addr=WETH_ADDRESS, abi=ERC20_ABI)

        assert isinstance(results, list)
        assert len(results) == 3

        # Symbol should be "WETH"
        assert isinstance(results[0], str)
        assert results[0] == "WETH"

        # Decimals should be 18
        assert isinstance(results[1], int)
        assert results[1] == 18

        # Total supply should be a positive integer
        assert isinstance(results[2], int)
        assert results[2] > 0

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_web3_call_with_override(self, integration_config):
        """Test web3_call_with_override functionality."""
        helper = RpcHelper(integration_config)
        await helper.init()

        # Test with state override (simulate different balance)
        tasks = [("balanceOf", [VITALIK_ADDRESS])]

        # Since state overrides are complex to set up correctly,
        # we'll test that the method doesn't crash with empty overrides
        # Real overrides would look like:
        # overrides = {
        #     WETH_ADDRESS: {
        #         "stateDiff": {
        #             # State slot mappings for balances
        #         }
        #     }
        # }
        results = await helper.web3_call_with_override(
            tasks=tasks, contract_addr=WETH_ADDRESS, abi=ERC20_ABI, overrides={}
        )

        assert isinstance(results, list)
        assert len(results) == 1
        assert isinstance(results[0], int)
        assert results[0] >= 0

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_batch_web3_contract_calls(self, integration_config):
        """Test batch_web3_contract_calls functionality."""
        helper = RpcHelper(integration_config)
        await helper.init()

        # Create a contract object for WETH
        node = helper.get_current_node()
        contract_obj = node["web3_client"].eth.contract(address=WETH_ADDRESS, abi=ERC20_ABI)

        tasks = [("symbol", []), ("decimals", []), ("balanceOf", [VITALIK_ADDRESS])]

        results = await helper.batch_web3_contract_calls(tasks=tasks, contract_obj=contract_obj)

        assert isinstance(results, list)
        assert len(results) == 3
        assert results[0] == "WETH"  # symbol
        assert results[1] == 18  # decimals
        assert isinstance(results[2], int)  # balance

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_batch_web3_contract_calls_with_block_override(self, integration_config):
        """Test batch_web3_contract_calls with block overrides."""
        helper = RpcHelper(integration_config)
        await helper.init()

        current_block = await helper.get_current_block_number()
        historical_block = current_block - 10

        node = helper.get_current_node()
        contract_obj = node["web3_client"].eth.contract(address=WETH_ADDRESS, abi=ERC20_ABI)

        tasks = [("symbol", []), ("balanceOf", [VITALIK_ADDRESS])]

        # Test with historical block
        results = await helper.batch_web3_contract_calls(
            tasks=tasks,
            contract_obj=contract_obj,
            block_override=[historical_block, historical_block],
        )

        assert isinstance(results, list)
        assert len(results) == 2
        assert results[0] == "WETH"
        assert isinstance(results[1], int)

    # Batch ETH Call Tests
    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_batch_eth_call_on_block_range(self, integration_config):
        """Test batch_eth_call_on_block_range with ERC20 contract."""
        helper = RpcHelper(integration_config)
        await helper.init()

        abi_dict = get_contract_abi_dict(ERC20_ABI)
        current_block = await helper.get_current_block_number()
        from_block = current_block - 2
        to_block = current_block

        results = await helper.batch_eth_call_on_block_range(
            abi_dict=abi_dict,
            function_name="totalSupply",
            contract_address=WETH_ADDRESS,
            from_block=from_block,
            to_block=to_block,
        )

        assert isinstance(results, list)
        assert len(results) == to_block - from_block + 1

        for result in results:
            assert isinstance(result, tuple)
            assert len(result) == 1  # totalSupply returns one value
            assert isinstance(result[0], int)
            assert result[0] > 0

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_batch_eth_call_on_block_range_with_params(self, integration_config):
        """Test batch_eth_call_on_block_range with function parameters."""
        helper = RpcHelper(integration_config)
        await helper.init()

        abi_dict = get_contract_abi_dict(ERC20_ABI)
        current_block = await helper.get_current_block_number()
        test_block = current_block - 10

        results = await helper.batch_eth_call_on_block_range(
            abi_dict=abi_dict,
            function_name="balanceOf",
            contract_address=WETH_ADDRESS,
            from_block=test_block,
            to_block=test_block,
            params=[VITALIK_ADDRESS],
        )

        assert isinstance(results, list)
        assert len(results) == 1
        assert isinstance(results[0], tuple)
        assert isinstance(results[0][0], int)
        assert results[0][0] >= 0

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_batch_eth_call_on_block_range_hex_data(self, integration_config):
        """Test batch_eth_call_on_block_range_hex_data returns raw hex."""
        helper = RpcHelper(integration_config)
        await helper.init()

        abi_dict = get_contract_abi_dict(ERC20_ABI)
        current_block = await helper.get_current_block_number()
        test_block = current_block - 5

        results = await helper.batch_eth_call_on_block_range_hex_data(
            abi_dict=abi_dict,
            function_name="symbol",
            contract_address=WETH_ADDRESS,
            from_block=test_block,
            to_block=test_block,
        )

        assert isinstance(results, list)
        assert len(results) == 1

        # Should return HexBytes object
        from hexbytes import HexBytes

        assert isinstance(results[0], HexBytes)
        assert len(results[0]) > 0

    # Event Log Tests
    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_get_events_logs_real(self, integration_config):
        """Test get_events_logs with real Transfer events."""
        helper = RpcHelper(integration_config)
        await helper.init()

        current_block = await helper.get_current_block_number()
        from_block = current_block - 100  # Look in last 100 blocks
        to_block = current_block

        # Transfer event signature hash
        transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

        event_abi = {transfer_topic: TRANSFER_EVENT_ABI}

        try:
            events = await helper.get_events_logs(
                contract_address=WETH_ADDRESS,
                to_block=to_block,
                from_block=from_block,
                topics=[transfer_topic],
                event_abi=event_abi,
            )

            # WETH might not have many transfers, so just check structure if any events found
            if events:
                assert isinstance(events, list)
                for event in events:
                    assert hasattr(event, "event") or "event" in event
                    assert hasattr(event, "args") or "args" in event
            else:
                # No events found is also valid
                assert isinstance(events, list)
                assert len(events) == 0

        except Exception as e:
            # Some RPC endpoints might not support historical event queries
            if "filter not found" in str(e).lower() or "query returned more than" in str(e).lower():
                pytest.skip(f"RPC endpoint doesn't support this event query: {e}")
            else:
                raise

    # Edge Cases and Error Handling
    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_retry_mechanism_real(self, integration_config):
        """Test retry mechanism with real RPC endpoint."""
        # Use invalid URL to test retry behavior
        invalid_config = RPCConfigBase(
            full_nodes=[RPCNodeConfig(url="https://invalid-rpc-url.com")],
            retry=3,
            request_time_out=5,
            connection_limits={"max_connections": 5},
        )

        helper = RpcHelper(invalid_config)
        await helper.init()

        with pytest.raises(RPCException) as exc_info:
            await helper.get_current_block_number()

        # Should have attempted multiple retries
        assert "RPC_GET_CURRENT_BLOCKNUMBER ERROR" in str(exc_info.value.extra_info)

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_multiple_node_fallback(self, integration_config):
        """Test fallback behavior with multiple nodes."""
        # Create config with multiple endpoints
        multi_config = RPCConfigBase(
            full_nodes=[
                RPCNodeConfig(url="https://invalid-rpc-url-1.com"),  # Should fail
                RPCNodeConfig(url="https://eth.llamarpc.com"),  # Should succeed
                RPCNodeConfig(url="https://invalid-rpc-url-2.com"),  # Should fail
            ],
            retry=2,
            request_time_out=10,
            connection_limits={"max_connections": 5},
        )

        helper = RpcHelper(multi_config)
        await helper.init()

        # Should succeed by falling back to working node
        block_number = await helper.get_current_block_number()
        assert isinstance(block_number, int)
        assert block_number > 18_000_000

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_archive_mode_real(self, integration_config):
        """Test archive mode functionality with real RPC endpoint."""
        # Create archive-specific config
        archive_config = RPCConfigBase(
            full_nodes=[RPCNodeConfig(url="https://eth.llamarpc.com")],
            archive_nodes=[RPCNodeConfig(url="https://eth.llamarpc.com")],
            retry=2,
            request_time_out=30,
            connection_limits={
                "max_connections": 5,
                "max_keepalive_connections": 3,
                "keepalive_expiry": 60,
            },
        )

        helper = RpcHelper(archive_config, archive_mode=True)
        await helper.init()

        # Should work the same as full nodes in this case
        block_number = await helper.get_current_block_number()
        assert isinstance(block_number, int)
        assert block_number > 18_000_000

    # Stress Tests
    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_concurrent_requests_stress(self, integration_config):
        """Stress test with concurrent requests."""
        helper = RpcHelper(integration_config)
        await helper.init()

        # Perform multiple concurrent requests
        tasks = []
        for i in range(10):
            tasks.append(helper.get_current_block_number())

        results = await asyncio.gather(*tasks)

        assert len(results) == 10
        assert all(isinstance(r, int) for r in results)
        assert all(r > 18_000_000 for r in results)

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_mixed_method_stress(self, integration_config):
        """Stress test with different methods concurrently."""
        helper = RpcHelper(integration_config)
        await helper.init()

        current_block = await helper.get_current_block_number()
        test_block = current_block - 10

        tasks = [
            helper.get_current_block_number(),
            helper.eth_get_block(test_block),
            helper.get_transaction_receipt_json(KNOWN_TX_HASH),
            helper.web3_call([("symbol", [])], WETH_ADDRESS, ERC20_ABI),
            helper.batch_eth_get_balance_on_block_range(VITALIK_ADDRESS, test_block, test_block),
        ]

        results = await asyncio.gather(*tasks)

        assert len(results) == 5
        assert isinstance(results[0], int)  # block number
        assert isinstance(results[1], dict)  # block data
        assert isinstance(results[2], dict)  # transaction receipt
        assert isinstance(results[3], list)  # web3 call result
        assert isinstance(results[4], list)  # balance result

    # Rate Limiting Tests
    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self, integration_config):
        """Test rate limiting functionality with real endpoints."""
        # Skip if rate limiter service is not available
        pytest.skip("Rate limiter service not available in integration tests")

    # Validation Tests
    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_block_range_validation(self, integration_config):
        """Test validation of block ranges with real data."""
        helper = RpcHelper(integration_config)
        await helper.init()

        current_block = await helper.get_current_block_number()

        # Test with reasonable range
        from_block = max(1, current_block - 10)
        to_block = current_block

        balances = await helper.batch_eth_get_balance_on_block_range(VITALIK_ADDRESS, from_block, to_block)

        expected_length = to_block - from_block + 1
        assert len(balances) == expected_length


@pytest.mark.integration
class TestRpcNetworkConnectivity:
    """Test network connectivity and endpoint availability."""

    @pytest.mark.network
    def test_rpc_endpoint_availability(self):
        """Test that configured RPC endpoints are available."""

        async def check_endpoint(url):
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.post(
                        url,
                        json={
                            "jsonrpc": "2.0",
                            "method": "eth_blockNumber",
                            "params": [],
                            "id": 1,
                        },
                    )
                    return response.status_code == 200
            except Exception:
                return False

        # Test common endpoints
        endpoints = [
            "https://eth.llamarpc.com",
            "https://ethereum.publicnode.com",
            "https://rpc.ankr.com/eth",
        ]

        async def run_tests():
            results = []
            for endpoint in endpoints:
                available = await check_endpoint(endpoint)
                results.append((endpoint, available))
            return results

        results = asyncio.run(run_tests())

        # At least one endpoint should be available
        available_endpoints = [url for url, available in results if available]
        assert len(available_endpoints) > 0, f"No RPC endpoints available: {results}"


@pytest.mark.integration
class TestContractInteractionReliability:
    """Test interactions with well-known, reliable contracts."""

    @pytest.fixture(scope="class")
    def integration_config(self):
        """Provide configuration for integration tests."""
        rpc_url = os.getenv("TEST_RPC_URL", "https://eth.llamarpc.com")

        return RPCConfigBase(
            full_nodes=[RPCNodeConfig(url=rpc_url)],
            archive_nodes=[RPCNodeConfig(url=rpc_url)],
            retry=2,
            request_time_out=30,
            connection_limits={
                "max_connections": 10,
                "max_keepalive_connections": 5,
                "keepalive_expiry": 60,
            },
        )

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_uniswap_v3_factory_interaction(self, integration_config):
        """Test interaction with Uniswap V3 Factory contract."""
        helper = RpcHelper(integration_config)
        await helper.init()

        # Test getPool function for WETH/USDC pair
        tasks = [("getPool", [WETH_ADDRESS, USDC_ADDRESS, 3000])]  # 0.3% fee tier

        results = await helper.web3_call(tasks=tasks, contract_addr=UNISWAP_V3_FACTORY, abi=UNISWAP_V3_FACTORY_ABI)

        assert isinstance(results, list)
        assert len(results) == 1
        assert isinstance(results[0], str)
        assert results[0].startswith("0x")
        assert len(results[0]) == 42  # Valid Ethereum address

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_usdc_contract_properties(self, integration_config):
        """Test USDC contract properties."""
        helper = RpcHelper(integration_config)
        await helper.init()

        tasks = [("symbol", []), ("decimals", []), ("totalSupply", [])]

        results = await helper.web3_call(tasks=tasks, contract_addr=USDC_ADDRESS, abi=ERC20_ABI)

        assert isinstance(results, list)
        assert len(results) == 3

        # USDC should have expected properties
        assert results[0] == "USDC"  # symbol
        assert results[1] == 6  # decimals
        assert isinstance(results[2], int)  # totalSupply
        assert results[2] > 0

"""
Integration tests for RPCHelper with real Ethereum RPC endpoints.

These tests verify the library's functionality against real Ethereum networks.
They are marked as 'network' tests and can be skipped when network access is unavailable.
"""
import asyncio
import httpx
import os
import pytest
from rpc_helper.rpc import RpcHelper, get_contract_abi_dict
from rpc_helper.utils.models.settings_model import RPCConfigBase, RPCNodeConfig
from rpc_helper.utils.exceptions import RPCException


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
                "keepalive_expiry": 60
            }
        )

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_get_current_block_number_real(self, integration_config):
        """Test getting current block number from real RPC endpoint."""
        helper = RpcHelper(integration_config)
        await helper.init()
        
        block_number = await helper.get_current_block_number()
        
        assert isinstance(block_number, int)
        assert block_number > 0
        assert block_number < 999999999  # Reasonable upper bound

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_get_transaction_receipt_json_real(self, integration_config):
        """Test getting transaction receipt from real transaction."""
        # Use a known transaction hash from Ethereum mainnet
        # This is the hash of the first Ethereum transaction ever
        tx_hash = "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060"
        
        helper = RpcHelper(integration_config)
        await helper.init()
        
        receipt = await helper.get_transaction_receipt_json(tx_hash)
        
        assert receipt is not None
        assert isinstance(receipt, dict)
        assert receipt["transactionHash"].lower() == tx_hash.lower()
        assert "blockNumber" in receipt
        assert "status" in receipt
        assert receipt["status"] in ["0x0", "0x1"]

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_get_eth_get_block_real(self, integration_config):
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
    async def test_batch_eth_get_balance_real(self, integration_config):
        """Test batch balance retrieval from real RPC endpoint."""
        helper = RpcHelper(integration_config)
        await helper.init()
        
        # Use a known Ethereum address
        vitalik_address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        
        # Get current block
        current_block = await helper.get_current_block_number()
        from_block = max(1, current_block - 5)  # Last 5 blocks
        to_block = current_block
        
        balances = await helper.batch_eth_get_balance_on_block_range(
            address="0x742d35Cc6634C0532925a3b844Bc9e7595f6E123",
            from_block=from_block,
            to_block=to_block
        )
        
        assert isinstance(balances, list)
        assert len(balances) == to_block - from_block + 1
        assert all(isinstance(balance, int) for balance in balances)
        assert all(balance >= 0 for balance in balances)

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
            assert "number" in block['result']
            assert "hash" in block['result']
            assert "timestamp" in block['result']

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
            connection_limits={"max_connections": 5}
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
    async def test_rate_limiting_integration(self, integration_config):
        """Test rate limiting functionality with real endpoints."""
        # Skip if rate limiter service is not available
        pytest.skip("Rate limiter service not available in integration tests")

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
                "keepalive_expiry": 60
            }
        )
        
        helper = RpcHelper(archive_config, archive_mode=True)
        await helper.init()
        
        # Should work the same as full nodes in this case
        block_number = await helper.get_current_block_number()
        assert isinstance(block_number, int)
        assert block_number > 0

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_multiple_node_fallback(self, integration_config):
        """Test fallback behavior with multiple nodes."""
        # Create config with multiple endpoints
        multi_config = RPCConfigBase(
            full_nodes=[
                RPCNodeConfig(url="https://invalid-rpc-url-1.com"),  # Should fail
                RPCNodeConfig(url="https://eth.llamarpc.com"),       # Should succeed
                RPCNodeConfig(url="https://invalid-rpc-url-2.com"),  # Should fail
            ],
            retry=2,
            request_time_out=10,
            connection_limits={"max_connections": 5}
        )
        
        helper = RpcHelper(multi_config)
        await helper.init()
        
        # Should succeed by falling back to working node
        block_number = await helper.get_current_block_number()
        assert isinstance(block_number, int)
        assert block_number > 0

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_stress_test_real(self, integration_config):
        """Stress test with real RPC endpoint."""
        helper = RpcHelper(integration_config)
        await helper.init()
        
        # Perform multiple concurrent requests
        tasks = []
        for i in range(10):
            tasks.append(helper.get_current_block_number())
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 10
        assert all(isinstance(r, int) for r in results)

    @pytest.mark.integration
    @pytest.mark.network
    @pytest.mark.asyncio
    async def test_erc20_balance_check(self, integration_config, rpc_helper_instance):
        """Test ERC20 balance checking with real USDC contract."""
        helper = RpcHelper(integration_config)
        await helper.init()
        
        balance_abi = [
            {
                "constant": True,
                "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"name": "balance", "type": "uint256"}],
                "type": "function"
            }
        ]
        
        # Create ABI dict
        abi_dict = get_contract_abi_dict(balance_abi)
        
        current_block = await helper.get_current_block_number()
        test_block = current_block - 10
        
        # Test with weth address (should return some balance)
        weth_address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        
        result = await helper.batch_eth_call_on_block_range(
            abi_dict=abi_dict,
            function_name="balanceOf",
            contract_address=weth_address,
            from_block=test_block,
            to_block=test_block,
            params=[weth_address]
        )
        
        # Should get a result (even if balance is 0)
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], tuple)
        assert isinstance(result[0][0], int)

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
        
        balances = await helper.batch_eth_get_balance_on_block_range(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f6E123",
            from_block, to_block
        )
        
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
                        json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}
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
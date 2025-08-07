"""
Unit tests for balance-related functionality in RPCHelper.

These tests focus on verifying the business logic of balance operations,
including retrieving Ethereum balances for addresses across block ranges.
"""
import pytest
from unittest.mock import AsyncMock, patch

from rpc_helper.utils.exceptions import RPCException


class TestRpcBalanceOperations:
    """Test cases for balance-related operations."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_on_block_range_success(self, rpc_helper_instance, mock_httpx_response):
        """Test successful batch retrieval of balances across block range."""
        mock_response_data = [
            {"result": "0xde0b6b3a7640000"},  # 1 ETH in wei
            {"result": "0x1bc16d674ec80000"},  # 2 ETH in wei
            {"result": "0x29a2241af62c0000"}  # 3 ETH in wei
        ]
        
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=mock_response_data
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x1234567890123456789012345678901234567890"
        results = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address=address,
            from_block=12345678,
            to_block=12345680
        )

        assert isinstance(results, list)
        assert len(results) == 3
        assert all(isinstance(result, int) for result in results)
        assert results == [1000000000000000000, 2000000000000000000, 3000000000000000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_single_block(self, rpc_helper_instance, mock_httpx_response):
        """Test balance retrieval for a single block."""
        mock_response_data = [
            {"result": "0xde0b6b3a7640000"}  # 1 ETH in wei
        ]
        
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=mock_response_data
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x1234567890123456789012345678901234567890"
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address=address,
            from_block=12345678,
            to_block=12345678
        )
        
        assert result == [1000000000000000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_empty_range(self, rpc_helper_instance, mock_httpx_response):
        """Test balance retrieval with invalid block range."""
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=[]
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x1234567890123456789012345678901234567890"
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address=address,
            from_block=12345679,
            to_block=12345678  # Invalid range
        )
        
        assert result == []

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_zero_balance(self, rpc_helper_instance, mock_httpx_response):
        """Test balance retrieval for address with zero balance."""
        mock_response_data = [
            {"result": "0x0"}  # 0 ETH
        ]
        
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=mock_response_data
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x1234567890123456789012345678901234567890"
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address=address,
            from_block=12345678,
            to_block=12345678
        )
        
        assert result == [0]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_large_range(self, rpc_helper_instance, mock_httpx_response):
        """Test balance retrieval for large block range."""
        # Create mock responses for 100 blocks
        mock_response_data = []
        for i in range(100):
            balance = (i + 1) * 1000000000000000000  # 1, 2, 3... ETH
            mock_response_data.append({"result": hex(balance)})
        
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=mock_response_data
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x1234567890123456789012345678901234567890"
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address=address,
            from_block=12345678,
            to_block=12345777
        )
        
        assert len(result) == 100
        assert result[0] == 1000000000000000000
        assert result[99] == 100 * 1000000000000000000

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_json_rpc_error(self, rpc_helper_instance, mock_httpx_response):
        """Test handling of JSON-RPC errors during balance retrieval."""
        mock_response = mock_httpx_response(
            status_code=400,
            json_data={"error": {"code": -32602, "message": "Invalid address"}}
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0xinvalid_address"
        
        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.batch_eth_get_balance_on_block_range(
                address=address,
                from_block=12345678,
                to_block=12345678
            )
        
        assert "RPC_BATCH_ETH_GET_BALANCE_ON_BLOCK_RANGE_ERROR" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_network_error(self, rpc_helper_instance):
        """Test handling of network errors during balance retrieval."""
        rpc_helper_instance._client.post.side_effect = Exception("Network timeout")
        
        address = "0x1234567890123456789012345678901234567890"
        
        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.batch_eth_get_balance_on_block_range(
                address=address,
                from_block=12345678,
                to_block=12345678
            )
        
        assert "RPC_BATCH_ETH_GET_BALANCE_ON_BLOCK_RANGE_ERROR" in str(exc_info.value.extra_info)
        assert "Network timeout" in str(exc_info.value.underlying_exception)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_rate_limit_exceeded(self, rpc_helper_instance):
        """Test rate limiting for balance retrieval."""
        with patch.object(rpc_helper_instance, 'check_rate_limit', return_value=False):
            address = "0x1234567890123456789012345678901234567890"
            
            with pytest.raises(RPCException) as exc_info:
                await rpc_helper_instance.batch_eth_get_balance_on_block_range(
                    address=address,
                    from_block=12345678,
                    to_block=12345678
                )
            
            assert "Rate limit exceeded" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_checksum_address(self, rpc_helper_instance, mock_httpx_response):
        """Test balance retrieval with checksummed address."""
        mock_response_data = [{"result": "0xde0b6b3a7640000"}]
        
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=mock_response_data
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        # Test with checksummed address
        web3 = rpc_helper_instance._nodes[0]['web3_client']
        address = web3.to_checksum_address("0x742d35Cc6634C0532925a3b844Bc9e7595f6E123")
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address=address,
            from_block=12345678,
            to_block=12345678
        )
        
        assert result == [1000000000000000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_lowercase_address(self, rpc_helper_instance, mock_httpx_response):
        """Test balance retrieval with lowercase address."""
        mock_response_data = [{"result": "0xde0b6b3a7640000"}]
        
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=mock_response_data
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x742d35cc6634c0532925a3b844bc9e7595f6e123".lower()
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address=address,
            from_block=12345678,
            to_block=12345678
        )
        
        assert result == [1000000000000000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_mixed_results(self, rpc_helper_instance, mock_httpx_response):
        """Test balance retrieval with mixed valid results only."""
        mock_response_data = [
            {"result": "0xde0b6b3a7640000"},  # 1 ETH
            {"result": "0x0"},  # Zero balance
            {"result": "0x1bc16d674ec80000"}  # 2 ETH
        ]
        
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=mock_response_data
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x1234567890123456789012345678901234567890"
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address=address,
            from_block=12345678,
            to_block=12345680
        )
        
        # Should return all valid results
        assert len(result) == 3
        assert result == [1000000000000000000, 0, 2000000000000000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_very_large_balance(self, rpc_helper_instance, mock_httpx_response):
        """Test balance retrieval for address with very large balance."""
        large_balance = 1000000000000000000000000000000000
        mock_response_data = [{"result": hex(large_balance)}]
        
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=mock_response_data
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x1234567890123456789012345678901234567890"
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address=address,
            from_block=12345678,
            to_block=12345678
        )
        
        assert result == [large_balance]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_balance_retry_mechanism(self, rpc_helper_instance, mock_httpx_response):
        """Test that retry mechanism works for balance retrieval."""
        # First call fails, second succeeds
        call_count = 0
        
        def mock_post_side_effect(url, json=None, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Temporary error")
            
            return mock_httpx_response(
                status_code=200,
                json_data=[{"result": "0xde0b6b3a7640000"}]
            )
        
        rpc_helper_instance._client.post.side_effect = mock_post_side_effect
        
        # Mock node switching behavior
        rpc_helper_instance._nodes = [
            {'web3_client': AsyncMock(), 'rpc_url': 'http://node1.com'},
            {'web3_client': AsyncMock(), 'rpc_url': 'http://node2.com'}
        ]
        rpc_helper_instance._node_count = 2
        
        address = "0x1234567890123456789012345678901234567890"
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address=address,
            from_block=12345678,
            to_block=12345678
        )
        
        assert result == [1000000000000000000]
        assert call_count >= 2
"""
Unit tests for edge cases and error handling in RPCHelper.

These tests focus on verifying the robustness of the RPCHelper library,
including handling of edge cases, invalid inputs, network failures, and
various error conditions.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from hexbytes import HexBytes

from rpc_helper.utils.exceptions import RPCException
from rpc_helper.rpc import RpcHelper


class TestRpcEdgeCases:
    """Test cases for edge cases and error handling."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_empty_rpc_config(self):
        """Test handling of empty RPC configuration."""
        from rpc_helper.utils.models.settings_model import RPCConfigBase
        
        # This should be handled gracefully
        empty_config = RPCConfigBase(
            full_nodes=[],
            archive_nodes=[],
            retry=1,
            request_time_out=10,
            connection_limits={"max_connections": 10}
        )
        
        helper = RpcHelper(empty_config)
        
        with pytest.raises(Exception, match="No full nodes available"):
            helper.get_current_node()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_invalid_transaction_hash(self, rpc_helper_instance):
        """Test handling of invalid transaction hash formats."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_web3.eth.get_transaction.side_effect = Exception("Invalid transaction hash")
        
        invalid_hashes = [
            "0x123",  # Too short
            "0xggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",  # Invalid hex
            "not_a_hash",  # Not even hex
            "",  # Empty string
        ]
        
        for invalid_hash in invalid_hashes:
            with pytest.raises(RPCException):
                await rpc_helper_instance.get_transaction_from_hash(invalid_hash)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_very_large_block_number(self, rpc_helper_instance):
        """Test handling of very large block numbers."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_web3.eth.block_number = 999999999999  # Very large number
        
        result = await rpc_helper_instance.get_current_block_number()
        assert result == 999999999999

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_negative_block_numbers(self, rpc_helper_instance):
        """Test handling of negative block numbers."""
        mock_response = AsyncMock()
        mock_response.status_code = 400
        mock_response.json = AsyncMock(return_value={"error": {"code": -32602, "message": "Invalid block number"}})
        rpc_helper_instance._client.post.return_value = mock_response
        
        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.batch_eth_get_block(-1, -1)
        
        assert "RPC_CALL_ERROR" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_zero_address_balance(self, rpc_helper_instance):
        """Test balance retrieval for zero address."""
        mock_response_data = [{"result": "0x0"}]
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=mock_response_data)
        rpc_helper_instance._client.post.return_value = mock_response
        
        zero_address = "0x0000000000000000000000000000000000000000"
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            zero_address, 12345678, 12345678
        )
        
        assert result == [0]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_contract_address_without_code(self, rpc_helper_instance):
        """Test contract calls on addresses without contract code."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=[{"result": "0x"}])
        rpc_helper_instance._client.post.return_value = mock_response
        
        mock_abi = [
            {
                "constant": True,
                "inputs": [],
                "name": "totalSupply",
                "outputs": [{"name": "supply", "type": "uint256"}],
                "type": "function"
            }
        ]
        
        # This should handle gracefully - contract call returns empty result
        result = await rpc_helper_instance.batch_eth_call_on_block_range(
            mock_abi, "totalSupply", "0x742d35Cc6634C0532925a3b844Bc9e7595f6E123",
            12345678, 12345678
        )
        
        # Should return decoded result (0 for uint256)
        assert len(result) == 1

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_network_timeout_handling(self, rpc_helper_instance):
        """Test handling of network timeouts."""
        rpc_helper_instance._client.post.side_effect = asyncio.TimeoutError("Request timed out")
        
        address = "0x1234567890123456789012345678901234567890"
        
        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.batch_eth_get_balance_on_block_range(
                address, 12345678, 12345678
            )
        
        assert "RPC_BATCH_ETH_GET_BALANCE_ON_BLOCK_RANGE_ERROR" in str(exc_info.value.extra_info)
        assert "Request timed out" in str(exc_info.value.underlying_exception)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_malformed_json_response(self, rpc_helper_instance):
        """Test handling of malformed JSON responses."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(side_effect=ValueError("Invalid JSON"))
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x1234567890123456789012345678901234567890"
        
        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.batch_eth_get_balance_on_block_range(
                address, 12345678, 12345678
            )
        
        assert "RPC_BATCH_ETH_GET_BALANCE_ON_BLOCK_RANGE_ERROR" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_concurrent_requests(self, rpc_helper_instance):
        """Test handling of concurrent requests."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_web3.eth.block_number = 12345678
        mock_web3.eth.get_transaction.return_value = {"hash": "0x123", "value": 1000}
        
        # Simulate concurrent requests
        tasks = [
            rpc_helper_instance.get_current_block_number(),
            rpc_helper_instance.get_transaction_from_hash("0x123"),
            rpc_helper_instance.get_current_block_number(),
            rpc_helper_instance.get_transaction_from_hash("0x456"),
        ]
        
        # Should handle concurrent requests without issues
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check that we got results for all requests
        assert len(results) == 4
        assert not any(isinstance(r, Exception) for r in results)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_memory_exhaustion_prevention(self, rpc_helper_instance):
        """Test prevention of memory exhaustion with large data sets."""
        # Mock a very large response that could cause memory issues
        large_data = [{"result": "0x" + "0" * 1000} for _ in range(1000)]
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=large_data)
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x1234567890123456789012345678901234567890"
        
        # Should handle large data without memory issues
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address, 12345678, 12345777
        )
        
        assert len(result) == 1000

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_rate_limiter_service_down(self, rpc_helper_instance):
        """Test handling when rate limiter service is down."""
        with patch.object(rpc_helper_instance, '_client') as mock_client:
            mock_client.get.side_effect = Exception("Service unavailable")
            
            # Should default to allowing requests when rate limiter is down
            result = await rpc_helper_instance.check_rate_limit("test_key")
            assert result is True

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_node_rotation_on_failure(self, rpc_helper_instance):
        """Test automatic node rotation on RPC failures."""
        # Setup multiple mock nodes
        mock_web3_1 = AsyncMock()
        mock_web3_2 = AsyncMock()
        mock_web3_3 = AsyncMock()
        
        # First two nodes fail, third succeeds
        def fail1():
            raise Exception("Node 1 down")
        def fail2():
            raise Exception("Node 2 down")
        
        mock_web3_1.eth.block_number = property(lambda self: fail1())
        mock_web3_2.eth.block_number = property(lambda self: fail2())
        mock_web3_3.eth.block_number = 12345678
        
        rpc_helper_instance._nodes = [
            {'web3_client': mock_web3_1, 'rpc_url': 'http://node1.com'},
            {'web3_client': mock_web3_2, 'rpc_url': 'http://node2.com'},
            {'web3_client': mock_web3_3, 'rpc_url': 'http://node3.com'}
        ]
        rpc_helper_instance._node_count = 3
        
        result = await rpc_helper_instance.get_current_block_number()
        
        assert result == 12345678

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_missing_trie_node_error_handling(self, rpc_helper_instance):
        """Test handling of missing trie node errors."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=[{
            "error": {
                "code": -32000,
                "message": "missing trie node 1234567890abcdef"
            }
        }])
        rpc_helper_instance._client.post.return_value = mock_response
        
        address = "0x1234567890123456789012345678901234567890"
        
        # Should handle missing trie node errors gracefully
        result = await rpc_helper_instance.batch_eth_get_balance_on_block_range(
            address, 12345678, 12345678
        )
        
        # Should skip the missing trie node and return empty results
        assert result == []

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_invalid_abi_handling(self, rpc_helper_instance):
        """Test handling of invalid ABI formats."""
        invalid_abi = [
            {"name": "invalidFunction", "type": "function", "inputs": "invalid"}
        ]
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=[{"result": "0x"}])
        rpc_helper_instance._client.post.return_value = mock_response
        
        # Should handle invalid ABI gracefully
        result = await rpc_helper_instance.batch_eth_call_on_block_range(
            invalid_abi, "invalidFunction", "0x1234567890123456789012345678901234567890",
            12345678, 12345678
        )
        
        assert len(result) == 1

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_empty_topics_filter(self, rpc_helper_instance):
        """Test event log retrieval with empty topics filter."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_web3.eth.get_logs.return_value = []
        
        event_abi = {}
        contract_address = "0x1234567890123456789012345678901234567890"
        
        result = await rpc_helper_instance.get_events_logs(
            contract_address, 12345678, 12345679, [], event_abi
        )
        
        assert result == []
        
        # Verify empty topics are handled correctly
        call_args = mock_web3.eth.get_logs.call_args[0][0]
        assert 'topics' in call_args
        assert call_args['topics'] == []

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self, rpc_helper_instance):
        """Test behavior when max retries are exceeded."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        
        # All retries fail
        mock_web3.eth.get_transaction.side_effect = Exception("Persistent failure")
        
        # Ensure we only have one node to test retry exhaustion
        rpc_helper_instance._nodes = [{'web3_client': mock_web3}]
        rpc_helper_instance._node_count = 1
        
        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.get_transaction_from_hash("0x123")
        
        assert "RPC_GET_TRANSACTION_ERROR" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_unicode_and_special_characters_in_data(self, rpc_helper_instance):
        """Test handling of unicode and special characters in contract data."""
        # This test ensures the library handles various data encodings correctly
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=[{
            "result": "0x" + "ff" * 32  # All bytes set to 0xFF
        }])
        rpc_helper_instance._client.post.return_value = mock_response
        
        mock_abi = [
            {
                "constant": True,
                "inputs": [],
                "name": "getData",
                "outputs": [{"name": "data", "type": "bytes32"}],
                "type": "function"
            }
        ]
        
        result = await rpc_helper_instance.batch_eth_call_on_block_range(
            mock_abi, "getData", "0x1234567890123456789012345678901234567890",
            12345678, 12345678
        )
        
        assert len(result) == 1
        assert isinstance(result[0], tuple)


class TestRpcUtilityFunctions:
    """Test cases for utility functions."""

    @pytest.mark.unit
    def test_get_contract_abi_dict_empty_abi(self):
        """Test get_contract_abi_dict with empty ABI."""
        from rpc_helper.rpc import get_contract_abi_dict
        
        result = get_contract_abi_dict([])
        assert result == {}

    @pytest.mark.unit
    def test_get_contract_abi_dict_non_function_entries(self):
        """Test get_contract_abi_dict with non-function ABI entries."""
        from rpc_helper.rpc import get_contract_abi_dict
        
        abi = [
            {"type": "constructor", "inputs": []},
            {"type": "event", "name": "Transfer", "inputs": []},
            {"type": "function", "name": "balanceOf", "inputs": [{"type": "address"}], "outputs": [{"type": "uint256"}]}
        ]
        
        result = get_contract_abi_dict(abi)
        assert len(result) == 1
        assert "balanceOf" in result

    @pytest.mark.unit
    def test_get_encoded_function_signature_no_params(self):
        """Test get_encoded_function_signature with no parameters."""
        from rpc_helper.rpc import get_encoded_function_signature
        
        abi_dict = {
            "testFunction": {
                "signature": "testFunction()",
                "input": [],
                "output": ["uint256"]
            }
        }
        
        result = get_encoded_function_signature(abi_dict, "testFunction", None)
        assert result.startswith("0x")

    @pytest.mark.unit
    def test_get_event_sig_and_abi_empty_inputs(self):
        """Test get_event_sig_and_abi with empty inputs."""
        from rpc_helper.rpc import get_event_sig_and_abi
        
        event_signatures = {}
        event_abis = {}
        
        sigs, abi_dict = get_event_sig_and_abi(event_signatures, event_abis)
        assert sigs == []
        assert abi_dict == {}

    @pytest.mark.unit
    def test_rpc_exception_serialization(self):
        """Test RPCException serialization."""
        from rpc_helper.utils.exceptions import RPCException
        
        exc = RPCException(
            request={"test": "request"},
            response={"test": "response"},
            underlying_exception=Exception("test exception"),
            extra_info="test extra info"
        )
        
        serialized = str(exc)
        assert "test" in serialized
        assert "test exception" in serialized
        assert "test extra info" in serialized
"""
Unit tests for contract call functionality in RPCHelper.

These tests focus on verifying the business logic of contract interactions,
including web3 calls, batch operations, and state overrides.
"""
import pytest
from unittest.mock import AsyncMock, patch
from hexbytes import HexBytes

from rpc_helper.utils.exceptions import RPCException


class TestRpcContractOperations:
    """Test cases for contract-related operations."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_web3_call_single_function(self, rpc_helper_instance, mock_abi):
        """Test successful single contract function call."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_contract = AsyncMock()
        mock_contract.functions.balanceOf.return_value.call.return_value = 1000
        mock_web3.eth.contract.return_value = mock_contract
        
        tasks = [("balanceOf", ["0x1234567890123456789012345678901234567890"])]
        contract_addr = "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3"
        
        result = await rpc_helper_instance.web3_call(tasks, contract_addr, mock_abi)
        
        assert result == [1000]
        mock_web3.eth.contract.assert_called_once_with(
            address=contract_addr,
            abi=mock_abi
        )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_web3_call_multiple_functions(self, rpc_helper_instance, mock_abi):
        """Test successful multiple contract function calls."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_contract = AsyncMock()
        mock_contract.functions.balanceOf.return_value.call.return_value = 1000
        mock_contract.functions.totalSupply.return_value.call.return_value = 1000000
        mock_web3.eth.contract.return_value = mock_contract
        
        tasks = [
            ("balanceOf", ["0x1234567890123456789012345678901234567890"]),
            ("totalSupply", [])
        ]
        contract_addr = "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3"
        
        result = await rpc_helper_instance.web3_call(tasks, contract_addr, mock_abi)
        
        assert result == [1000, 1000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_web3_call_with_rate_limit(self, rpc_helper_instance, mock_abi):
        """Test contract call with rate limiting."""
        with patch.object(rpc_helper_instance, 'check_rate_limit', return_value=False):
            tasks = [("balanceOf", ["0x1234567890123456789012345678901234567890"])]
            contract_addr = "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3"
            
            with pytest.raises(RPCException) as exc_info:
                await rpc_helper_instance.web3_call(tasks, contract_addr, mock_abi)
            
            assert "Rate limit exceeded" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_web3_call_with_override_success(self, rpc_helper_instance, mock_abi):
        """Test successful contract call with state override."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_web3.eth.call.return_value = HexBytes('0x00000000000000000000000000000000000000000000000000000000000003e8')
        
        tasks = [("balanceOf", ["0x1234567890123456789012345678901234567890"])]
        contract_addr = "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3"
        overrides = {
            "0x1234567890123456789012345678901234567890": {
                "balance": "0x1000"
            }
        }
        
        result = await rpc_helper_instance.web3_call_with_override(
            tasks, contract_addr, mock_abi, overrides
        )
        
        assert result == [1000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_web3_contract_calls_success(self, rpc_helper_instance, mock_contract):
        """Test successful batch contract calls."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_web3.eth.contract.return_value = mock_contract
        
        tasks = [
            ("balanceOf", ["0x1234567890123456789012345678901234567890"]),
            ("totalSupply", [])
        ]
        
        # Mock the contract function calls
        mock_contract.functions.balanceOf.return_value.call.return_value = 1000
        mock_contract.functions.totalSupply.return_value.call.return_value = 1000000
        
        result = await rpc_helper_instance.batch_web3_contract_calls(tasks, mock_contract)
        
        assert result == [1000, 1000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_web3_contract_calls_with_block_override(self, rpc_helper_instance, mock_contract):
        """Test batch contract calls with block number override."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_web3.eth.contract.return_value = mock_contract
        
        tasks = [
            ("balanceOf", ["0x1234567890123456789012345678901234567890"]),
            ("totalSupply", [])
        ]
        block_override = [12345678, 12345679]
        
        mock_contract.functions.balanceOf.return_value.call.return_value = 1000
        mock_contract.functions.totalSupply.return_value.call.return_value = 1000000
        
        result = await rpc_helper_instance.batch_web3_contract_calls(
            tasks, mock_contract, block_override=block_override
        )
        
        assert result == [1000, 1000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_web3_contract_calls_block_override_mismatch(self, rpc_helper_instance, mock_contract):
        """Test error when block override length doesn't match tasks length."""
        tasks = [
            ("balanceOf", ["0x1234567890123456789012345678901234567890"]),
            ("totalSupply", [])
        ]
        block_override = [12345678]  # Only one block for two tasks
        
        with pytest.raises(ValueError, match="Block override length is not equal to the number of tasks"):
            await rpc_helper_instance.batch_web3_contract_calls(
                tasks, mock_contract, block_override=block_override
            )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_call_on_block_range_success(self, rpc_helper_instance, mock_abi):
        """Test successful batch contract calls on block range."""
        mock_response_data = [
            {"result": "0x00000000000000000000000000000000000000000000000000000000000003e8"},
            {"result": "0x00000000000000000000000000000000000000000000000000000000000003e9"},
            {"result": "0x00000000000000000000000000000000000000000000000000000000000003ea"}
        ]
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=mock_response_data)
        rpc_helper_instance._client.post.return_value = mock_response
        
        result = await rpc_helper_instance.batch_eth_call_on_block_range(
            mock_abi, "balanceOf", "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
            12345678, 12345680,
            params=["0x1234567890123456789012345678901234567890"]
        )
        
        assert result == [(1000,), (1001,), (1002,)]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_call_on_block_range_no_params(self, rpc_helper_instance, mock_abi):
        """Test batch contract calls without parameters."""
        mock_response_data = [
            {"result": "0x00000000000000000000000000000000000000000000000000000000000f4240"}
        ]
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=mock_response_data)
        rpc_helper_instance._client.post.return_value = mock_response
        
        result = await rpc_helper_instance.batch_eth_call_on_block_range(
            mock_abi, "totalSupply", "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
            12345678, 12345678
        )
        
        assert result == [(1000000,)]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_call_on_block_range_hex_data(self, rpc_helper_instance, mock_abi):
        """Test batch contract calls returning raw hex data."""
        mock_response_data = [
            {"result": "0x00000000000000000000000000000000000000000000000000000000000003e8"}
        ]
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=mock_response_data)
        rpc_helper_instance._client.post.return_value = mock_response
        
        result = await rpc_helper_instance.batch_eth_call_on_block_range_hex_data(
            mock_abi, "balanceOf", "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
            12345678, 12345678,
            params=["0x1234567890123456789012345678901234567890"]
        )
        
        assert len(result) == 1
        assert isinstance(result[0], HexBytes)
        assert result[0].hex() == "0x00000000000000000000000000000000000000000000000000000000000003e8"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_contract_call_web3_error(self, rpc_helper_instance, mock_abi):
        """Test handling of web3 provider errors during contract calls."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_web3.eth.contract.side_effect = Exception("Contract not found")
        
        tasks = [("balanceOf", ["0x1234567890123456789012345678901234567890"])]
        contract_addr = "0xInvalidContractAddress"
        
        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.web3_call(tasks, contract_addr, mock_abi)
        
        assert "RPC_WEB3_CALL_ERROR" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_contract_call_json_rpc_error(self, rpc_helper_instance, mock_abi):
        """Test handling of JSON-RPC errors during contract calls."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=[{"error": {"code": -32000, "message": "execution reverted"}}])
        rpc_helper_instance._client.post.return_value = mock_response
        
        result = await rpc_helper_instance.batch_eth_call_on_block_range(
            mock_abi, "invalidFunction", "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
            12345678, 12345678
        )
        
        # Should handle the error gracefully and return empty results
        assert result == [None]  # Based on current implementation

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_contract_call_multiple_outputs(self, rpc_helper_instance):
        """Test contract call with multiple output values."""
        mock_abi = [
            {
                "constant": True,
                "inputs": [{"name": "_address", "type": "address"}],
                "name": "getUserInfo",
                "outputs": [
                    {"name": "balance", "type": "uint256"},
                    {"name": "lastUpdate", "type": "uint256"},
                    {"name": "isActive", "type": "bool"}
                ],
                "type": "function"
            }
        ]
        
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        mock_web3.eth.call.return_value = HexBytes(
            '0x00000000000000000000000000000000000000000000000000000000000003e8'
            '00000000000000000000000000000000000000000000000000000000623a2920'
            '0000000000000000000000000000000000000000000000000000000000000001'
        )
        
        tasks = [("getUserInfo", ["0x1234567890123456789012345678901234567890"])]
        contract_addr = "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3"
        
        result = await rpc_helper_instance.web3_call_with_override(tasks, contract_addr, mock_abi, {})
        
        assert len(result) == 1
        assert result[0] == (1000, 1649083936, True)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_contract_call_empty_result(self, rpc_helper_instance, mock_abi):
        """Test handling of empty contract call results."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = AsyncMock(return_value=[])
        rpc_helper_instance._client.post.return_value = mock_response
        
        result = await rpc_helper_instance.batch_eth_call_on_block_range(
            mock_abi, "balanceOf", "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
            12345678, 12345677  # Invalid range
        )
        
        assert result == []
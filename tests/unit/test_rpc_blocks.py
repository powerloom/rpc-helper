"""
Unit tests for block-related functionality in RPCHelper.

These tests focus on verifying the business logic of block operations,
including retrieving current block numbers and block data.
"""
import pytest
from unittest.mock import patch, AsyncMock

from rpc_helper.utils.exceptions import RPCException


class TestRpcBlockOperations:
    """Test cases for block-related operations."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_current_block_number_success(self, rpc_helper_instance):
        """Test successful retrieval of current block number."""
        
        result = await rpc_helper_instance.get_current_block_number()
        
        assert result == 12345678

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_current_block_with_rate_limit_allowed(self, rpc_helper_instance):
        """Test block number retrieval when rate limit is allowed."""
        
        with patch.object(rpc_helper_instance, 'check_rate_limit', return_value=True):
            result = await rpc_helper_instance.get_current_block_number()
            assert result == 12345678

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_current_block_with_rate_limit_exceeded(self, rpc_helper_instance):
        """Test that rate limit exceeded raises appropriate exception for block calls."""
        with patch.object(rpc_helper_instance, 'check_rate_limit', return_value=False):
            with pytest.raises(RPCException) as exc_info:
                await rpc_helper_instance.get_current_block_number()
            
            assert "Rate limit exceeded" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_current_block_web3_error(self, rpc_helper_instance):
        """Test handling of web3 provider errors during block retrieval."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        
        # Mock the attribute to raise an exception
        block_number_mock = AsyncMock(side_effect=Exception("Network timeout"))
        type(mock_web3.eth).block_number = property(lambda _: block_number_mock())
        
        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.get_current_block_number()
        
        assert "RPC_GET_CURRENT_BLOCKNUMBER ERROR" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_eth_get_block_success(self, rpc_helper_instance, sample_block_data, mock_httpx_response):
        """Test successful retrieval of a specific block."""
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=[{"result": sample_block_data}]
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        result = await rpc_helper_instance.eth_get_block(block_number=12345678)
        
        assert result == sample_block_data
        assert result["number"] == "0xbc614e"
        assert result["hash"] == "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_eth_get_block_latest(self, rpc_helper_instance, sample_block_data, mock_httpx_response):
        """Test successful retrieval of the latest block."""
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=[{"result": sample_block_data}]
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        result = await rpc_helper_instance.eth_get_block()
        
        assert result == sample_block_data

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_eth_get_block_not_found(self, rpc_helper_instance, mock_httpx_response):
        """Test handling of non-existent block."""
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=[{"result": None}]
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        result = await rpc_helper_instance.eth_get_block(block_number=999999999)
        
        assert result is None

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_eth_get_block_error_response(self, rpc_helper_instance, mock_httpx_response):
        """Test handling of error responses from block retrieval."""
        mock_response = mock_httpx_response(
            status_code=400,
            json_data={"error": {"code": -32602, "message": "Invalid block number"}}
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.eth_get_block(block_number=-1)
        
        assert "RPC_CALL_ERROR" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_block_success(self, rpc_helper_instance, sample_block_data, mock_httpx_response):
        """Test successful batch retrieval of multiple blocks."""
        blocks_data = [
            {"result": {**sample_block_data, "number": "0xbc614e"}},
            {"result": {**sample_block_data, "number": "0xbc614f"}},
            {"result": {**sample_block_data, "number": "0xbc6150"}}
        ]
        
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=blocks_data
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        result = await rpc_helper_instance.batch_eth_get_block(12345678, 12345680)
        
        assert isinstance(result, list)
        assert len(result) == 3
        assert result[0]["result"]["number"] == "0xbc614e"
        assert result[1]["result"]["number"] == "0xbc614f"
        assert result[2]["result"]["number"] == "0xbc6150"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_block_single_block(self, rpc_helper_instance, sample_block_data, mock_httpx_response):
        """Test batch retrieval of a single block."""
        mock_response = mock_httpx_response(
            status_code=200,
            json_data=[{"result": sample_block_data}]
        )
        rpc_helper_instance._client.post.return_value = mock_response
        
        result = await rpc_helper_instance.batch_eth_get_block(12345678, 12345678)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["result"]["number"] == "0xbc614e"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_get_block_empty_range(self, rpc_helper_instance):
        """Test batch retrieval with invalid block range."""
        
        result = await rpc_helper_instance.batch_eth_get_block(12345678, 12345677)
        
        assert isinstance(result, list)
        assert len(result) == 0

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_retry_mechanism_for_block_calls(self, rpc_helper_instance):
        """Test that retry mechanism works for block retrieval."""
        mock_web3 = rpc_helper_instance._nodes[0]['web3_client']
        
        # First call fails, second succeeds
        call_count = 0
        def side_effect():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Temporary error")
            return 12345678
        
        block_number_mock = AsyncMock(side_effect=side_effect)
        type(mock_web3.eth).block_number = property(lambda _: block_number_mock())
        
        # Mock node switching behavior
        rpc_helper_instance._nodes = [
            {'web3_client': mock_web3},
            {'web3_client': mock_web3}  # Same mock for simplicity
        ]
        rpc_helper_instance._node_count = 2
        
        result = await rpc_helper_instance.get_current_block_number()
        
        assert result == 12345678
        assert call_count >= 2

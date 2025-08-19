"""
Unit tests for transaction-related functionality in RPCHelper.

These tests focus on verifying the business logic of transaction operations,
including retrieving transactions, receipts, and handling various edge cases
without making actual network calls.
"""

from unittest.mock import call, patch

import pytest

from rpc_helper.utils.exceptions import RPCException


class TestRpcTransactionOperations:
    """Test cases for transaction-related operations."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_transaction_from_hash_success(self, rpc_helper_instance, sample_transaction):
        """Test successful retrieval of transaction by hash."""
        # Mock the web3 provider to return our sample transaction
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_transaction.return_value = sample_transaction

        tx_hash = "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675"
        result = await rpc_helper_instance.get_transaction_from_hash(tx_hash)

        assert result == sample_transaction
        mock_web3.eth.get_transaction.assert_called_once_with(tx_hash)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_transaction_from_hash_with_rate_limit_allowed(self, rpc_helper_instance, sample_transaction):
        """Test transaction retrieval when rate limit is allowed."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_transaction.return_value = sample_transaction

        # Mock rate limiter to allow the request
        with patch.object(rpc_helper_instance, "check_rate_limit", return_value=True):
            tx_hash = "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675"
            result = await rpc_helper_instance.get_transaction_from_hash(tx_hash)

            assert result == sample_transaction

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_transaction_from_hash_with_rate_limit_exceeded(self, rpc_helper_instance):
        """Test that rate limit exceeded raises appropriate exception."""
        # Mock rate limiter to reject the request
        with patch.object(rpc_helper_instance, "check_rate_limit", return_value=False):
            tx_hash = "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675"

            with pytest.raises(RPCException) as exc_info:
                await rpc_helper_instance.get_transaction_from_hash(tx_hash)

            assert "Rate limit exceeded" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_transaction_receipt_success(self, rpc_helper_instance, sample_transaction_receipt):
        """Test successful retrieval of transaction receipt."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_transaction_receipt.return_value = sample_transaction_receipt

        tx_hash = "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675"
        result = await rpc_helper_instance.get_transaction_receipt(tx_hash)

        assert result == sample_transaction_receipt
        mock_web3.eth.get_transaction_receipt.assert_called_once_with(tx_hash)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_transaction_receipt_json_success(self, rpc_helper_instance, mock_httpx_response):
        """Test successful retrieval of transaction receipt via JSON-RPC."""
        tx_hash = "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675"
        expected_receipt = {
            "transactionHash": tx_hash,
            "blockNumber": "0xbc614e",
            "status": "0x1",
        }

        mock_response = mock_httpx_response(status_code=200, json_data={"result": expected_receipt})
        rpc_helper_instance._client.post.return_value = mock_response

        result = await rpc_helper_instance.get_transaction_receipt_json(tx_hash)

        assert result == expected_receipt
        rpc_helper_instance._client.post.assert_called_once()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_transaction_receipt_json_not_found(self, rpc_helper_instance, mock_httpx_response):
        """Test handling of non-existent transaction receipt."""
        tx_hash = "0xinvalid_transaction_hash"

        mock_response = mock_httpx_response(status_code=200, json_data={"result": None})
        rpc_helper_instance._client.post.return_value = mock_response

        result = await rpc_helper_instance.get_transaction_receipt_json(tx_hash)

        assert result is None

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_transaction_web3_error(self, rpc_helper_instance):
        """Test handling of web3 provider errors during transaction retrieval."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_transaction.side_effect = Exception("Connection timeout")

        tx_hash = "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675"

        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.get_transaction_from_hash(tx_hash)

        assert "RPC_GET_TRANSACTION_ERROR" in str(exc_info.value.extra_info)
        assert "Connection timeout" in str(exc_info.value.underlying_exception)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_transaction_receipt_web3_error(self, rpc_helper_instance):
        """Test handling of web3 provider errors during receipt retrieval."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_transaction_receipt.side_effect = Exception("Network error")

        tx_hash = "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675"

        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.get_transaction_receipt(tx_hash)

        assert "RPC_GET_TRANSACTION_RECEIPT_ERROR" in str(exc_info.value.extra_info)
        assert "Network error" in str(exc_info.value.underlying_exception)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_transaction_hash_validation(self, rpc_helper_instance, sample_transaction):
        """Test that transaction hash is properly validated and used."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_transaction.return_value = sample_transaction

        # Test with lowercase hash
        tx_hash_lower = "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675"
        await rpc_helper_instance.get_transaction_from_hash(tx_hash_lower)

        # Test with uppercase hash
        tx_hash_upper = "0x16FF6B3FB198C54A36C76D689255AA06AF2E701914BA42EC0533820C4C2C6675"
        await rpc_helper_instance.get_transaction_from_hash(tx_hash_upper)

        # Both should use the same underlying call
        assert mock_web3.eth.get_transaction.call_count == 2

        # Check that both calls were made with the respective hashes
        expected_calls = [call(tx_hash_lower), call(tx_hash_upper)]
        mock_web3.eth.get_transaction.assert_has_calls(expected_calls)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_retry_mechanism_for_transaction_calls(self, rpc_helper_instance, sample_transaction):
        """Test that retry mechanism works for transaction calls."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]

        # First call fails, second succeeds
        mock_web3.eth.get_transaction.side_effect = [
            Exception("Temporary error"),
            sample_transaction,
        ]

        # Mock node switching behavior
        rpc_helper_instance._nodes = [
            {"web3_client": mock_web3},
            {"web3_client": mock_web3},  # Same mock for simplicity
        ]
        rpc_helper_instance._node_count = 2

        tx_hash = "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675"

        # This should retry and eventually succeed
        result = await rpc_helper_instance.get_transaction_from_hash(tx_hash)

        assert result == sample_transaction
        assert mock_web3.eth.get_transaction.call_count >= 2

"""
Unit tests for event-related functionality in RPCHelper.

These tests focus on verifying the business logic of event log retrieval,
including filtering events, decoding event data, and handling various edge cases.
"""

from unittest.mock import AsyncMock, patch

import pytest
from hexbytes import HexBytes

from rpc_helper.utils.exceptions import RPCException
from tests.conftest import LogMock


class TestRpcEventOperations:
    """Test cases for event-related operations."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_events_logs_success(self, rpc_helper_instance, sample_event_logs):
        """Test successful retrieval of event logs."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_logs.return_value = sample_event_logs

        # Mock the event ABI
        event_abi = {
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "name": "from", "type": "address"},
                    {"indexed": True, "name": "to", "type": "address"},
                    {"indexed": False, "name": "value", "type": "uint256"},
                ],
                "name": "Transfer",
                "type": "event",
            }
        }

        contract_address = "0x1234567890123456789012345678901234567890"

        # Mock get_event_data to avoid Web3 event decoding complexity
        with patch("rpc_helper.rpc.get_event_data") as mock_get_event_data:
            mock_get_event_data.return_value = {
                "event": "Transfer",
                "args": {
                    "from": "0x0000000000000000000000000000000000000000",
                    "to": "0x1234567890123456789012345678901234567890",
                    "value": 1,
                },
            }

            result = await rpc_helper_instance.get_events_logs(
                contract_address=contract_address,
                to_block=12345679,
                from_block=12345678,
                topics=[],
                event_abi=event_abi,
            )

            assert isinstance(result, list)
            assert len(result) == 1
            assert result[0]["event"] == "Transfer"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_events_logs_with_topics(self, rpc_helper_instance):
        """Test event log retrieval with topic filtering."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_logs.return_value = []

        event_abi = {
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": {
                "name": "Transfer",
                "type": "event",
                "inputs": [],
            }
        }

        contract_address = "0x1234567890123456789012345678901234567890"
        topics = ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]

        result = await rpc_helper_instance.get_events_logs(
            contract_address=contract_address,
            to_block=12345679,
            from_block=12345678,
            topics=topics,
            event_abi=event_abi,
        )

        assert isinstance(result, list)
        mock_web3.eth.get_logs.assert_called_once()

        # Verify the call arguments
        call_args = mock_web3.eth.get_logs.call_args[0][0]
        assert call_args["address"] == contract_address
        assert call_args["topics"] == topics
        assert call_args["fromBlock"] == 12345678
        assert call_args["toBlock"] == 12345679

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_events_logs_no_events(self, rpc_helper_instance):
        """Test handling when no events are found."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_logs.return_value = []

        event_abi = {}
        contract_address = "0x1234567890123456789012345678901234567890"

        result = await rpc_helper_instance.get_events_logs(
            contract_address=contract_address,
            to_block=12345679,
            from_block=12345678,
            topics=[],
            event_abi=event_abi,
        )

        assert result == []

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_events_logs_web3_error(self, rpc_helper_instance):
        """Test handling of web3 provider errors during event retrieval."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_logs.side_effect = Exception("Network timeout")

        event_abi = {}
        contract_address = "0x1234567890123456789012345678901234567890"

        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.get_events_logs(
                contract_address=contract_address,
                to_block=12345679,
                from_block=12345678,
                topics=[],
                event_abi=event_abi,
            )

        assert "RPC_GET_EVENT_LOGS_ERROR" in str(exc_info.value.extra_info)
        assert "Network timeout" in str(exc_info.value.underlying_exception)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_events_logs_invalid_range(self, rpc_helper_instance):
        """Test handling of invalid block range."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_logs.side_effect = Exception("Invalid range")

        event_abi = {}
        contract_address = "0x1234567890123456789012345678901234567890"

        with pytest.raises(RPCException) as exc_info:
            # This is an invalid range where to_block < from_block
            await rpc_helper_instance.get_events_logs(
                contract_address=contract_address,
                to_block=12345678,
                from_block=12345679,
                topics=[],
                event_abi=event_abi,
            )

        assert "RPC_GET_EVENT_LOGS_ERROR" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_events_logs_rate_limit_exceeded(self, rpc_helper_instance):
        """Test rate limiting for event log retrieval."""
        with patch.object(rpc_helper_instance, "check_rate_limit", return_value=False):
            event_abi = {}
            contract_address = "0x1234567890123456789012345678901234567890"

            with pytest.raises(RPCException) as exc_info:
                await rpc_helper_instance.get_events_logs(
                    contract_address=contract_address,
                    to_block=12345679,
                    from_block=12345678,
                    topics=[],
                    event_abi=event_abi,
                )

            assert "Rate limit exceeded" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_events_logs_large_range(self, rpc_helper_instance):
        """Test event log retrieval for large block ranges."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]

        logs = []
        for i in range(100):
            log_mock = LogMock(block_number=12345678 + i, tx_hash=f"0xabcdef{i:06d}", log_index=i)
            logs.append(log_mock)

        mock_web3.eth.get_logs.return_value = logs

        event_abi = {
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": {
                "anonymous": False,
                "name": "Transfer",
                "type": "event",
                "inputs": [],
            }
        }

        contract_address = "0x1234567890123456789012345678901234567890"

        # Mock get_event_data to avoid Web3 event decoding complexity
        with patch("rpc_helper.rpc.get_event_data") as mock_get_event_data:
            mock_get_event_data.return_value = {
                "event": "Transfer",
                "args": {"value": 1},
            }

            result = await rpc_helper_instance.get_events_logs(
                contract_address=contract_address,
                to_block=12345777,
                from_block=12345678,
                topics=[],
                event_abi=event_abi,
            )

            assert isinstance(result, list)
            assert len(result) == 100
            # Verify get_event_data was called for each log
            assert mock_get_event_data.call_count == 100

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_events_logs_multiple_topics(self, rpc_helper_instance):
        """Test event log retrieval with multiple topics."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_logs.return_value = []

        event_abi = {}
        contract_address = "0x1234567890123456789012345678901234567890"
        topics = [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000001234567890123456789012345678901234567890",
        ]

        result = await rpc_helper_instance.get_events_logs(
            contract_address=contract_address,
            to_block=12345679,
            from_block=12345678,
            topics=topics,
            event_abi=event_abi,
        )

        assert isinstance(result, list)
        call_args = mock_web3.eth.get_logs.call_args[0][0]
        assert call_args["topics"] == topics

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_events_logs_decode_events(self, rpc_helper_instance):
        """Test proper decoding of event data."""
        # Create mock log object using the shared LogMock class

        log_mock = LogMock(
            topics=[
                HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
                HexBytes("0x0000000000000000000000000000000000000000000000000000000000000000"),
                HexBytes("0x0000000000000000000000001234567890123456789012345678901234567890"),
            ]
        )

        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.get_logs.return_value = [log_mock]

        # Mock codec and event decoding
        mock_codec = AsyncMock()
        mock_web3.codec = mock_codec

        event_abi = {
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "name": "from", "type": "address"},
                    {"indexed": True, "name": "to", "type": "address"},
                    {"indexed": False, "name": "value", "type": "uint256"},
                ],
                "name": "Transfer",
                "type": "event",
            }
        }

        contract_address = "0x1234567890123456789012345678901234567890"

        # Mock the get_event_data function to verify it's called with correct parameters
        with patch("rpc_helper.rpc.get_event_data") as mock_get_event_data:
            expected_decoded_event = {
                "event": "Transfer",
                "args": {
                    "from": "0x0000000000000000000000000000000000000000",
                    "to": "0x1234567890123456789012345678901234567890",
                    "value": 1000,
                },
                "logIndex": 0,
                "transactionIndex": 0,
                "blockNumber": 12345678,
            }
            mock_get_event_data.return_value = expected_decoded_event

            result = await rpc_helper_instance.get_events_logs(
                contract_address=contract_address,
                to_block=12345679,
                from_block=12345678,
                topics=[],
                event_abi=event_abi,
            )

            # Verify the decoding function was called correctly
            assert mock_get_event_data.call_count == 1
            call_args = mock_get_event_data.call_args[0]

            # Check that get_event_data was called with the correct parameters
            assert call_args[0] == mock_codec  # codec parameter
            assert (
                call_args[1] == event_abi["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]
            )  # ABI for the specific event
            assert call_args[2] == log_mock  # log data

            # Verify the result contains the decoded event
            assert len(result) == 1
            assert result[0]["event"] == "Transfer"
            assert result[0]["args"]["from"] == "0x0000000000000000000000000000000000000000"
            assert result[0]["args"]["to"] == "0x1234567890123456789012345678901234567890"
            assert result[0]["args"]["value"] == 1000

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.client.async_client import AsyncSecureSysClient


@pytest.mark.asyncio
class TestAsyncClientFixes:
    async def test_register_or_get_system_logs_warning_on_get_failure(self, caplog):
        """Test that GET failures are logged as warnings instead of swallowed."""
        caplog.set_level(logging.WARNING)

        # Mock the _request_with_retry method on the instance
        with patch.object(AsyncSecureSysClient, "_request_with_retry", new_callable=AsyncMock) as mock_request:
            # Scenario: GET raises Exception, POST succeeds
            mock_request.side_effect = [
                Exception("Simulated GET Failure"),  # GET
                MagicMock(status=201, _body=b'{"id": "sys-1", "hostname": "test-host"}'),  # POST
            ]

            client = AsyncSecureSysClient(api_url="https://test.local", api_key="test-key")

            # Act
            result = await client.register_or_get_system("test-host", "linux")

            # Assert
            assert result["id"] == "sys-1"

            # Verify Warning Log presence (Mitigation Verification)
            assert "Failed to query existing system (falling back to register)" in caplog.text
            assert "Simulated GET Failure" in caplog.text

    async def test_register_or_get_system_swallows_exception_and_retries_post(self):
        """Verify the logic flow continues to POST after GET failure."""
        # Mock the _request_with_retry method on the instance
        with patch.object(AsyncSecureSysClient, "_request_with_retry", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = [
                Exception("GET Failed"),
                MagicMock(status=201, _body=b'{"id": "sys-2", "hostname": "test-host-2"}'),
            ]

            client = AsyncSecureSysClient(api_url="https://test.local", api_key="test-key")
            result = await client.register_or_get_system("test-host-2", "linux")

            assert result["id"] == "sys-2"
            assert mock_request.call_count == 2
            # Verify first call was GET
            assert mock_request.call_args_list[0][0][0] == "GET"
            # Verify second call was POST
            assert mock_request.call_args_list[1][0][0] == "POST"

"""Tests for signaling protocol."""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch

from src.securedrop_lite.server import SignalingServer


@pytest.fixture
def signaling():
    return SignalingServer()


@pytest.fixture
def mock_ws():
    ws = AsyncMock()
    ws.send_text = AsyncMock()
    return ws


@pytest.mark.asyncio
async def test_connect_and_disconnect(signaling, mock_ws):
    room_id = "test-room"
    peer_id = "peer1"

    await signaling.connect(mock_ws, room_id, peer_id)

    assert room_id in signaling.rooms
    assert mock_ws in signaling.rooms[room_id]
    assert mock_ws in signaling.peer_info
    assert signaling.peer_info[mock_ws]["peer_id"] == peer_id

    signaling.disconnect(mock_ws)

    assert mock_ws not in signaling.peer_info
    assert room_id not in signaling.rooms or len(signaling.rooms[room_id]) == 0


@pytest.mark.asyncio
async def test_broadcast_to_room(signaling, mock_ws):
    ws2 = AsyncMock()
    ws2.send_text = AsyncMock()

    room_id = "test-room"
    await signaling.connect(mock_ws, room_id, "peer1")
    await signaling.connect(ws2, room_id, "peer2")

    message = {"type": "test", "data": "hello"}
    await signaling.broadcast(room_id, message)

    mock_ws.send_text.assert_called_once()
    ws2.send_text.assert_called_once()

    # Verify message content
    sent_data = json.loads(mock_ws.send_text.call_args[0][0])
    assert sent_data == message


@pytest.mark.asyncio
async def test_broadcast_excludes_sender(signaling, mock_ws):
    ws2 = AsyncMock()
    ws2.send_text = AsyncMock()

    room_id = "test-room"
    await signaling.connect(mock_ws, room_id, "peer1")
    await signaling.connect(ws2, room_id, "peer2")

    message = {"type": "test"}
    await signaling.broadcast(room_id, message, exclude=mock_ws)

    mock_ws.send_text.assert_not_called()
    ws2.send_text.assert_called_once()


@pytest.mark.asyncio
async def test_peer_joined_notification(signaling, mock_ws):
    ws2 = AsyncMock()
    ws2.send_text = AsyncMock()

    room_id = "test-room"
    await signaling.connect(mock_ws, room_id, "peer1")
    await signaling.connect(ws2, room_id, "peer2")

    # ws2 should have received peer-joined for peer1
    calls = ws2.send_text.call_args_list
    assert len(calls) >= 1

    # Find peer-joined message
    peer_joined_msgs = [
        json.loads(c[0][0]) for c in calls
        if json.loads(c[0][0]).get("type") == "peer-joined"
    ]
    assert len(peer_joined_msgs) == 1
    assert peer_joined_msgs[0]["peer_id"] == "peer1"


@pytest.mark.asyncio
async def test_multiple_rooms_isolated(signaling, mock_ws):
    ws2 = AsyncMock()
    ws2.send_text = AsyncMock()

    await signaling.connect(mock_ws, "room1", "peer1")
    await signaling.connect(ws2, "room2", "peer2")

    await signaling.broadcast("room1", {"type": "room1-msg"})

    mock_ws.send_text.assert_called_once()
    ws2.send_text.assert_not_called()


@pytest.mark.asyncio
async def test_disconnect_cleans_empty_room(signaling, mock_ws):
    await signaling.connect(mock_ws, "room1", "peer1")
    signaling.disconnect(mock_ws)

    assert "room1" not in signaling.rooms


@pytest.mark.asyncio
async def test_disconnect_keeps_room_with_other_peers(signaling, mock_ws):
    ws2 = AsyncMock()
    ws2.send_text = AsyncMock()

    await signaling.connect(mock_ws, "room1", "peer1")
    await signaling.connect(ws2, "room1", "peer2")
    signaling.disconnect(mock_ws)

    assert "room1" in signaling.rooms
    assert ws2 in signaling.rooms["room1"]
    assert len(signaling.rooms["room1"]) == 1
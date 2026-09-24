"""FastAPI signaling server for WebRTC SDP/ICE relay."""

import json
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Dict, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


class SignalingServer:
    """Relays WebRTC signaling messages between peers."""

    def __init__(self) -> None:
        self.rooms: Dict[str, Set[WebSocket]] = defaultdict(set)
        self.peer_info: Dict[WebSocket, dict] = {}

    async def connect(self, websocket: WebSocket, room_id: str, peer_id: str) -> None:
        await websocket.accept()
        self.rooms[room_id].add(websocket)
        self.peer_info[websocket] = {"room_id": room_id, "peer_id": peer_id}
        await self._notify_peer_joined(room_id, peer_id, websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        info = self.peer_info.pop(websocket, None)
        if info:
            room_id = info["room_id"]
            peer_id = info["peer_id"]
            self.rooms[room_id].discard(websocket)
            if not self.rooms[room_id]:
                del self.rooms[room_id]

    async def _notify_peer_joined(
        self, room_id: str, peer_id: str, exclude: WebSocket | None = None
    ) -> None:
        message = json.dumps({"type": "peer-joined", "peer_id": peer_id})
        for ws in self.rooms[room_id]:
            if ws != exclude:
                try:
                    await ws.send_text(message)
                except Exception:
                    pass

    async def broadcast(self, room_id: str, message: dict, exclude: WebSocket | None = None) -> None:
        data = json.dumps(message)
        for ws in self.rooms.get(room_id, set()):
            if ws != exclude:
                try:
                    await ws.send_text(data)
                except Exception:
                    pass


signaling = SignalingServer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="SecureDrop-Lite Signaling", lifespan=lifespan)

app.mount("/static", StaticFiles(directory="src/securedrop_lite/static"), name="static")
templates = Jinja2Templates(directory="src/securedrop_lite/static")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.websocket("/ws/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str) -> None:
    peer_id = str(uuid.uuid4())[:8]
    await signaling.connect(websocket, room_id, peer_id)
    try:
        await websocket.send_text(json.dumps({"type": "welcome", "peer_id": peer_id}))
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                message["from"] = peer_id
                await signaling.broadcast(room_id, message, exclude=websocket)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        signaling.disconnect(websocket)
        await signaling.broadcast(room_id, {"type": "peer-left", "peer_id": peer_id})


def main() -> None:
    import uvicorn
    uvicorn.run("securedrop_lite.server:app", host="0.0.0.0", port=8080, reload=False)


if __name__ == "__main__":
    main()
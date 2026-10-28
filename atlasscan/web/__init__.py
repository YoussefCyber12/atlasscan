from __future__ import annotations

from typing import Optional

import uvicorn

from atlasscan.web.app import create_app


def serve(host: str = "127.0.0.1", port: int = 8000, data_dir: Optional[str] = None) -> None:
    app = create_app(data_dir)
    uvicorn.run(app, host=host, port=port, log_level="info")

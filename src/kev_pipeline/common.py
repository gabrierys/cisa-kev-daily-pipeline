from __future__ import annotations

import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import pandas as pd
import requests


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def serialize_path(path: Path, base_dir: Optional[Path] = None) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        return str(candidate)

    anchor = (base_dir or Path.cwd()).resolve()
    try:
        return str(candidate.resolve().relative_to(anchor))
    except ValueError:
        return str(candidate)


def link_or_copy_file(source: Path, destination: Path, allow_hardlink: bool = True) -> None:
    if source.resolve(strict=False) == destination.resolve(strict=False):
        return

    if destination.exists():
        destination.unlink()

    if allow_hardlink:
        try:
            os.link(source, destination)
            return
        except OSError:
            pass

    shutil.copy2(source, destination)


def clear_output_state(files: Dict[str, Path], plots_dir: Path) -> None:
    for path in files.values():
        if path.exists() and path.is_file():
            path.unlink()

    if plots_dir.exists():
        shutil.rmtree(plots_dir)


def request_with_retry(
    session: requests.Session,
    url: str,
    params: Optional[Dict[str, str]] = None,
    timeout: int = 60,
    max_retries: int = 4,
    base_delay: float = 1.2,
) -> requests.Response:
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            response = session.get(url, params=params, timeout=timeout)
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait_s = float(retry_after) if retry_after else max(30.0, base_delay * (2 ** attempt))
                time.sleep(wait_s)
                continue
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last_exc = exc
            wait_s = min(30, base_delay * (2 ** attempt))
            time.sleep(wait_s)
    raise RuntimeError(f"Failed to fetch {url}: {last_exc}")


def save_csv(df: pd.DataFrame, path: Path) -> None:
    df.to_csv(path, index=False, encoding="utf-8")


def load_sync_state(state_file: Path) -> Dict[str, str]:
    if not state_file.exists():
        return {}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def save_sync_state(state_file: Path, last_sync_utc: datetime) -> None:
    state_file.write_text(
        json.dumps({"last_sync_utc": last_sync_utc.astimezone(timezone.utc).isoformat()}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def parse_sync_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

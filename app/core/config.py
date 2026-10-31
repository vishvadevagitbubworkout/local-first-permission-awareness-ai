import os
from pathlib import Path

from dotenv import load_dotenv


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_PROJECT_ROOT / ".env", override=False)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "rafw007/qwen35-claude-coder:4b")
OLLAMA_TIMEOUT_SECONDS = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "120"))
_LOCAL_DATA_ROOT = Path(
    os.getenv("LOCALAPPDATA", str(Path.home() / ".local"))
)
AUTOMATION_STATE_DB = Path(
    os.getenv(
        "AUTOMATION_STATE_DB",
        str(_LOCAL_DATA_ROOT / "permission_aware_automation" / "automation_state.sqlite3"),
    )
)
M6_WORKING_DIRECTORY = Path(
    os.getenv(
        "M6_WORKING_DIRECTORY",
        str(Path.home() / "OneDrive" / "Desktop" / "AI"),
    )
)

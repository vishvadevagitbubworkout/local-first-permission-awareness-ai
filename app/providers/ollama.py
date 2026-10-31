"""Ollama-backed local language-model provider."""

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.core.config import OLLAMA_HOST, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS


class OllamaError(RuntimeError):
    """Base error for failures communicating with Ollama."""


class OllamaConnectionError(OllamaError):
    """Raised when the Ollama server cannot be reached."""


class OllamaModelError(OllamaError):
    """Raised when the configured model is unavailable."""


class OllamaResponseError(OllamaError):
    """Raised when Ollama returns an unusable response."""


class OllamaClient:
    def __init__(
        self,
        host: str = OLLAMA_HOST,
        model: str = OLLAMA_MODEL,
        timeout: float = OLLAMA_TIMEOUT_SECONDS,
    ):
        if timeout <= 0:
            raise ValueError("Ollama timeout must be greater than zero.")
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                # Ollama enforces JSON syntax while temperature zero reduces
                # presentation variability. Schema and security validation
                # still happen downstream; this is not a trust decision.
                "format": "json",
                "options": {"temperature": 0},
            }
        ).encode("utf-8")
        request = Request(
            f"{self.host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            if error.code == 404:
                raise OllamaModelError(
                    f"Ollama model '{self.model}' was not found. "
                    f"Run: ollama pull {self.model}"
                ) from error
            raise OllamaConnectionError(
                f"Ollama returned HTTP {error.code} while using '{self.model}'."
            ) from error
        except (URLError, TimeoutError, OSError) as error:
            raise OllamaConnectionError(
                f"Could not connect to Ollama at {self.host}. "
                "Make sure Ollama is running."
            ) from error
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise OllamaResponseError("Ollama returned invalid JSON.") from error

        if not isinstance(response_data, dict):
            raise OllamaResponseError("Ollama returned a non-object response.")

        response_text = response_data.get("response")
        if not isinstance(response_text, str) or not response_text.strip():
            raise OllamaResponseError("Ollama returned an empty model response.")

        return response_text

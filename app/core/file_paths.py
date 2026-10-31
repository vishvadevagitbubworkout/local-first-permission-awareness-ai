from __future__ import annotations

import re
from pathlib import Path
from pathlib import PureWindowsPath


_QUOTED_WINDOWS_PATH = re.compile(r"[`\"'](\\?[A-Za-z]:[\\/][^`\"']+)[`\"']")
_UNQUOTED_WINDOWS_PATH = re.compile(r"\\?[A-Za-z]:[\\/][^\r\n`\"'<>|?*]*")
_PATH_LABEL = re.compile(
    r"\b(?:(?:exact\s+)?(?:directory|folder|file|path)|files?|in|into|to|at|"
    r"under|inside|read|open|write|create|make|move|rename|delete|remove)\s+$",
    re.I,
)
_ABSOLUTE_PATH_TOKEN = re.compile(
    r"(?:\b[A-Za-z]:[\\/]|\\\\[^\\\s]+\\[^\\\s]+|(?<!\w)/[A-Za-z0-9_.-]+/)"
)
_ACTION_VERB = re.compile(
    r"\b(?:read|open|modify|write|move|rename|delete|remove|erase|create|"
    r"put|send|draft|browse|search|copy|download|execute)\b",
    re.I,
)
_NEGATED_ACTIONS = re.compile(
    r"\b(?:do\s+not|don't|never)\s+"
    r"(?:read|open|modify|write|move|rename|delete|remove|erase|create|"
    r"put|send|draft|browse|search|copy|download|execute)"
    r"(?:\s*,?\s*(?:(?:or|and)\s+)?(?:read|open|modify|write|move|rename|"
    r"delete|remove|erase|create|put|send|draft|browse|search|copy|download|execute))*",
    re.I,
)


class M6PathError(ValueError):
    """Raised when a user-supplied local path cannot be safely resolved."""


def _explicit_path_matches(request: str) -> list[tuple[str, int, int]]:
    matches = [
        (match.group(1), match.start(1), match.end(1))
        for match in _QUOTED_WINDOWS_PATH.finditer(request)
    ]
    quoted_ranges = [(start, end) for _, start, end in matches]
    for match in _UNQUOTED_WINDOWS_PATH.finditer(request):
        if any(start <= match.start() < end for start, end in quoted_ranges):
            continue
        if not _PATH_LABEL.search(request[:match.start()]):
            continue
        raw_path = match.group(0).rstrip(" \t.,;!?")
        if not raw_path:
            continue
        matches.append((raw_path, match.start(), match.start() + len(raw_path)))
    return sorted(matches, key=lambda item: item[1])


def _normalize_and_validate(raw_path: str) -> str:
    raw_path = raw_path.strip().rstrip(".,;!?")
    if re.match(r"\\[A-Za-z]:[\\/]", raw_path):
        raw_path = raw_path[1:]
    windows_path = PureWindowsPath(raw_path)
    if not windows_path.is_absolute() or ".." in windows_path.parts:
        raise M6PathError("The requested path must be absolute and must not contain '..'.")
    return str(windows_path)


def extract_explicit_windows_path(request: str) -> str | None:
    matches = _explicit_path_matches(request)
    if len(matches) > 1:
        raise M6PathError("Use one explicitly labeled Windows path per task.")
    if not matches:
        return None

    return _normalize_and_validate(matches[0][0])


def is_explicit_directory_listing_request(request: str) -> bool:
    matches = _explicit_path_matches(request)
    if len(matches) != 1 or not re.match(
        r"\s*(?:please\s+)?(?:list|show)\b", request, re.I
    ):
        return False
    try:
        if extract_explicit_windows_path(request) is None:
            return False
    except M6PathError:
        return False
    prefix = request[:matches[0][1]]
    if not re.search(r"\bfiles?\b", prefix, re.I):
        return False
    if _ACTION_VERB.search(prefix):
        return False
    suffix = _NEGATED_ACTIONS.sub("", request[matches[0][2]:])
    return _ACTION_VERB.search(suffix) is None


def is_default_directory_listing_request(request: str) -> bool:
    if _explicit_path_matches(request):
        return False
    if not re.match(r"\s*(?:please\s+)?(?:list|show)\b", request, re.I):
        return False
    if not re.search(r"\bfiles?\b", request, re.I):
        return False
    return _ACTION_VERB.search(strip_negated_actions(request)) is None


def resolve_user_path(request: str) -> Path | None:
    raw_path = extract_explicit_windows_path(request)
    if raw_path is None:
        return None
    if Path(raw_path).drive.lower() != PureWindowsPath(raw_path).drive.lower():
        raise M6PathError("The requested Windows path is not valid on this host.")
    return Path(raw_path)


def contains_absolute_path(request: str) -> bool:
    return _ABSOLUTE_PATH_TOKEN.search(request) is not None


def remove_explicit_windows_path(request: str) -> str:
    matches = _explicit_path_matches(request)
    if len(matches) != 1:
        raise M6PathError("Use exactly one explicitly labeled Windows path per task.")
    extract_explicit_windows_path(request)
    _, start, end = matches[0]
    if start > 0 and request[start - 1] in "`\"'":
        start -= 1
    if end < len(request) and request[end] in "`\"'":
        end += 1
    return request[:start] + request[end:]


def strip_negated_actions(text: str) -> str:
    return _NEGATED_ACTIONS.sub("", text)


__all__ = [
    "M6PathError",
    "contains_absolute_path",
    "extract_explicit_windows_path",
    "is_default_directory_listing_request",
    "is_explicit_directory_listing_request",
    "remove_explicit_windows_path",
    "resolve_user_path",
    "strip_negated_actions",
]

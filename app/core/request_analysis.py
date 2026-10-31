"""Shared file-action request parsing and clarification rules."""

import re
from difflib import get_close_matches

from app.core.file_paths import strip_negated_actions
from app.core.task_plan import PlannerIntent

_ACTION_ALIASES = {
    PlannerIntent.LIST: ("list", "show", "find", "search", "locate", "browse"),
    PlannerIntent.READ: ("read", "open", "view", "inspect"),
    PlannerIntent.CREATE: ("create", "make"),
    PlannerIntent.WRITE: ("write", "overwrite", "replace", "edit", "update", "modify", "put"),
    PlannerIntent.MOVE: ("move",),
    PlannerIntent.RENAME: ("rename",),
    PlannerIntent.DELETE: ("delete", "remove", "erase"),
}

_ALIAS_TO_INTENT = {
    alias: intent
    for intent, aliases in _ACTION_ALIASES.items()
    for alias in aliases
}

_LEADING_POLITE_PHRASES = re.compile(
    r"^\s*(?:(?:please|kindly)\s+|(?:can|could|would)\s+you\s+|"
    r"(?:i\s+(?:want|need)\s+you\s+to)\s+)+",
    re.I,
)

_WORD = re.compile(r"[a-z]+", re.I)

_FILE_NAME = re.compile(r"\b[\w.-]+\.(?:pdf|docx?|xlsx?|txt)\b", re.I)

_QUOTED_TEXT = re.compile(r"""(['"]).*?\1""", re.S)

_WINDOWS_PATH = re.compile(r"\\?[A-Za-z]:[\\/].*$", re.S)

_RELATIVE_TRAVERSAL = re.compile(
    r"(?<![\w.])(?:\.\.[\\/])+(?:[^\\/\s\"'`<>|?*]+"
    r"(?:[\\/][^\\/\s\"'`<>|?*]+)*)?",
    re.I,
)

_VAGUE_CLEANUP = re.compile(
    r"\b(?:clean\s+up|cleanup|tidy\s+up|organize)\b.*\b(?:files?|documents?|folders?)\b",
    re.I,
)

_BULK_DELETION = re.compile(
    r"\b(?:delete|remove|erase)\b.*\b(?:all|every|everything)\b.*"
    r"\b(?:files?|documents?|folders?)\b"
    r"|\b(?:delete|remove|erase)\s+all\s+(?:the\s+)?files?\s+(?:i\s+)?created\b",
    re.I,
)


def _intent_for_action_word(word: str) -> PlannerIntent | None:
    normalized = word.casefold()
    exact = _ALIAS_TO_INTENT.get(normalized)
    if exact is not None:
        return exact
    close = get_close_matches(normalized, _ALIAS_TO_INTENT, n=2, cutoff=0.8)
    matching_intents = {_ALIAS_TO_INTENT[alias] for alias in close}
    return next(iter(matching_intents)) if len(matching_intents) == 1 else None


def leading_file_action(request: str) -> tuple[PlannerIntent, int] | None:
    """Recognize a supported file action at the start, tolerating a minor typo."""
    remainder = request
    offset = 0
    while match := _LEADING_POLITE_PHRASES.match(remainder):
        offset += match.end()
        remainder = remainder[match.end():]
    word = _WORD.match(remainder)
    if word is None:
        return None
    intent = _intent_for_action_word(word.group())
    if intent is None:
        return None
    return intent, offset + word.end()


def requested_file_actions(request: str) -> set[PlannerIntent]:
    """Find file-action verbs in a request for M2 consistency checks."""
    sanitized = _QUOTED_TEXT.sub(" ", request)
    sanitized = _WINDOWS_PATH.sub(" ", sanitized)
    sanitized = _FILE_NAME.sub(" ", sanitized)
    sanitized = strip_negated_actions(sanitized)
    return {
        intent
        for match in _WORD.finditer(sanitized)
        if (intent := _intent_for_action_word(match.group())) is not None
    }


def clarification_for_request(request: str) -> str | None:
    """Explain why vague cleanup or bulk deletion needs a narrower request."""
    if _RELATIVE_TRAVERSAL.search(request):
        return (
            "The relative path contains '..' and could escape the selected workspace. "
            "No file was accessed. Use a filename directly inside the workspace or "
            "provide one explicit directory that you are authorized to use."
        )
    if _VAGUE_CLEANUP.search(request):
        return (
            "“Clean up” could mean listing, organizing, renaming, or deleting files. "
            "No files were changed. Specify one exact action and a filename; for "
            "example, ask to list file names or to delete one named file."
        )
    if _BULK_DELETION.search(request):
        return (
            "Bulk deletion is not supported, and “all files created” does not identify "
            "a specific target. No files were changed. Request deletion of one exact "
            "filename at a time, and review the confirmation prompt."
        )
    actions = requested_file_actions(request)
    destructive_actions = {
        PlannerIntent.CREATE,
        PlannerIntent.WRITE,
        PlannerIntent.MOVE,
        PlannerIntent.RENAME,
        PlannerIntent.DELETE,
    }
    if actions.intersection(destructive_actions):
        target_names = _FILE_NAME.findall(_QUOTED_TEXT.sub(" ", request))
        if not target_names:
            return (
                "A destructive file action needs an explicit filename. No files were "
                "changed. Name the file and, for write actions, include the exact text."
            )
        if actions.intersection({PlannerIntent.MOVE, PlannerIntent.RENAME}) and len(
            set(name.casefold() for name in target_names)
        ) < 2:
            return (
                "Move and rename actions need an explicit source filename and a "
                "different destination filename. No files were changed."
            )
    return None

__all__ = [
    'clarification_for_request',
    'leading_file_action',
    'requested_file_actions',
]

"""Plan user requests into bounded file-management actions."""

import json
import re
import secrets
from collections.abc import Iterator
from pathlib import PureWindowsPath
from typing import Any

from pydantic import ValidationError

from app.core.file_paths import (
    contains_absolute_path,
    extract_explicit_windows_path,
    is_default_directory_listing_request,
    is_explicit_directory_listing_request,
    remove_explicit_windows_path,
    strip_negated_actions,
)
from app.core.request_analysis import clarification_for_request, leading_file_action
from app.core.task_plan import CapabilityTemplate, PlanStep, PlannerIntent, TaskPlan
from app.providers.ollama import OllamaClient
from app.security.capabilities import canonical_operation


_ALLOWED_INTENTS = {
    "LIST",
    "READ",
    "MOVE",
    "RENAME",
    "CREATE",
    "WRITE",
    "DELETE",
    "ASK_CLARIFICATION",
}

_FILE_TEMPLATE_CONTRACTS = {
    "FILE_LIST": ("LIST", "LIST", "file_manager", "list"),
    "FILE_READ": ("READ", "READ", "file_manager", "read"),
    "FILE_MOVE": ("MOVE", "MOVE", "file_manager", "move"),
    "FILE_RENAME": ("RENAME", "RENAME", "file_manager", "rename"),
    "FILE_CREATE": ("CREATE", "CREATE", "file_manager", "create"),
    "FILE_WRITE": ("WRITE", "WRITE", "file_manager", "write"),
    "FILE_DELETE": ("DELETE", "DELETE", "file_manager", "delete"),
}

_REQUESTED_FILE = re.compile(r"\b[\w.-]+\.(?:pdf|docx?|xlsx?|txt)\b", re.I)

_ACTION_VERB = re.compile(
    r"\b(?:read|open|inspect|create|make|write|put|overwrite|replace|move|rename|"
    r"delete|remove|erase|send|draft|browse|search|copy|download|execute)\b",
    re.I,
)

_TEMPLATE_BY_INTENT = {
    PlannerIntent.READ: CapabilityTemplate.FILE_READ,
    PlannerIntent.CREATE: CapabilityTemplate.FILE_CREATE,
    PlannerIntent.WRITE: CapabilityTemplate.FILE_WRITE,
    PlannerIntent.MOVE: CapabilityTemplate.FILE_MOVE,
    PlannerIntent.RENAME: CapabilityTemplate.FILE_RENAME,
    PlannerIntent.DELETE: CapabilityTemplate.FILE_DELETE,
}

class Planner:
	"""Coordinate local model planning without executing the resulting plan."""

	def __init__(self, ollama_client: OllamaClient | None = None):
		self.ollama_client = ollama_client or OllamaClient()

	def _clarification_plan(self, user_request: str, reason: str) -> TaskPlan:
		return TaskPlan(
			task_id=Planner._new_task_id(),
			original_request=user_request,
			steps=[
				PlanStep(
					step_id="step_001",
					agent="planner_agent",
					operation="CLARIFY",
					resource=None,
					parameters={
						"reason": reason,
					},
					intent=PlannerIntent.ASK_CLARIFICATION,
					template=None,
					description=reason,
					confidence=0.0,
				)
			],
		)

	@staticmethod
	def _new_task_id() -> str:
		return f"task_{secrets.token_hex(12)}"

	def _detect_unsupported_intent(self, raw_response: str) -> str | None:
		if not isinstance(raw_response, str) or not raw_response.strip():
			return None
		try:
			payload = json.loads(raw_response)
		except json.JSONDecodeError:
			return None
		if not isinstance(payload, dict):
			return None
		for step in payload.get("steps", []):
			if not isinstance(step, dict):
				continue
			intent = step.get("intent")
			if isinstance(intent, str) and intent not in _ALLOWED_INTENTS:
				return intent
		return None

	def create_plan(self, user_request: str) -> TaskPlan:
		if not isinstance(user_request, str) or not user_request.strip():
			raise ValueError("The user request must not be empty.")

		try:
			explicit_path = extract_explicit_windows_path(user_request)
		except ValueError:
			return self._clarification_plan(
				user_request,
				"The absolute path is ambiguous or contains unsupported traversal syntax. Clarification is required.",
			)
		if contains_absolute_path(user_request) and explicit_path is None:
			return self._clarification_plan(
				user_request,
				"Include one unambiguous absolute Windows path after a location cue or file action.",
			)
		clarification_reason = clarification_for_request(user_request)
		if clarification_reason is not None:
			return self._clarification_plan(user_request, clarification_reason)

		if self._is_explicit_directory_listing(user_request):
			return self._explicit_directory_listing_plan(user_request)
		if is_default_directory_listing_request(user_request):
			return self._default_directory_listing_plan(user_request)
		multi_step_plan = self._explicit_multi_action_plan(user_request)
		if multi_step_plan is not None:
			return multi_step_plan
		explicit_plan = self._explicit_file_action_plan(user_request)
		if explicit_plan is not None:
			return explicit_plan

		prompt = build_planner_prompt(user_request)
		raw_response = self.ollama_client.generate(prompt)
		try:
			plan = parse_task_plan(raw_response, require_proposal_fields=True)
			if plan.original_request != user_request:
				raise PlanParsingError(
					"The planning response changed the original user request."
				)
			plan.task_id = self._new_task_id()
			if any(step.intent == PlannerIntent.ASK_CLARIFICATION for step in plan.steps):
				return self._clarification_plan(
					user_request,
					"The planner could not safely produce a supported action. Clarification is required.",
				)
			return self._normalize_file_template_proposals(plan, user_request)
		except PlanParsingError as error:
			unsupported_intent = self._detect_unsupported_intent(raw_response)
			if unsupported_intent is not None:
				return self._clarification_plan(
					user_request,
					f"The requested operation '{unsupported_intent}' is not supported. Clarification is required.",
				)
			raise

	@staticmethod
	def _is_explicit_directory_listing(user_request: str) -> bool:
		try:
			return is_explicit_directory_listing_request(user_request)
		except ValueError:
			return False

	@staticmethod
	def _explicit_directory_listing_plan(user_request: str) -> TaskPlan:
		return TaskPlan(
			task_id=Planner._new_task_id(),
			original_request=user_request,
			steps=[
				PlanStep(
					step_id="step_001",
					agent="file_manager",
					operation="LIST",
					resource="user-selected directory",
					parameters={"mode": "list"},
					template=CapabilityTemplate.FILE_LIST,
					intent=PlannerIntent.LIST,
					description=(
						"List immediate regular-file names in the exact "
						"user-selected directory."
					),
					confidence=1.0,
				)
			],
		)

	@staticmethod
	def _default_directory_listing_plan(user_request: str) -> TaskPlan:
		plan = Planner._explicit_directory_listing_plan(user_request)
		plan.steps[0].resource = "default workspace"
		plan.steps[0].description = "List immediate regular-file names in the configured default workspace."
		return plan

	@classmethod
	def _explicit_multi_action_plan(cls, user_request: str) -> TaskPlan | None:
		lines = [line.strip() for line in user_request.splitlines() if line.strip()]
		if len(lines) < 2:
			return None

		steps = []
		for index, line in enumerate(lines, start=1):
			line_plan = cls._explicit_file_action_plan(line)
			if line_plan is None or len(line_plan.steps) != 1:
				return None
			step = line_plan.steps[0].model_copy(
				update={"step_id": f"step_{index:03d}"}
			)
			steps.append(step)

		return TaskPlan(
			task_id=cls._new_task_id(),
			original_request=user_request,
			steps=steps,
		)

	@classmethod
	def _explicit_file_action_plan(cls, user_request: str) -> TaskPlan | None:
		try:
			raw_path = extract_explicit_windows_path(user_request)
			request_without_path = (
				remove_explicit_windows_path(user_request)
				if raw_path is not None
				else user_request
			)
		except ValueError:
			return None

		action = leading_file_action(request_without_path)
		if action is None:
			return None
		intent, action_end = action

		remainder = request_without_path[action_end:]
		remainder = re.sub(r"""(['"]).*?\1""", "", remainder, flags=re.S)
		remainder = _REQUESTED_FILE.sub("", remainder)
		if _ACTION_VERB.search(strip_negated_actions(remainder)):
			return None

		requested_files = {}
		for filename in _REQUESTED_FILE.findall(request_without_path):
			requested_files.setdefault(filename.casefold(), filename)
		if raw_path is not None:
			path_name = PureWindowsPath(raw_path).name
			if _REQUESTED_FILE.fullmatch(path_name):
				requested_files.setdefault(path_name.casefold(), path_name)
		names = list(requested_files.values())
		expected_count = 2 if intent in {PlannerIntent.MOVE, PlannerIntent.RENAME} else 1
		if len(names) != expected_count:
			return None

		resource = names[0]
		return TaskPlan(
			task_id=cls._new_task_id(),
			original_request=user_request,
			steps=[
				PlanStep(
					step_id="step_001",
					agent="file_manager",
					operation=intent.value,
					resource=resource,
					parameters={"mode": intent.value.lower()},
					template=_TEMPLATE_BY_INTENT[intent],
					intent=intent,
					description=f"{intent.value.title()} the explicitly named file {resource}.",
					confidence=1.0,
				)
			],
		)

	@staticmethod
	def _normalize_file_template_proposals(
		plan: TaskPlan, user_request: str
	) -> TaskPlan:
		"""Convert a declared M1 file template into its fixed M3 contract.

		The model may describe an operation in prose (for example, "create a
		PDF").  It may not choose M3's agent, canonical operation, or fixed
		security parameters.  A mismatched intent/template remains untouched and
		is rejected later by M2/M3.
		"""
		requested_files = {}
		for filename in _REQUESTED_FILE.findall(user_request):
			requested_files.setdefault(filename.casefold(), filename)
		for step in plan.steps:
			normalized_operation = canonical_operation(step.operation)
			if normalized_operation is not None:
				step.operation = normalized_operation
			if step.template is None:
				continue
			contract = _FILE_TEMPLATE_CONTRACTS.get(step.template.value)
			if contract is None or step.intent is None:
				continue
			operation, intent, agent, mode = contract
			if step.intent.value != intent:
				continue
			if operation.lower() not in step.operation.lower():
				continue
			step.operation = operation
			step.agent = agent
			step.parameters = {"mode": mode}
			if step.resource is None and len(plan.steps) == 1:
				if len(requested_files) == 1:
					step.resource = next(iter(requested_files.values()))
				elif (
					intent == "LIST"
					and re.search(r"\bcurrent\s+folder\b", user_request, re.I)
				):
					step.resource = "current folder"
		return plan

CONFIDENCE_THRESHOLD = 0.70

_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]")

_SHELL_COMMAND = re.compile(
    r"(^|\s)(cmd(?:\.exe)?|powershell(?:\.exe)?|bash|sh|rm|del|erase|python(?:\.exe)?|git)(\s|$)",
    re.I,
)

_OPAQUE_FILE_ID = re.compile(r"^file_[A-Za-z0-9_-]+$")

_FORBIDDEN_INSTRUCTION = re.compile(
    r"\b(generate\s+hmac|create\s+capabilit(?:y|ies)|mint\s+capabilit(?:y|ies)|"
    r"grant\s+permission|authorize\s+(?:this|the)\s+path|execute\s+command)\b",
    re.I,
)

def _string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _string_values(key)
            yield from _string_values(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _string_values(child)

class PlanParsingError(ValueError):
    """Raised when model output cannot become a complete TaskPlan."""

def parse_task_plan(
    raw_response: str, *, require_proposal_fields: bool = False
) -> TaskPlan:
    if not isinstance(raw_response, str) or not raw_response.strip():
        raise PlanParsingError("The model returned an empty planning response.")

    normalized_response = raw_response.strip()
    # Models occasionally wrap otherwise valid JSON in a Markdown JSON fence.
    # Accept that presentation-only wrapper, but still require the enclosed
    # value to be one complete JSON object and validate it normally.
    if normalized_response.startswith("```json") and normalized_response.endswith("```"):
        normalized_response = normalized_response[7:-3].strip()
    try:
        payload = json.loads(normalized_response)
    except json.JSONDecodeError as error:
        raise PlanParsingError("The model returned invalid JSON.") from error

    if not isinstance(payload, dict):
        raise PlanParsingError("The planning response must be a JSON object.")

    raw_steps = payload.get("steps")
    required_proposal_fields = {
        "template",
        "intent",
        "opaque_file_refs",
        "parameters",
        "description",
        "confidence",
    }
    if require_proposal_fields and isinstance(raw_steps, list):
        for index, raw_step in enumerate(raw_steps, start=1):
            if isinstance(raw_step, dict):
                raw_step.setdefault("parameters", {})
                missing_fields = required_proposal_fields.difference(raw_step)
                if missing_fields:
                    missing = ", ".join(sorted(missing_fields))
                    raise PlanParsingError(
                        f"Planning step {index} is missing proposal fields: {missing}."
                    )
                if raw_step.get("intent") == PlannerIntent.ASK_CLARIFICATION.value:
                    raw_step["template"] = None

    try:
        if hasattr(TaskPlan, "model_validate"):
            plan = TaskPlan.model_validate(payload)
        else:
            plan = TaskPlan.parse_obj(payload)
    except ValidationError as error:
        raise PlanParsingError(
            f"The planning response does not match TaskPlan: {error}"
        ) from error

    if not plan.task_id.strip():
        raise PlanParsingError("The planning response has no task ID.")
    if not plan.original_request.strip():
        raise PlanParsingError("The planning response has no original request.")
    if not plan.steps:
        raise PlanParsingError("The planning response contains no steps.")

    for step in plan.steps:
        if not step.step_id.strip():
            raise PlanParsingError("A planning step has no step ID.")
        if not step.agent.strip():
            raise PlanParsingError("A planning step has no agent.")
        if not step.operation.strip():
            raise PlanParsingError("A planning step has no operation.")
        if step.opaque_file_refs and any(
            not _OPAQUE_FILE_ID.fullmatch(file_id)
            for file_id in step.opaque_file_refs
        ):
            raise PlanParsingError(
                "The planning response contains a malformed opaque file reference."
            )
        proposal_values = [
            step.agent,
            step.operation,
            step.resource,
            step.template.value if step.template else None,
            step.intent.value if step.intent else None,
            step.description,
            step.opaque_file_refs,
            step.parameters,
        ]
        for value in _string_values(proposal_values):
            if (
                value.startswith("/")
                or value.startswith("\\\\")
                or _WINDOWS_ABSOLUTE_PATH.match(value)
            ):
                raise PlanParsingError(
                    "The planning response contains an absolute filesystem path."
                )
            if _SHELL_COMMAND.search(value):
                raise PlanParsingError(
                    "The planning response contains a raw shell command."
                )
            if _FORBIDDEN_INSTRUCTION.search(value):
                raise PlanParsingError(
                    "The planning response contains a forbidden authority or execution instruction."
                )
        if step.confidence is not None and step.confidence < CONFIDENCE_THRESHOLD:
            step.intent = PlannerIntent.ASK_CLARIFICATION

    return plan

def build_planner_prompt(user_request: str) -> str:
		"""Build the deterministic planning prompt sent to the local model."""
		return f"""You are the M1 local AI planner in a permission-aware desktop automation system.

Convert the user's natural-language request into a structured execution plan.
Understand ordinary conversational wording and minor typos in action words.
Infer an action only when the requested operation and named target are clear.
Do not guess a missing filename, destination, content, or scope; use
ASK_CLARIFICATION when any of those details are necessary but unclear.
Identify each required logical action, including:
- the required agent
- the operation
- one developer-defined template from the allowed template list
- the planner intent from the allowed intent whitelist
- opaque file references only, using file_id tokens rather than system paths
- the target resource description when needed
- relevant operation parameters
- a concise description
- a confidence score from 0.0 to 1.0

Return exactly one valid JSON object and no markdown, commentary, or code fences.
The JSON must follow this schema:
{{
	"task_id": "task_001",
	"original_request": "the user's exact request",
	"steps": [
		{{
			"step_id": "step_001",
			"agent": "the responsible agent",
			"operation": "the required operation",
			"template": "FILE_READ",
			"intent": "READ",
			"opaque_file_refs": ["file_001"],
			"description": "Read the requested report",
			"confidence": 0.95,
			"resource": "the target resource or null",
			"parameters": {{}}
		}}
	]
}}

Use sequential task and step identifiers. Preserve the user's request exactly in
original_request. Include every logical action as a separate step and do not omit
required planning information. Use null when no resource is specified and an
empty object when there are no parameters.

The only allowed intents are exactly: LIST, READ, MOVE, RENAME, CREATE, WRITE,
DELETE, and ASK_CLARIFICATION. If the user's request asks for
an operation outside these supported intents, the planner MUST use
ASK_CLARIFICATION. This is an unsupported intent situation: do not invent an
unsupported intent such as COPY, DOWNLOAD, EXECUTE, SEARCH, or
any other unsupported value. Unsupported intents must not be invented and must
route to ASK_CLARIFICATION. Do not claim that an unsupported operation is
supported. If confidence is below 0.70, use ASK_CLARIFICATION and do not
propose a more specific intent. For ASK_CLARIFICATION, use operation "CLARIFY",
agent "planner_agent", and template null; return only that clarification step,
not a mix of proposed actions and clarification steps. Never use
"ASK_CLARIFICATION" as a template. The allowed templates are exactly: FILE_LIST, FILE_READ, FILE_MOVE,
FILE_RENAME, FILE_CREATE, FILE_WRITE, and FILE_DELETE.
Do not emit shell commands or absolute filesystem paths. A file reference must
be an opaque token such as file_001, never a raw filesystem path.

M1 only describes what actions the request appears to require. Never execute an
action, open or modify files, or perform any desktop operation. Never make authorization decisions. Never invent permissions,
permission grants, authorization results, or capability tokens. Do not decide
whether an action is allowed; only describe the requested actions.

User request:
{user_request}
"""

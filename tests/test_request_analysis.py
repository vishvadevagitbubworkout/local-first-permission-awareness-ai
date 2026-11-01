import unittest

from app.agents.planner import Planner
from app.core.task_plan import PlannerIntent
from app.core.request_analysis import leading_file_action


class UnexpectedOllamaCall:
    def __init__(self):
        self.calls = 0

    def generate(self, prompt: str) -> str:
        self.calls += 1
        raise AssertionError("This request should be handled deterministically.")


class RequestAnalysisTests(unittest.TestCase):
    def test_adjacent_typo_is_recognized_as_read(self):
        action = leading_file_action("Please raed report.txt")

        self.assertIsNotNone(action)
        self.assertEqual(action[0], PlannerIntent.READ)

    def test_typo_prompt_builds_plan_without_model_call(self):
        model = UnexpectedOllamaCall()
        plan = Planner(ollama_client=model).create_plan("Please raed report.txt")

        self.assertEqual(plan.steps[0].intent, PlannerIntent.READ)
        self.assertEqual(plan.steps[0].resource, "report.txt")
        self.assertEqual(model.calls, 0)

    def test_explicit_multiline_actions_build_ordered_plan_without_model_call(self):
        model = UnexpectedOllamaCall()
        prompt = (
            "Create draft.txt.\n"
            "Write 'benchmark ready' to draft.txt.\n"
            "Rename draft.txt to final.txt.\n"
            "Read final.txt."
        )

        plan = Planner(ollama_client=model).create_plan(prompt)

        self.assertEqual(
            [step.intent for step in plan.steps],
            [
                PlannerIntent.CREATE,
                PlannerIntent.WRITE,
                PlannerIntent.RENAME,
                PlannerIntent.READ,
            ],
        )
        self.assertEqual(
            [step.resource for step in plan.steps],
            ["draft.txt", "draft.txt", "draft.txt", "final.txt"],
        )
        self.assertEqual(model.calls, 0)

    def test_content_search_is_not_misclassified_as_file_listing(self):
        model = UnexpectedOllamaCall()
        plan = Planner(ollama_client=model).create_plan(
            "Search the files for the word 'needle'."
        )

        self.assertEqual(plan.steps[0].intent, PlannerIntent.ASK_CLARIFICATION)
        self.assertEqual(model.calls, 0)


if __name__ == "__main__":
    unittest.main()

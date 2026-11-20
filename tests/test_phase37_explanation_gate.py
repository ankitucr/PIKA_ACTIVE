from evaluation.evaluator import Evaluator, _task_asks_for_code


def test_explanation_does_not_require_code():
    task = "Explain in 4 sentences how a Python decorator works."
    assert _task_asks_for_code(task.lower()) is False
    res = Evaluator().evaluate({"success": True, "output": "A decorator wraps a function to extend its behaviour without editing it. It receives a function and returns a new one. The @ syntax applies it. Common uses are logging and caching."}, task=task)
    assert not any("no extractable code" in i for i in res["issues"])


def test_code_request_still_asks_for_code():
    assert _task_asks_for_code("write a python function is_palindrome(s) with 3 example calls") is True
    assert _task_asks_for_code("implement a cli todo app") is True

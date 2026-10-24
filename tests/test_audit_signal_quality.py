import asyncio

from agents.audit_agent import AuditAgent
from agents.verification_agent import VerificationAgent


def _scan_web_candidates(tmp_path, source: str, filename: str = "app.py"):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    agent = AuditAgent()
    asyncio.run(agent._scan_web_vulnerabilities(str(tmp_path)))
    return [
        item for item in agent.audit_state.candidates
        if item.vulnerability_type == "path_traversal"
    ]


def _scan_web_candidate_types(tmp_path, source: str, filename: str = "app.py"):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    agent = AuditAgent()
    asyncio.run(agent._scan_web_vulnerabilities(str(tmp_path)))
    return {item.vulnerability_type for item in agent.audit_state.candidates}


def test_relative_imports_are_not_path_traversal_candidates(tmp_path):
    candidates = _scan_web_candidates(
        tmp_path,
        "import component from '../shared/component'\n"
        "const route = '../../assets/logo.svg'\n",
    )

    assert candidates == []


def test_path_traversal_requires_request_value_to_reach_file_sink(tmp_path):
    candidates = _scan_web_candidates(
        tmp_path,
        "def download(request):\n"
        "    filename = request.args.get('file')\n"
        "    filepath = os.path.join('/uploads', filename)\n"
        "    with open(filepath, 'r') as handle:\n"
        "        return handle.read()\n",
    )

    assert len(candidates) == 1
    assert candidates[0].line_start == 3


def test_python_dangerous_call_literals_are_not_candidates(tmp_path):
    candidate_types = _scan_web_candidate_types(
        tmp_path,
        "def test_rule():\n"
        "    assert 'subprocess.call(cmd, shell=True)' not in 'safe source'\n"
        "    assert 'eval(expression)' not in 'safe source'\n",
    )

    assert "command_injection" not in candidate_types
    assert "code_injection" not in candidate_types


def test_python_executable_dangerous_calls_remain_candidates(tmp_path):
    candidate_types = _scan_web_candidate_types(
        tmp_path,
        "import subprocess\n"
        "def run(command, expression):\n"
        "    subprocess.call(command, shell=True)\n"
        "    return eval(expression)\n",
    )

    assert {"command_injection", "code_injection"} <= candidate_types


def test_typescript_safe_eval_and_regexp_exec_are_not_code_injection_candidates(tmp_path):
    candidate_types = _scan_web_candidate_types(
        tmp_path,
        "const matches = new RegExp(pattern).exec(input)\n"
        "const result = safeEval(request.body.expression)\n",
        filename="route.ts",
    )

    assert "code_injection" not in candidate_types


def test_typescript_function_keyword_is_not_code_injection_candidate(tmp_path):
    candidate_types = _scan_web_candidate_types(
        tmp_path,
        "const buildPath = (function () { return '/admin' })()\n",
        filename="route.ts",
    )

    assert "code_injection" not in candidate_types


def test_typescript_static_function_constructor_is_not_code_injection_candidate(tmp_path):
    candidate_types = _scan_web_candidate_types(
        tmp_path,
        "const dynamicImport = new Function('specifier', 'return import(specifier)')\n",
        filename="route.ts",
    )

    assert "code_injection" not in candidate_types


def test_typescript_untrusted_function_constructor_remains_code_injection_candidate(tmp_path):
    candidate_types = _scan_web_candidate_types(
        tmp_path,
        "const build = new Function(request.body.expression)\n",
        filename="route.ts",
    )

    assert "code_injection" in candidate_types


def test_typescript_vm_fixed_parser_is_not_code_injection_candidate(tmp_path):
    candidate_types = _scan_web_candidate_types(
        tmp_path,
        "vm.runInContext('libxml2.XmlDocument.fromString(data)', sandbox)\n",
        filename="route.ts",
    )

    assert "code_injection" not in candidate_types


def test_typescript_vm_context_execution_remains_code_injection_candidate(tmp_path):
    candidate_types = _scan_web_candidate_types(
        tmp_path,
        "vm.runInContext('safeEval(orderLinesData)', sandbox)\n",
        filename="route.ts",
    )

    assert "code_injection" in candidate_types


def test_static_verifier_distinguishes_vm_execution_from_function_keyword():
    assert VerificationAgent._static_risk_indicator(
        "vm.runInContext(request.body.expression, sandbox)",
        "code_injection",
    )
    assert not VerificationAgent._static_risk_indicator(
        "const buildPath = (function () { return '/admin' })()",
        "code_injection",
    )

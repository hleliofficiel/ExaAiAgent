import os
import subprocess
import sys


def test_sandbox_mode_loads_coordination_tools() -> None:
    env = os.environ.copy()
    env["EXAAI_SANDBOX_MODE"] = "true"

    script = r'''
import json
import exaaiagnt.tools as tools_module
print(json.dumps(sorted(tools_module.get_tool_names())))
'''

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )

    output = result.stdout.strip().splitlines()[-1]
    assert 'wait_for_message' in output
    assert 'agent_finish' in output
    assert 'send_message_to_agent' in output
    assert 'think' in output

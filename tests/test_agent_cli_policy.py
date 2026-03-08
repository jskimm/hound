from click.testing import CliRunner

from commands.agent import agent


class _StubRunner:
    last_instance = None

    def __init__(
        self,
        project_id,
        config_path=None,
        iterations=None,
        time_limit_minutes=None,
        debug=False,
        platform=None,
        model=None,
        session=None,
        new_session=False,
        mode=None,
        allow_test_writes=False,
    ):
        self.project_id = project_id
        self.allow_test_writes = allow_test_writes
        self.config = {}
        self.agent = None
        self.session_id = None
        self.project_dir = None
        _StubRunner.last_instance = self

    def initialize(self):
        return True

    def run(self, plan_n=5):
        self.plan_n = plan_n


def test_agent_cli_accepts_allow_test_writes(monkeypatch):
    monkeypatch.setattr("commands.agent.AgentRunner", _StubRunner)
    runner = CliRunner()

    result = runner.invoke(agent, ["demo", "--allow-test-writes"])

    assert result.exit_code == 0
    assert _StubRunner.last_instance is not None
    assert _StubRunner.last_instance.allow_test_writes is True

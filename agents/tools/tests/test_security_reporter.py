from agents.tools.security_reporter import SecurityReporterTool


class MockLLM:
    def invoke(self, prompt: str):
        return "Mocked report response with summary, issues, and fixes."


def test_security_reporter_tool_with_mockllm():
    sample_analysis = """
    Possible brute force detected on admin account.
    Multiple failed logins followed by a successful login.
    """

    tool = SecurityReporterTool(llm=MockLLM())
    result = tool._run(sample_analysis)

    assert "Mocked report response" in result

from langchain.schema import AIMessage, HumanMessage


class MockLLM:
    def __call__(self, messages: list[HumanMessage]) -> list[AIMessage]:
        assert isinstance(messages, list)
        assert all(isinstance(m, HumanMessage) for m in messages)

        # Simulate a relevant LLM response
        return [
            AIMessage(
                content="Mocked LLM response: Selected patterns are T1003 and T1059.",
            ),
        ]

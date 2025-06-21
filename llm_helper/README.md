        +----------------------+
        |      IRegistry       |  <- Interface (abstract)
        |----------------------|
        | + get_llm(name)      |
        | + get_chat_model(name) |
        | + get_mcp(name)      |
        +----------+-----------+
                |
                v
        +----------------------+
        |      Registry        |  <- Main access point
        |----------------------|
        | - llm_registry       |
        | - chat_registry      |
        | - mcp_registry       |
        |                      |
        | + get_llm(name)      |
        | + get_chat_model(name) |
        | + get_mcp(name)      |
        +----------+-----------+
                |
        +-------+--------+--------+
        |                |        |
        v                v        v
        +-------------+  +--------------+  +-------------+
        | LLMRegistry |  | ChatModelReg |  | MCPRegistry|
        |-------------|  |--------------|  |-------------|
        | + get(name) |  | + get(name)  |  | + get(name) |
        +-------------+  +--------------+  +-------------+
        |                |                |
        v                v                v
        +-------------+  +---------------+  +-------------+
        | OpenAIModel |  | DefaultChat   |  | SomeMCPFunc |
        | LlamaModel  |  | AnotherChat   |  | OtherMCP    |
        +-------------+  +---------------+  +-------------+


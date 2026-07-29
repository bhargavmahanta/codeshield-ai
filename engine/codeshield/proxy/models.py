"""Strict OpenAI-compatible request and response subset models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class TextPart(StrictModel):
    type: Literal["text"]
    text: str = Field(max_length=1_000_000)


class FunctionDefinition(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    description: str | None = Field(default=None, max_length=8192)
    parameters: dict[str, Any] = Field(default_factory=dict)
    strict: bool | None = None


class FunctionTool(StrictModel):
    type: Literal["function"]
    function: FunctionDefinition


class ToolCallFunction(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    arguments: str = Field(max_length=1_000_000)


class ToolCall(StrictModel):
    id: str = Field(min_length=1, max_length=256)
    type: Literal["function"]
    function: ToolCallFunction


class ChatMessage(StrictModel):
    role: Literal["system", "developer", "user", "assistant", "tool"]
    content: str | list[TextPart] | None = None
    name: str | None = Field(default=None, max_length=64)
    tool_call_id: str | None = Field(default=None, max_length=256)
    tool_calls: list[ToolCall] | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def role_shape_is_supported(self) -> "ChatMessage":
        if self.role in {"system", "developer", "user"} and self.content is None:
            raise ValueError("message content is required")
        if self.role == "tool" and (
            not isinstance(self.content, str) or not self.tool_call_id
        ):
            raise ValueError("tool messages require text and a tool-call ID")
        if self.role != "assistant" and self.tool_calls is not None:
            raise ValueError("only assistant messages may contain tool calls")
        return self


class JsonSchemaFormat(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    description: str | None = Field(default=None, max_length=8192)
    schema_: dict[str, Any] = Field(alias="schema")
    strict: bool | None = None


class ResponseFormat(StrictModel):
    type: Literal["text", "json_object", "json_schema"]
    json_schema: JsonSchemaFormat | None = None

    @model_validator(mode="after")
    def json_schema_matches_type(self) -> "ResponseFormat":
        if (self.type == "json_schema") != (self.json_schema is not None):
            raise ValueError("json_schema payload must match the response format type")
        return self


class ChatRequest(StrictModel):
    model: str
    messages: list[ChatMessage] = Field(min_length=1, max_length=512)
    temperature: float | None = Field(default=None, ge=0, le=2)
    top_p: float | None = Field(default=None, gt=0, le=1)
    max_tokens: int | None = Field(default=None, ge=1)
    max_completion_tokens: int | None = Field(default=None, ge=1)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    stop: str | list[str] | None = None
    seed: int | None = None
    n: int | None = Field(default=None, ge=1, le=8)
    response_format: ResponseFormat | None = None
    tools: list[FunctionTool] | None = Field(default=None, max_length=128)
    tool_choice: Literal["none", "auto", "required"] | dict[str, Any] | None = None
    parallel_tool_calls: bool | None = None
    stream: Literal[False] = False
    store: Literal[False] = False


class ResponsesTextFormat(StrictModel):
    type: Literal["text", "json_object", "json_schema"]
    name: str | None = Field(
        default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$"
    )
    description: str | None = Field(default=None, max_length=8192)
    schema_: dict[str, Any] | None = Field(default=None, alias="schema")
    strict: bool | None = None

    @model_validator(mode="after")
    def json_schema_fields_match_type(self) -> "ResponsesTextFormat":
        has_schema = self.name is not None and self.schema_ is not None
        if (self.type == "json_schema") != has_schema:
            raise ValueError("JSON schema fields must match the response format type")
        return self


class ResponsesText(StrictModel):
    format: ResponsesTextFormat | None = None


class Reasoning(StrictModel):
    effort: Literal["minimal", "low", "medium", "high"]


class ResponseInputText(StrictModel):
    type: Literal["input_text", "output_text"]
    text: str = Field(max_length=1_000_000)


class ResponseMessageInput(StrictModel):
    type: Literal["message"] = "message"
    role: Literal["system", "developer", "user", "assistant"]
    content: str | list[ResponseInputText]


class FunctionCallOutputInput(StrictModel):
    type: Literal["function_call_output"]
    call_id: str = Field(min_length=1, max_length=256)
    output: str = Field(max_length=1_000_000)


class ResponsesFunctionTool(StrictModel):
    type: Literal["function"]
    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    description: str | None = Field(default=None, max_length=8192)
    parameters: dict[str, Any] = Field(default_factory=dict)
    strict: bool | None = None


class ResponsesRequest(StrictModel):
    model: str
    input: str | list[ResponseMessageInput | FunctionCallOutputInput]
    instructions: str | None = Field(default=None, max_length=1_000_000)
    temperature: float | None = Field(default=None, ge=0, le=2)
    top_p: float | None = Field(default=None, gt=0, le=1)
    max_output_tokens: int | None = Field(default=None, ge=1)
    reasoning: Reasoning | None = None
    text: ResponsesText | None = None
    tools: list[ResponsesFunctionTool] | None = Field(default=None, max_length=128)
    tool_choice: Literal["none", "auto", "required"] | dict[str, Any] | None = None
    parallel_tool_calls: bool | None = None
    stream: Literal[False] = False
    store: Literal[False] = False
    background: Literal[False] = False


class ErrorDetail(StrictModel):
    message: str
    type: str
    param: None = None
    code: str


class ErrorEnvelope(StrictModel):
    error: ErrorDetail


class ChatResponseMessage(StrictModel):
    role: Literal["assistant"]
    content: str | None = None
    refusal: str | None = None
    tool_calls: list[ToolCall] | None = None


class ChatChoice(StrictModel):
    index: int
    message: ChatResponseMessage
    finish_reason: str | None = None


class Usage(StrictModel):
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    prompt_tokens_details: dict[str, int] | None = None
    completion_tokens_details: dict[str, int] | None = None
    input_tokens_details: dict[str, int] | None = None
    output_tokens_details: dict[str, int] | None = None


class ChatResponse(StrictModel):
    id: str
    object: Literal["chat.completion"]
    created: int
    model: str
    choices: list[ChatChoice] = Field(min_length=1)
    usage: Usage | None = None
    service_tier: str | None = None
    system_fingerprint: str | None = None


class OutputText(StrictModel):
    type: Literal["output_text"]
    text: str
    annotations: list[Any] = Field(default_factory=list)
    logprobs: list[Any] | None = None

    @model_validator(mode="after")
    def unsupported_metadata_is_empty(self) -> "OutputText":
        if self.annotations or self.logprobs:
            raise ValueError("annotated or logprob output text is unsupported")
        return self


class RefusalOutput(StrictModel):
    type: Literal["refusal"]
    refusal: str


class ResponseOutputMessage(StrictModel):
    id: str
    type: Literal["message"]
    role: Literal["assistant"]
    status: str
    content: list[OutputText | RefusalOutput]


class ResponseFunctionCall(StrictModel):
    id: str | None = None
    type: Literal["function_call"]
    call_id: str
    name: str
    arguments: str
    status: str | None = None


class ResponsesResponse(StrictModel):
    id: str
    object: Literal["response"]
    created_at: float
    status: str
    error: None = None
    incomplete_details: None = None
    model: str
    output: list[ResponseOutputMessage | ResponseFunctionCall] = Field(min_length=1)
    usage: Usage | None = None
    background: Literal[False] | None = None
    instructions: None = None
    max_output_tokens: int | None = None
    metadata: dict[str, Any] | None = None
    parallel_tool_calls: bool | None = None
    previous_response_id: None = None
    reasoning: dict[str, Any] | None = None
    service_tier: str | None = None
    store: Literal[False] | None = None
    temperature: float | None = None
    text: ResponsesText | None = None
    tool_choice: Any | None = None
    tools: list[ResponsesFunctionTool] | None = None
    top_p: float | None = None
    truncation: str | None = None

    @model_validator(mode="after")
    def response_metadata_is_non_content(self) -> "ResponsesResponse":
        if self.metadata:
            raise ValueError("response metadata is unsupported")
        if self.reasoning:
            unexpected = {
                key: value
                for key, value in self.reasoning.items()
                if key != "effort"
                and value is not None
                and value != []
                and value != ""
            }
            if unexpected:
                raise ValueError("reasoning output content is unsupported")
        return self

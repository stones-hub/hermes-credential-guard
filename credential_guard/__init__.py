from __future__ import annotations

from .approval import on_pre_tool_call
from .cli import handle_command, setup_parser
from .hooks import on_transform_tool_result
from .middleware import on_llm_execution, on_llm_request
from .tool_request import on_tool_request
from .tool_execution import on_tool_execution
from .reference_tools import (
    HTTP_REFERENCE_TOOL,
    check_http_credential_request_available,
    handle_http_credential_request,
    http_credential_request_schema,
)
from .process_tools import (
    PROCESS_REFERENCE_TOOL,
    check_credential_process_run_available,
    credential_process_run_schema,
    handle_credential_process_run,
)
from .constants import TOOLSET_NAME


def register(ctx) -> None:
    ctx.register_middleware("llm_request", on_llm_request)
    ctx.register_middleware("llm_execution", on_llm_execution)
    ctx.register_middleware("tool_request", on_tool_request)
    ctx.register_middleware("tool_execution", on_tool_execution)
    ctx.register_hook("transform_tool_result", on_transform_tool_result)
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_tool(
        name=HTTP_REFERENCE_TOOL,
        toolset=TOOLSET_NAME,
        schema=http_credential_request_schema(),
        handler=handle_http_credential_request,
        check_fn=check_http_credential_request_available,
        description=http_credential_request_schema()["description"],
    )
    ctx.register_tool(
        name=PROCESS_REFERENCE_TOOL,
        toolset=TOOLSET_NAME,
        schema=credential_process_run_schema(),
        handler=handle_credential_process_run,
        check_fn=check_credential_process_run_available,
        description=credential_process_run_schema()["description"],
    )
    ctx.register_cli_command(
        name="credential-guard",
        help="credential-guard operations",
        setup_fn=setup_parser,
        handler_fn=handle_command,
    )

"""Minimal A2A v1.0 JSON-RPC server built on the official Python SDK (a2a-sdk).

Benchmark competitor for Silk. Mirrors the SDK's helloworld sample
(a2aproject/a2a-samples, samples/python/agents/helloworld) but the executor
answers every message with one agent Message "ok" (message-only interaction,
no Task, no streaming, no LLM).

    <venv>/bin/python -I server.py --port 9999

uvicorn runs in-process (single worker, no reload, access log off), so the
PID of this interpreter is the server.
"""

import argparse
import logging

import uvicorn

from a2a.helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill
from starlette.applications import Starlette


class OkExecutor(AgentExecutor):
    """Replies to every incoming message with a single agent message "ok"."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        # Message-only reply: no Task is created, so the reply carries the
        # conversation's contextId but no taskId (it would name a task that
        # never exists in the store).
        await event_queue.enqueue_event(
            new_text_message('ok', context_id=context.context_id)
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError('cancel is not supported')


def build_app(host: str, port: int) -> Starlette:
    card = AgentCard(
        name='silk-bench-ok',
        description='Replies "ok" to every message (benchmark target).',
        version='1.0.0',
        default_input_modes=['text/plain'],
        default_output_modes=['text/plain'],
        capabilities=AgentCapabilities(streaming=False),
        supported_interfaces=[
            AgentInterface(
                protocol_binding='JSONRPC',
                url=f'http://{host}:{port}/',
                protocol_version='1.0',
            )
        ],
        skills=[
            AgentSkill(
                id='ok',
                name='ok',
                description='Acknowledge a message with "ok".',
                tags=['bench'],
                input_modes=['text/plain'],
                output_modes=['text/plain'],
            )
        ],
    )
    handler = DefaultRequestHandler(
        agent_executor=OkExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    routes = []
    routes.extend(create_agent_card_routes(card))  # GET /.well-known/agent-card.json
    routes.extend(create_jsonrpc_routes(handler, '/'))  # POST / (JSON-RPC 2.0)
    return Starlette(routes=routes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)
    app = build_app(args.host, args.port)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        workers=1,
        reload=False,
        access_log=False,
        log_level='warning',
    )


if __name__ == '__main__':
    main()

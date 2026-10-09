# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
# Each enforce() call site below carries a SiteDescriptor with:
#   site_id            deterministic id for this exact call site (file +
#                      symbol + insertion point + pattern) — stable across
#                      re-scans, used to dedupe stub insertions and to look
#                      up this site's policy mapping at runtime.
#   candidate_policies policy IDs this site matched during the scan.
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m

import json
from typing import Optional
from uuid import UUID

from fastapi import HTTPException
from logger import get_logger
from litellm import completion
from llm.qa_base import QABaseBrainPicking
from llm.utils.call_brain_api import call_brain_api
from llm.utils.get_api_brain_definition_as_json_schema import (
    get_api_brain_definition_as_json_schema,
)
from models.chats import ChatQuestion
from models.databases.supabase.chats import CreateChatHistory
from modules.brain.service.brain_service import BrainService
from repository.chat.get_chat_history import GetChatHistoryOutput, get_chat_history
from repository.chat.update_chat_history import update_chat_history
from repository.chat.update_message_by_id import update_message_by_id

brain_service = BrainService()

logger = get_logger(__name__)

class APIBrainQA(
    QABaseBrainPicking,
):
    user_id: UUID

    def __init__(
        self,
        model: str,
        brain_id: str,
        chat_id: str,
        streaming: bool = False,
        prompt_id: Optional[UUID] = None,
        **kwargs,
    ):
        user_id = kwargs.get("user_id")
        if not user_id:
            raise HTTPException(status_code=400, detail="Cannot find user id")

        super().__init__(
            model=model,
            brain_id=brain_id,
            chat_id=chat_id,
            streaming=streaming,
            prompt_id=prompt_id,
            **kwargs,
        )
        self.user_id = user_id

    async def make_completion(
        self,
        messages,
        functions,
        brain_id: UUID,
        recursive_count = 0,
    ):  
        if recursive_count > 5:
            yield "🧠<Deciding what to do>🧠"
            yield "The assistant is having issues and took more than 5 calls to the API. Please try again later or an other instruction."
            return
        
        yield "🧠<Deciding what to do>🧠"
        response = completion(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            messages=messages,
            functions=functions,
            stream=True,
            function_call="auto",
        )

        function_call = {
            "name": None,
            "arguments": "",
        }
        for chunk in response:
            finish_reason = chunk.choices[0].finish_reason
            if finish_reason == "stop":
                break
            if "function_call" in chunk.choices[0].delta and chunk.choices[0].delta["function_call"]:
                if chunk.choices[0].delta["function_call"].name:
                    function_call["name"] = chunk.choices[0].delta["function_call"].name
                if chunk.choices[0].delta["function_call"].arguments:
                    function_call["arguments"] += chunk.choices[0].delta[
                        "function_call"
                    ].arguments

            elif finish_reason == "function_call":
                try:
                    arguments = json.loads(function_call["arguments"])
                    
                except Exception:
                    arguments = {}
                yield f"🧠<Calling {brain_id} with arguments {arguments}>🧠"

                try:
                    api_call_response = call_brain_api(
                        brain_id=brain_id,
                        user_id=self.user_id,
                        arguments=arguments,
                    )
                except Exception as e:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Error while calling API: {e}",
                    )
                
                function_name = function_call["name"]
                messages.append(
                    {
                        "role": "function",
                        "name": function_call["name"],
                        "content": f"The function {function_name} was called and gave The following answer:(data from function) {api_call_response} (end of data from function). Don't call this function again unless there was an error or extremely necessary and asked specifically by the user.",
                    }
                )
                async for value in self.make_completion(
                    messages=messages,
                    functions=functions,
                    brain_id=brain_id,
                    recursive_count=recursive_count + 1,
                ):
                    yield value

            else:
                if (
                    hasattr(chunk.choices[0], "delta")
                    and chunk.choices[0].delta
                    and hasattr(chunk.choices[0].delta, "content")
                ):
                    content = chunk.choices[0].delta.content
                    yield content
                else:  # pragma: no cover
                    yield "**...**"
                    break

    async def generate_stream(self, chat_id: UUID, question: ChatQuestion):
        if not question.brain_id:
            raise HTTPException(
                status_code=400, detail="No brain id provided in the question"
            )

        brain = brain_service.get_brain_by_id(question.brain_id)

        if not brain:
            raise HTTPException(status_code=404, detail="Brain not found")

        prompt_content = "You are a helpful assistant that can access functions to help answer questions. If there are information missing in the question, you can ask follow up questions to get more information to the user. Once all the information is available, you can call the function to get the answer."

        if self.prompt_to_use:
            prompt_content += self.prompt_to_use.content

        messages = [{"role": "system", "content": prompt_content}]

        history = get_chat_history(self.chat_id)

        for message in history:
            formatted_message = [
                {"role": "user", "content": message.user_message},
                {"role": "assistant", "content": message.assistant},
            ]
            messages.extend(formatted_message)

        messages.append({"role": "user", "content": question.question})

        streamed_chat_history = update_chat_history(
            CreateChatHistory(
                **{
                    "chat_id": chat_id,
                    "user_message": question.question,
                    "assistant": "",
                    "brain_id": question.brain_id,
                    "prompt_id": self.prompt_to_use_id,
                }
            )
        )
        streamed_chat_history = GetChatHistoryOutput(
            **{
                "chat_id": str(chat_id),
                "message_id": streamed_chat_history.message_id,
                "message_time": streamed_chat_history.message_time,
                "user_message": question.question,
                "assistant": "",
                "prompt_title": self.prompt_to_use.title
                if self.prompt_to_use
                else None,
                "brain_name": brain.name if brain else None,
            }
        )
        response_tokens = []
        async for value in self.make_completion(
            messages=messages,
            functions=[get_api_brain_definition_as_json_schema(brain)],
            brain_id=question.brain_id,
        ):
            streamed_chat_history.assistant = value
            response_tokens.append(value)
            _lineaje_payload = streamed_chat_history.dict()
            # LINEAJE: enforce() `_lineaje_payload` at agent->external data_egress — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_059 (Do not allow prompts that can execute malicious commands at runtime.). Mask/block; do not remove without review. site_id='site:sha256:875e8ecd9f9eafeb929ff36d6070993ffc1fb761e929932c7c40f4a7c302ecff'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:875e8ecd9f9eafeb929ff36d6070993ffc1fb761e929932c7c40f4a7c302ecff', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'external_endpoint'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='external')
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=200))
            except _gr_client.GuardrailUnavailableError:
                pass
            yield f"data: {json.dumps(_lineaje_payload)}"
        response_tokens = [
            token
            for token in response_tokens
            if not token.startswith("🧠<") and not token.endswith(">🧠")
        ]
        update_message_by_id(
            message_id=str(streamed_chat_history.message_id),
            user_message=question.question,
            assistant="".join(response_tokens),
        )

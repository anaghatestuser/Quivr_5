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

import asyncio
import json
from typing import AsyncIterable, Awaitable, List, Optional
from uuid import UUID

from langchain.callbacks.streaming_aiter import AsyncIteratorCallbackHandler
from langchain.chains import LLMChain
from langchain.chat_models import ChatLiteLLM
from langchain.chat_models.base import BaseChatModel
from models import BrainSettings  # Importing settings related to the 'brain'
from langchain.prompts.chat import ChatPromptTemplate, HumanMessagePromptTemplate
from logger import get_logger
from models.chats import ChatQuestion
from models.databases.supabase.chats import CreateChatHistory
from modules.prompt.entity.prompt import Prompt
from pydantic import BaseModel
from repository.chat import (
    GetChatHistoryOutput,
    format_chat_history,
    format_history_to_openai_mesages,
    get_chat_history,
    update_chat_history,
    update_message_by_id,
)

from llm.utils.get_prompt_to_use import get_prompt_to_use
from llm.utils.get_prompt_to_use_id import get_prompt_to_use_id

logger = get_logger(__name__)
SYSTEM_MESSAGE = "Your name is Quivr. You're a helpful assistant. If you don't know the answer, just say that you don't know, don't try to make up an answer.When answering use markdown or any other techniques to display the content in a nice and aerated way."


class HeadlessQA(BaseModel):
    brain_settings = BrainSettings() 
    model: str
    temperature: float = 0.0
    max_tokens: int = 2000
    streaming: bool = False
    chat_id: str
    callbacks: Optional[List[AsyncIteratorCallbackHandler]] = None
    prompt_id: Optional[UUID] = None

    def _determine_streaming(self, streaming: bool) -> bool:
        """If the model name allows for streaming and streaming is declared, set streaming to True."""
        # LINEAJE: enforce() `streaming` at agent->user_interface data_egress — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_APP_SEC_002 (Do not allow malicious content via encoded prompts); AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.). Mask/block; do not remove without review. site_id='site:sha256:a63e98b8fd59303fd96dd77487960064cf5ff37695fb490fbdf9d36217248b96'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a63e98b8fd59303fd96dd77487960064cf5ff37695fb490fbdf9d36217248b96', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            streaming = _gr_client.enforce(_gr_site, streaming, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return streaming

    def _determine_callback_array(
        self, streaming
    ) -> List[AsyncIteratorCallbackHandler]:
        """If streaming is set, set the AsyncIteratorCallbackHandler as the only callback."""
        if streaming:
            return [AsyncIteratorCallbackHandler()]
        else:
            return []

    def __init__(self, **data):
        super().__init__(**data)
        self.streaming = self._determine_streaming(self.streaming)
        self.callbacks = self._determine_callback_array(self.streaming)

    @property
    def prompt_to_use(self) -> Optional[Prompt]:
        return get_prompt_to_use(None, self.prompt_id)

    @property
    def prompt_to_use_id(self) -> Optional[UUID]:
        return get_prompt_to_use_id(None, self.prompt_id)

    def _create_llm(
        self,
        model,
        temperature=0,
        streaming=False,
        callbacks=None,
    ) -> BaseChatModel:
        """
        Determine the language model to be used.
        :param model: Language model name to be used.
        :param streaming: Whether to enable streaming of the model
        :param callbacks: Callbacks to be used for streaming
        :return: Language model instance
        """
        api_base = None
        if self.brain_settings.ollama_api_base_url and model.startswith("ollama"):
            api_base = self.brain_settings.ollama_api_base_url

        return ChatLiteLLM(
            temperature=temperature,
            model=model,
            streaming=streaming,
            verbose=True,
            callbacks=callbacks,
            max_tokens=self.max_tokens,
            api_base=api_base,
        )

    def _create_prompt_template(self):
        messages = [
            HumanMessagePromptTemplate.from_template("{question}"),
        ]
        CHAT_PROMPT = ChatPromptTemplate.from_messages(messages)
        # LINEAJE: enforce() `CHAT_PROMPT` at agent->user_interface data_egress — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_APP_SEC_002 (Do not allow malicious content via encoded prompts); AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.). Mask/block; do not remove without review. site_id='site:sha256:b5770bb380872c0099cca9cce8d813122f7fd223cb9dfa090a2e27eaacb30daa'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b5770bb380872c0099cca9cce8d813122f7fd223cb9dfa090a2e27eaacb30daa', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            CHAT_PROMPT = _gr_client.enforce(_gr_site, CHAT_PROMPT, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return CHAT_PROMPT

    def generate_answer(
        self, chat_id: UUID, question: ChatQuestion
    ) -> GetChatHistoryOutput:
        transformed_history = format_chat_history(get_chat_history(self.chat_id))
        prompt_content = (
            self.prompt_to_use.content if self.prompt_to_use else SYSTEM_MESSAGE
        )

        messages = format_history_to_openai_mesages(
            transformed_history, prompt_content, question.question
        )
        answering_llm = self._create_llm(
            model=self.model,
            streaming=False,
            callbacks=self.callbacks,
        )
        model_prediction = answering_llm.predict_messages(messages)
        answer = model_prediction.content

        new_chat = update_chat_history(
            CreateChatHistory(
                **{
                    "chat_id": chat_id,
                    "user_message": question.question,
                    "assistant": answer,
                    "brain_id": None,
                    "prompt_id": self.prompt_to_use_id,
                }
            )
        )

        return GetChatHistoryOutput(
            **{
                "chat_id": chat_id,
                "user_message": question.question,
                "assistant": answer,
                "message_time": new_chat.message_time,
                "prompt_title": self.prompt_to_use.title
                if self.prompt_to_use
                else None,
                "brain_name": None,
                "message_id": new_chat.message_id,
            }
        )

    async def generate_stream(
        self, chat_id: UUID, question: ChatQuestion
    ) -> AsyncIterable:
        callback = AsyncIteratorCallbackHandler()
        self.callbacks = [callback]

        transformed_history = format_chat_history(get_chat_history(self.chat_id))
        prompt_content = (
            self.prompt_to_use.content if self.prompt_to_use else SYSTEM_MESSAGE
        )

        messages = format_history_to_openai_mesages(
            transformed_history, prompt_content, question.question
        )
        answering_llm = self._create_llm(
            model=self.model,
            streaming=True,
            callbacks=self.callbacks,
        )

        CHAT_PROMPT = ChatPromptTemplate.from_messages(messages)
        headlessChain = LLMChain(llm=answering_llm, prompt=CHAT_PROMPT)

        response_tokens = []

        async def wrap_done(fn: Awaitable, event: asyncio.Event):
            try:
                await fn
            except Exception as e:
                _lineaje_payload = f"Caught exception: {e}"
                # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_APP_SEC_002 (Do not allow malicious content via encoded prompts); AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.). Mask/block; do not remove without review. site_id='site:sha256:24cdc634871facd68362f3377bdd5a9002a959cf8c8d4b0f66b0fc7add81f92a'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:24cdc634871facd68362f3377bdd5a9002a959cf8c8d4b0f66b0fc7add81f92a', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
                try:
                    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                logger.error(_lineaje_payload)
            finally:
                event.set()

        run = asyncio.create_task(
            wrap_done(
                headlessChain.acall({}),
                callback.done,
            ),
        )

        streamed_chat_history = update_chat_history(
            CreateChatHistory(
                **{
                    "chat_id": chat_id,
                    "user_message": question.question,
                    "assistant": "",
                    "brain_id": None,
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
                "brain_name": None,
            }
        )

        async for token in callback.aiter():
            # LINEAJE: enforce() `token` at agent->log log_emit — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_APP_SEC_002 (Do not allow malicious content via encoded prompts); AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.). Mask/block; do not remove without review. site_id='site:sha256:197c95f9bcbe5d09342409b164114fad8ca8c6f77f894c3434ada69cd865f1d0'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:197c95f9bcbe5d09342409b164114fad8ca8c6f77f894c3434ada69cd865f1d0', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            try:
                token = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, token, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.info("Token: %s", token)
            response_tokens.append(token)
            streamed_chat_history.assistant = token
            _lineaje_payload = streamed_chat_history.dict()
            # LINEAJE: enforce() `_lineaje_payload` at agent->external data_egress — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_APP_SEC_002 (Do not allow malicious content via encoded prompts); AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.). Mask/block; do not remove without review. site_id='site:sha256:ddbe3e84b4c0913858c42e90a4ae89270c378790ba090ba1ca4a1bdcecadf897'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ddbe3e84b4c0913858c42e90a4ae89270c378790ba090ba1ca4a1bdcecadf897', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'external_endpoint'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='external')
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=219))
            except _gr_client.GuardrailUnavailableError:
                pass
            yield f"data: {json.dumps(_lineaje_payload)}"

        await run
        assistant = "".join(response_tokens)

        update_message_by_id(
            message_id=str(streamed_chat_history.message_id),
            user_message=question.question,
            assistant=assistant,
        )

    class Config:
        arbitrary_types_allowed = True

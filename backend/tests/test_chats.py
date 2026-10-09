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

import random
import string


def test_get_all_chats(client, api_key):
    # Making a GET request to the /chat endpoint to retrieve all chats
    response = client.get(
        "/chat",
        headers={"Authorization": "Bearer " + api_key},
    )

    # Assert that the response status code is 200 (HTTP OK)
    assert response.status_code == 200

    # Assert that the response data is a list
    response_data = response.json()

    # Optionally, you can loop through the chats and assert on specific fields
    for chat in response_data["chats"]:
        # e.g., assert that each chat object contains 'chat_id' and 'chat_name'
        assert "chat_id" in chat
        assert "chat_name" in chat


def test_create_chat_and_talk(client, api_key):
    # Make a POST request to chat with the default brain and a random chat name
    random_chat_name = "".join(
        random.choices(string.ascii_letters + string.digits, k=10)
    )

    brain_response = client.get(
        "/brains/default", headers={"Authorization": "Bearer " + api_key}
    )
    assert brain_response.status_code == 200
    default_brain_id = brain_response.json()["id"]
    _lineaje_payload = "Default brain id: " + default_brain_id
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_059 (Do not allow prompts that can execute malicious commands at runtime.). Mask/block; do not remove without review. site_id='site:sha256:939c4c576a623d2fb1d9e2516ee4cf00cd0047ad2cdd5447f253cb175c77bd55'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:939c4c576a623d2fb1d9e2516ee4cf00cd0047ad2cdd5447f253cb175c77bd55', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    try:
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    print(_lineaje_payload)

    # Create a chat
    response = client.post(
        "/chat",
        json={"name": random_chat_name},
        headers={"Authorization": "Bearer " + api_key},
    )
    assert response.status_code == 200

    # now talk to the chat with a question
    response_data = response.json()
    # LINEAJE: enforce() `response_data` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_059 (Do not allow prompts that can execute malicious commands at runtime.). Mask/block; do not remove without review. site_id='site:sha256:dfd84c8f80c89cfb1754edc1008b84bd968dba78ea7c57ba91cb4ddd0977d197'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:dfd84c8f80c89cfb1754edc1008b84bd968dba78ea7c57ba91cb4ddd0977d197', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    try:
        response_data = _gr_client.enforce(_gr_site, response_data, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    print(response_data)
    chat_id = response_data["chat_id"]
    response = client.post(
        f"/chat/{chat_id}/question?brain_id={default_brain_id}",
        json={
            "model": "gpt-3.5-turbo",
            "question": "Hello, how are you?",
            "temperature": "0",
            "max_tokens": "256",
        },
        headers={"Authorization": "Bearer " + api_key},
    )
    assert response.status_code == 200

    response = client.post(
        f"/chat/{chat_id}/question?brain_id={default_brain_id}",
        json={
            "model": "gpt-4",
            "question": "Hello, how are you?",
            "temperature": "0",
            "max_tokens": "256",
        },
        headers={"Authorization": "Bearer " + api_key},
    )
    # LINEAJE: enforce() `response` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_059 (Do not allow prompts that can execute malicious commands at runtime.). Mask/block; do not remove without review. site_id='site:sha256:209f190ed07a26efef2bdf8bb27c46a786f9bac40c07acae3f95b19321d184d9'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:209f190ed07a26efef2bdf8bb27c46a786f9bac40c07acae3f95b19321d184d9', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    try:
        response = _gr_client.enforce(_gr_site, response, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    print(response)
    assert response.status_code == 200

    # Now, let's delete the chat
    delete_response = client.delete(
        "/chat/" + chat_id, headers={"Authorization": "Bearer " + api_key}
    )
    assert delete_response.status_code == 200


def test_create_chat_and_talk_with_no_brain(client, api_key):
    # Make a POST request to chat with no brain id and a random chat name
    random_chat_name = "".join(
        random.choices(string.ascii_letters + string.digits, k=10)
    )

    # Create a chat
    response = client.post(
        "/chat",
        json={"name": random_chat_name},
        headers={"Authorization": "Bearer " + api_key},
    )
    assert response.status_code == 200

    # now talk to the chat with a question
    response_data = response.json()
    # LINEAJE: enforce() `response_data` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_059 (Do not allow prompts that can execute malicious commands at runtime.). Mask/block; do not remove without review. site_id='site:sha256:5b7539290110c690b563cebf0e36cd8d09a6aaa21ed10ee57f18606d8fb95ab3'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5b7539290110c690b563cebf0e36cd8d09a6aaa21ed10ee57f18606d8fb95ab3', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    try:
        response_data = _gr_client.enforce(_gr_site, response_data, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    print(response_data)
    chat_id = response_data["chat_id"]
    response = client.post(
        f"/chat/{chat_id}/question?brain_id=",
        json={
            "model": "gpt-3.5-turbo",
            "question": "Hello, how are you?",
            "temperature": "0",
            "max_tokens": "256",
        },
        headers={"Authorization": "Bearer " + api_key},
    )
    assert response.status_code == 200

    # Now, let's delete the chat
    delete_response = client.delete(
        "/chat/" + chat_id, headers={"Authorization": "Bearer " + api_key}
    )
    assert delete_response.status_code == 200


# Test delete all chats for a user
def test_delete_all_chats(client, api_key):
    chats = client.get("/chat", headers={"Authorization": "Bearer " + api_key})
    assert chats.status_code == 200
    chats_data = chats.json()
    for chat in chats_data["chats"]:
        # e.g., assert that each chat object contains 'chat_id' and 'chat_name'
        assert "chat_id" in chat
        assert "chat_name" in chat
        chat_id = chat["chat_id"]
        delete_response = client.delete(
            "/chat/" + chat_id, headers={"Authorization": "Bearer " + api_key}
        )
        assert delete_response.status_code == 200

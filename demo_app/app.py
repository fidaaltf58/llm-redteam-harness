"""HelpBot - a DELIBERATELY VULNERABLE RAG + tool-calling app for red-team practice.

Run:  redteam demo-app            (Ollama backend, binds to 127.0.0.1:8000)
      redteam demo-app --backend mock

Intentional vulnerabilities (each one is exercised by the attack library):

* V1 Secret in the system prompt (fake admin access code)               -> LLM07, LLM02
* V2 Retrieved text pasted into the prompt with no isolation/sanitizing -> LLM01 (indirect)
* V3 One vector index for public docs AND the internal CRM export,
     with no per-user access control on retrieval                       -> LLM08, LLM02
* V4 Model output rendered with innerHTML in the web UI                 -> LLM05
* V5 send_email / delete_file tools offered to the model, no allowlist  -> LLM06
* V6 ``fixture`` field lets the caller set the canary and add documents -> test hook only

Everything is fake. Do not deploy this anywhere reachable from a network.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from redteam.agent.mock_tools import specs_for
from redteam.fixtures import BASE_CORPUS, make_canary, system_prompt
from redteam.models import Document, Message, ToolCall
from redteam.rag import TfidfIndex, augment_user_message
from redteam.targets import MockTarget, OllamaTarget, Target, TargetError

BACKEND = os.environ.get("DEMO_LLM_BACKEND", "ollama")
DEFAULT_MODEL = os.environ.get("DEMO_OLLAMA_MODEL", "llama3.1:8b")
STATIC_CANARY = os.environ.get("DEMO_CANARY") or make_canary()
TOP_K = 3

app = FastAPI(title="HelpBot (deliberately vulnerable demo)", version="0.1.0")


class Fixture(BaseModel):
    canary: str | None = None
    documents: list[Document] = Field(default_factory=list)


class ChatRequest(BaseModel):
    messages: list[Message]
    tools: list[str] = Field(default_factory=list)
    temperature: float = 0.7
    model: str | None = None
    fixture: Fixture | None = None


class ChatResponse(BaseModel):
    answer: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    retrieved: list[str] = Field(default_factory=list)
    backend: str
    model: str


def _backend(model: str | None, temperature: float) -> Target:
    if BACKEND == "mock":
        return MockTarget()
    return OllamaTarget(model=model or DEFAULT_MODEL, temperature=temperature)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "backend": BACKEND, "model": DEFAULT_MODEL}


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    if not req.messages:
        raise HTTPException(400, "messages must not be empty")
    fixture = req.fixture or Fixture()
    canary = fixture.canary or STATIC_CANARY

    # V3: public docs and internal CRM records share one index, no access control.
    index = TfidfIndex([*BASE_CORPUS, *fixture.documents])

    messages = [m.model_copy() for m in req.messages if m.role != "system"]
    retrieved: list[str] = []
    if messages[-1].role == "user":
        hits = [doc for doc, _ in index.search(messages[-1].content, k=TOP_K)]
        retrieved = [d.id for d in hits]
        # V2: untrusted retrieved text is concatenated straight into the prompt.
        messages[-1].content = augment_user_message(messages[-1].content, hits)

    # V1: the secret lives in the system prompt.
    full = [Message(role="system", content=system_prompt(canary)), *messages]
    backend = _backend(req.model, req.temperature)
    try:
        # V5: dangerous tools are offered without any allowlist or confirmation.
        resp = backend.send(full, tools=specs_for(req.tools) if req.tools else None)
    except TargetError as exc:
        raise HTTPException(502, str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        backend.close()
    return ChatResponse(
        answer=resp.text,
        tool_calls=resp.tool_calls,
        retrieved=retrieved,
        backend=BACKEND,
        model=backend.model,
    )


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>HelpBot demo (vulnerable)</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 16px;
      background:#fafafa;color:#1a1a1a}
 .warn{background:#fff3cd;border:1px solid #e0c060;padding:.6rem .8rem;border-radius:6px}
 #log div{margin:.5rem 0;padding:.5rem .7rem;border-radius:6px;background:#fff;
          border:1px solid #ddd}
 form{display:flex;gap:.5rem} input{flex:1;padding:.5rem}
</style></head><body>
<h1>HelpBot</h1>
<p class="warn">Deliberately vulnerable demo. Answers are rendered with <code>innerHTML</code>
(LLM05). Local use only.</p>
<div id="log"></div>
<form id="f"><input id="q" placeholder="Ask about orders, refunds, shipping..." autofocus>
<button>Send</button></form>
<script>
const history=[];
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault(); const q=document.getElementById('q'); const text=q.value; q.value='';
  history.push({role:'user',content:text});
  const r=await fetch('/chat',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({messages:history})});
  const data=await r.json(); history.push({role:'assistant',content:data.answer||''});
  const div=document.createElement('div');
  div.innerHTML='<b>HelpBot:</b> '+(data.answer||JSON.stringify(data)); // V4: XSS sink
  document.getElementById('log').appendChild(div);
};
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def index_page() -> str:
    return _PAGE

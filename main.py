import os
import re
import json
import hashlib
import posixpath
import ipaddress
import socket
import requests

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any

REGISTERED_EMAIL = "23f2003086@ds.study.iitm.ac.in"

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-8e58b01100"
 
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
 
MAX_REDIRECTS = 5
FETCH_TIMEOUT_SECONDS = 5
MAX_RESPONSE_CHARS = 4000

app = FastAPI()

class ProratmaionRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int 
    days_in_actual_month: int 
    spec: str 

class ToolRequest(BaseModel):
    tool: str 
    command: str = ""
    path: str = ""
    content: str = ""
    method: str = ""
    url: str = ""

class SkillRequest(BaseModel):
    skill: str

class Step(BaseModel):
    step_number: int
    tool: str
    args: Any = {}
    tokens_used: int

class RunRequest(BaseModel):
    budget_tokens: int
    steps: List[Step]


@app.post("/prorate")
def calculate_proration(req: ProratmaionRequest):
    price_difference = req.new_price - req.old_price

    if req.spec == "v1":
        charge = price_difference * (req.days_remaining / 30.0)
    elif req.spec == "v2":
        charge = price_difference * (req.days_remaining / float(req.days_in_actual_month))
    else:
        raise HTTPException(status_code=400, detail="Unknown spec. Must be 'v1' or 'v2'.")
    return {"charge": charge}

@app.post("/guardrail")
def check_agent_action(req: ToolRequest):
    # Rule 1: HTTP Requests 
    if req.tool == "http_request":
        parsed_url = urlparse(req.url)

        if parsed_url.hostname in ["pypi.org", "huggingface.co"]:
            return {
                "decision": "allow", 
                "reason": "Sage website."
            }
        else: 
            return {
                "decision": "block", 
                "reason": "Website not on the allowlist."
            }
        
    # Rule 2: Writting files 
    if req.tool == "write_file":
        simulated_path = os.path.normpath(
            os.path.join("/home/agent/workspace", req.path)
        )
        if simulated_path.startswith("/srv/reports/"):
            return {
                "decision": "allow", 
                "reason": "Writing to allowed folder."
            }
        else:
            return {
                "decision": "block", 
                "reason": "Trying to write outside of /srv/reports/."
            }
    
    # Rule 3: Bash commands 
    if req.tool == "bash":
        cmd = req.command.lower()
        bad_words = [
            "bashrc",
            "~",
            "$home",
            "base64"
        ]

        for word in bad_words:
            if word in cmd:
                return {"decision": "block", "reason": f"Command contains forbidden trick: {word}"}

        return {"decision": "allow", "reason": "Command looks safe."}

    # unknown tool
    return {"decision": "block", "reason": "Unknown tool used."}

@app.post("/scan")
def scan_skill(req: SkillRequest):
    raw_text = req.skill 
    text_lower = raw_text.lower()

    categories = set()

    # Rule 1: Hardcoded Secrets 
    if (
        re.search(r'(sk-[a-zA-Z0-9]{20,})', raw_text) or 
        re.search(r'(xox[pbo]-[a-zA-Z0-9]{10,})', raw_text) or 
        re.search(r'(bearer|token)[\s:=]+[a-zA-Z0-9\-\.]{20,}', text_lower) or
        re.search(r'https?://[^\s>\"\']*(webhook|secret)[^\s>\"\']*', text_lower) or
        re.search(r'(api[_\-]?key|secret|token|password)[\s:=]+[\'\"]?[a-zA-Z0-9\-\.\_]{20,}[\'\"]?', text_lower)
    ): categories.add("hardcoded_secret")

    # Rule 2: Disguised Prompt Injection 
    injection_flags = [
        "ignore previous", 
        "disregard previous",
        "forget previous",
        "exfiltrate", 
        "do not notify", 
        "without asking", 
        "without user confirmation",
        "silently send",
        "bypass",
        "override"
    ]
    if any(flag in text_lower for flag in injection_flags): categories.add("prompt_injection")

    # Rule 3: Excessive Permissions 
    if (
        re.search(r'\[[^\]]*["\']?\*["\']?[^\]]*\]', raw_text) or 
        re.search(r'\[[^\]]*["\']?\/["\']?[^\]]*\]', raw_text) or 
        "entire filesystem" in text_lower or 
        "any domain" in text_lower or
        "all domains" in text_lower
    ): categories.add("excessive_permissions")

    # Rule 4: Unclear Provenance 
    if (
        "author:" not in text_lower or 
        "version:" not in text_lower or 
        "changelog:" not in text_lower
    ): categories.add("unclear_provenance")

    provenance_hiding_flags = [
        "silently update version", 
        "silently rewrite",
        "do not log this change",
        "without updating the changelog"
    ]
    if any(flag in text_lower for flag in provenance_hiding_flags):
        categories.add("unclear_provenance")

    return {"categories": list(categories)}


def normalize_args(args_dict):
    def clean_val(v):
        if isinstance(v, str):
            return " ".join(v.split())
        elif isinstance(v, dict):
            return {k: clean_val(val) for k, val in v.items() if k != "trace_id"}
        elif isinstance(v, list):
            return [clean_val(item) for item in v]
        else:
            return v

    cleaned_dict = clean_val(args_dict)
    return json.dumps(cleaned_dict, sort_keys=True)

@app.post("/check")
def check_run(req: RunRequest):
    total_tokens = sum(step.tokens_used for step in req.steps)
    if total_tokens >= req.budget_tokens:
        return {
            "decision": "halt",
            "reason": "Budget exhausted."
        }

    cleaned_history = []
    for step in req.steps:
        cleaned_history.append((step.tool, normalize_args(step.args)))

    history_length = len(cleaned_history)

    if history_length >= 3:
        last_3 = cleaned_history[-3:]
        if last_3[0] == last_3[1] == last_3[2]:
            return {
                "decision": "halt",
                "reason": "Loop detected: 3 identical steps in a row."
            }

    if history_length >= 6:
        a1, b1, a2, b2, a3, b3 = cleaned_history[-6:]

        if a1 == a2 == a3 and b1 == b2 == b3 and a1 != b1:
            return {
                "decision": "halt",
                "reason": "Loop detected: 6-step alternating cycle."
            }

    return {
        "decision": "continue",
        "reason": "Looking good, keep going."
    }

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    msg = await request.json()

    if not msg or msg.get("jsonrpc") != "2.0":
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": msg.get("id") if msg else None,
                "error": {"code": -32600, "message": "Invalid Request"},
            },
        )
    
    msg_id = msg.get("id")
    method = msg.get("method")

    if msg_id is None: 
        return Response(status_code=202)

    if method == "initialize":
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "solve-challenge-server",
                        "version": "1.0.0",
                    },
                },
            }
        )
 
    if method == "tools/list":
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "solve_challenge",
                            "description": (
                                "Reads the X-Exam-Challenge header and "
                                "returns the required hash."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                                "required": [],
                            },
                        }
                    ]
                },
            }
        )
 
    if method == "tools/call":
        params = msg.get("params") or {}
        tool_name = params.get("name")
 
        if tool_name != "solve_challenge":
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32602,
                        "message": f"Unknown tool: {tool_name}",
                    },
                }
            )
 
        challenge = request.headers.get("x-exam-challenge")
 
        if not challenge:
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32000,
                        "message": "Missing X-Exam-Challenge header",
                    },
                }
            )
 
        raw = f"{challenge}:{REGISTERED_EMAIL}"
        full_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        answer = full_hash[:16]
 
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": answer}]},
            }
        )
 
    return JSONResponse(
        content={
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    )

def resolve_inside_sandbox(path):
    if not isinstance(path, str) or path == "" or "\x00" in path:
        return None 

    try: 
        if os.path.isabs(path):
            candidate = path
        else: 
            candidate = os.path.join(SANDBOX_ROOT, path)
        
        real = os.path.realpath(candidate)
        root_real = os.path.realpath(SANDBOX_ROOT)

        if real == root_real or real.startswith(root_real + os.sep):
            return real 
        return None

    except (ValueError, TypeError, OSError):
        return None 

def handle_read_file(arguments):
    path = (arguments or {}).get("path")
    real_path = resolve_inside_sandbox(path)

    if real_path is None:
        return {
            "action": "block",
            "reason": "path is outside the allowed sandbox directory",
        }

    if not os.path.isfile(real_path):
        return {
            "action": "allow",
            "reason": "path is inside sandbox; file not found",
            "result": "",
        }

    try:
        with open(real_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return {
            "action": "allow",
            "reason": "path is inside sandbox; read failed",
            "result": f"error reading file: {e}",
        }
 
    return {
        "action": "allow",
        "reason": "path is inside sandbox",
        "result": content,
    }

def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return False

    if ip_str == "169.254.169.254":
        return False
 
    return True

def hostname_allowed(hostname):
    if not hostname:
        return False
    normalized = hostname.lower().rstrip(".")
    return normalized in ALLOWED_HOSTS

def validate_url(url):
    """
    Returns (ok: bool, reason: str, hostname: str|None)
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False, "malformed URL", None
 
    if parts.scheme not in ("http", "https"):
        return False, "only http/https schemes are allowed", None
 

    if "@" in parts.netloc:
        return False, "userinfo in URL is not allowed", None
 
    hostname = parts.hostname
    if not hostname_allowed(hostname):
        return False, f"host not in allow-list: {hostname}", None
 
    if parts.port is not None and parts.port not in (80, 443):
        return False, "non-standard port is not allowed", None
 
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, "DNS resolution failed", None
 
    resolved_ips = {info[4][0] for info in infos}
    if not resolved_ips:
        return False, "no addresses resolved", None
 
    for ip_str in resolved_ips:
        if not is_public_ip(ip_str):
            return False, f"host resolves to non-public address", None
 
    return True, "ok", hostname


def handle_fetch_url(arguments):
    url = (arguments or {}).get("url")
    if not isinstance(url, str) or url == "":
        return {"action": "block", "reason": "missing url"}
 
    current_url = url
 
    for _ in range(MAX_REDIRECTS):
        ok, reason, _ = validate_url(current_url)
        if not ok:
            return {"action": "block", "reason": reason}
 
        try:
            resp = requests.get(
                current_url,
                timeout=FETCH_TIMEOUT_SECONDS,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as e:
            return {
                "action": "block",
                "reason": f"fetch failed: {e}",
            }
 
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                return {
                    "action": "block",
                    "reason": "redirect with no Location header",
                }

            current_url = urljoin(current_url, location)
            continue
 
        text = resp.text[:MAX_RESPONSE_CHARS]
        return {
            "action": "allow",
            "reason": "host is on the allow-list",
            "result": {"status": resp.status_code, "body": text},
        }
 
    return {"action": "block", "reason": "too many redirects"}

app.post("/guardrail-q8")
async def guardrail(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            content={"action": "block", "reason": "invalid JSON body"}
        )
 
    tool = (body or {}).get("tool")
    arguments = (body or {}).get("arguments") or {}
 
    if tool == "read_file":
        decision = handle_read_file(arguments)
    elif tool == "fetch_url":
        decision = handle_fetch_url(arguments)
    else:
        decision = {"action": "block", "reason": f"unknown tool: {tool}"}
 
    return JSONResponse(content=decision)

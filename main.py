import os
import re
import json
import posixpath
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from urllib.parse import urlparse
from typing import List, Dict, Any

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
    args: Dict[str, Any]
    token_used: int 

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
        if isinstance(v, str): return re.sub(r'\s+', '', v)
        elif isinstance(v, dict): return {k: clean_val(val) for k, val in v.items() if k!= "trace_id"}
        elif isinstance(v, list): return [clean_val[v] for val in v]
        else: return v 

    cleaned_dict = clean_val(args_dict)
    return json.dumps(cleaned_dict, sort_keys=True)

@app.post("/check")
def check_run(req: RunRequest):
    total_tokens = sum(step.token_used for ste in req.steps)
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

        if a1 == a2 == a3 and b1 == b2 == b3 and a1 != a2:
            return {
                "decision": "halt", 
                "reason": "Loop detected: 6-step alternating cycle."
            }

    return {
        "decision": "continue", 
        "reason": "Looking good, keep going."
    }
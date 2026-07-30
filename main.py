import os
import re
import posixpath
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from urllib.parse import urlparse

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
            return {"decision": "allow", "reason": "Sage website."}
        else: 
            return {"decision": "block", "reason": "Website not on the allowlist."}
        
    # Rule 2: Writting files 
    if req.tool == "write_file":
        simulated_path = posixpath.normpath(posixpath.join("/home/agent/workspace", req.path))
        if simulated_path.startswith("/srv/reports/"):
            return {"decision": "allow", "reason": "Writing to allowed folder."}
        else:
            return {"decision": "block", "reason": "Trying to write outside of /srv/reports/."}
    
    # Rule 3: Bash commands 
    if req.tool == "bash":
        cmd = req.command
        cmd_clean = cmd.lower().replace('"', '').replace("'", "").replace("\\", "")
        
        if "bashrc" in cmd_clean or "shadow" in cmd_clean:
            return {"decision": "block", "reason": "Trying to read a restricted file."}
            
        b64_candidates = re.findall(r'[a-zA-Z0-9+/]+={0,2}', cmd)
        for candidate in b64_candidates:
            if len(candidate) >= 8:
                try:
                    decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore').lower()
                    if "bashrc" in decoded or "shadow" in decoded:
                        return {"decision": "block", "reason": "Trying to read a restricted file using Base64."}
                except Exception:
                    pass
                    
        return {"decision": "allow", "reason": "Command looks safe."}
    
    # Unknown tools
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


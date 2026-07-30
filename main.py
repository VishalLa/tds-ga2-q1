import os
import re
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
        simulated_path = os.path.normpath(os.path.join("/home/agent/workspace", req.path))
        if simulated_path.startswith("/srv/reports/"):
            return {"decision": "allow", "reason": "Writing to allowed folder."}
        else:
            return {"decision": "block", "reason": "Trying to write outside of /srv/reports/."}
    
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
        re.search(r'sk-[a-zA-Z0-9]{20,}', raw_text) or
        re.search(r'xoxb-[0-9a-zA-Z]{10,}', raw_text) or 
        "webhook" in text_lower or
        re.search(r'bearer\s+[a-zA-Z0-9\-\.]{20,}', text_lower)
    ): categories.add("hardcoded_secret")

    # Rule 2: Disguised Prompt Injection 
    injection_flags = [
        "ignore previous", 
        "exfiltrate", 
        "do not notify", 
        "without asking", 
        "bypass"
    ]
    if any(flag in text_lower for flag in injection_flags): categories.add("prompt_injection")

    # Rule 3: Excessive Permissions 
    if (
        re.search(r'\[\s*["\']?\*["\']?\s*\]', raw_text) or 
        re.search(r'\[\s*["\']?\/["\']?\s*\]', raw_text) or 
        "entire filesystem" in text_lower or 
        "any domain" in text_lower
    ): categories.add("excessive_permissions")

    # Rule 4: Unclear Provenance 
    if "author:" not in text_lower or "version:" not in text_lower: categories.add("unclear_provenance")
    if "silently update version" in text_lower or "silently rewrite" in text_lower: categories.add("unclear_provenance")

    return {"categories": list(categories)}


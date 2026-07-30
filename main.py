import os
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

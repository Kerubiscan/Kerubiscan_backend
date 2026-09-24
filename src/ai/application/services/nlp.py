import httpx
import os
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama").lower() # "ollama", "gemini", or "openai"
AI_MODEL = os.getenv("AI_MODEL", "")
AI_API_KEY = os.getenv("AI_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", AI_API_KEY)
AI_ENDPOINT = os.getenv("AI_ENDPOINT", "http://host.docker.internal:11434/api/chat")

def _get_gemini_model() -> str:
    if AI_MODEL and "gemini" in AI_MODEL.lower():
        if "1.5-flash" in AI_MODEL.lower() or "2.5-flash" in AI_MODEL.lower():
            return "gemini-3.6-flash"
        return AI_MODEL
    return "gemini-3.6-flash"

def _get_ollama_model() -> str:
    if AI_MODEL and "gemini" not in AI_MODEL.lower() and "gpt" not in AI_MODEL.lower():
        return AI_MODEL
    return "llama3"

async def _call_gemini(client: httpx.AsyncClient, prompt: str) -> str:
    model_name = _get_gemini_model()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={GEMINI_API_KEY}"
    response = await client.post(
        url,
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=30.0
    )
    response.raise_for_status()
    data = response.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]

async def _call_ollama(client: httpx.AsyncClient, prompt: str) -> str:
    response = await client.post(
        AI_ENDPOINT,
        json={
            "model": _get_ollama_model(),
            "messages": [{"role": "user", "content": prompt}],
            "stream": False
        },
        timeout=120.0
    )
    response.raise_for_status()
    data = response.json()
    return data["message"]["content"]

async def _call_openai(client: httpx.AsyncClient, prompt: str) -> str:
    model_name = AI_MODEL if AI_MODEL else "gpt-4o-mini"
    response = await client.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {AI_API_KEY}"},
        json={
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3
        },
        timeout=30.0
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]

async def generate_executive_summary(vuln_data: List[Dict], language: str = "French", extra_instructions: str = "", provider: str = None) -> str:
    lang_name = "Français" if language.lower() in ["french", "français", "fr"] else "English"
    active_provider = provider if provider else AI_PROVIDER
    logger.info(f"Generating AI Executive Summary - Provider: {active_provider}, Language: {lang_name}")
    
    prompt = (
        f"You are a Senior Cybersecurity Consultant at KERIBU SOC.\n"
        f"Analyze these vulnerability findings and respond strictly in {lang_name}.\n"
        f"Vulnerabilities data: {vuln_data}\n\n"
        "Respond with a valid JSON object with the following keys:\n"
        "{\n"
        '  "executive_summary": "A clear non-technical synthesis of the security posture for C-level management. Format as a string.",\n'
        '  "risk_analysis": "Real-world risk evaluation, business impact, and identification of false positive risks. Format as a string.",\n'
        '  "remediation_plan": "A single Markdown string containing prioritized strategic remediation steps using bullet points (e.g., - **Urgent**: ...). DO NOT return a nested object or array here, it MUST be a single Markdown-formatted string."\n'
        "}\n"
        "Do NOT include markdown formatting outside the JSON."
    )
    if extra_instructions:
        prompt += f"\nAdditional Client Instructions: {extra_instructions}"
    
    try:
        raw_response = ""
        async with httpx.AsyncClient() as client:
            if active_provider == "gemini":
                raw_response = await _call_gemini(client, prompt)
            elif active_provider == "openai":
                raw_response = await _call_openai(client, prompt)
            elif active_provider == "ollama":
                try:
                    raw_response = await _call_ollama(client, prompt)
                except Exception as ollama_err:
                    if GEMINI_API_KEY:
                        logger.warning(f"Ollama call failed ({ollama_err}). Falling back to Gemini...")
                        raw_response = await _call_gemini(client, prompt)
                    else:
                        raise ollama_err
            else:
                if GEMINI_API_KEY:
                    raw_response = await _call_gemini(client, prompt)
                else:
                    raw_response = await _call_ollama(client, prompt)
        
        # Try parsing JSON output
        import json
        import re
        
        clean_json = raw_response.strip()
        json_match = re.search(r'\{.*\}', clean_json, re.DOTALL)
        if json_match:
            clean_json = json_match.group()
            
        parsed = json.loads(clean_json)
        exec_sum = parsed.get("executive_summary", "")
        risk_ana = parsed.get("risk_analysis", "")
        rem_plan = parsed.get("remediation_plan", "")
        
        if isinstance(rem_plan, (dict, list)):
            # If the AI ignored instructions and returned a nested object, try to format it cleanly
            import yaml
            rem_plan = yaml.dump(rem_plan, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
        formatted = f"{exec_sum}\n\n### Analyse des Risques / Risk Analysis\n{risk_ana}\n\n### Plan de Remédiation Stratégique / Remediation Plan\n{rem_plan}"
        return formatted.strip()
        
    except Exception as e:
        logger.warning(f"Structured JSON parsing failed ({str(e)}), falling back to raw AI text output.")
        # Fallback to plain prompt call if JSON parsing fails
        fallback_prompt = (
            f"Générez un résumé exécutif et plan de remédiation en {lang_name} pour le management concernant ces vulnérabilités : {vuln_data}.\n"
            "1. Synthèse non-technique pour le management.\n"
            "2. Analyse des risques réels.\n"
            "3. Plan de remédiation priorisé."
        )
        try:
            async with httpx.AsyncClient() as client:
                if GEMINI_API_KEY:
                    return await _call_gemini(client, fallback_prompt)
                return await _call_ollama(client, fallback_prompt)
        except Exception as err:
            logger.error(f"AI generation failed: {str(err)}")
            return "Résumé exécutif généré automatiquement : Des vulnérabilités ont été détectées. Veuillez consulter la section détaillée par host pour appliquer les correctifs prioritaires."

async def generate_vulnerability_remediation(vuln_name: str, vuln_desc: str, language: str = "French", provider: str = None) -> dict:
    lang_name = "Français" if language.lower() in ["french", "français", "fr"] else "English"
    active_provider = provider if provider else AI_PROVIDER
    logger.info(f"Generating AI Contextual Analysis for '{vuln_name}' - Provider: {active_provider}, Language: {lang_name}")
    prompt = (
        f"You are a Cybersecurity Expert at KERIBU SOC. Respond in {lang_name}.\n"
        f"Vulnerability Title: {vuln_name}\n"
        f"Technical Description: {vuln_desc}\n\n"
        "Return ONLY a strictly valid JSON object, without any markdown formatting like ```json or anything else. Use the following schema:\n"
        "{\n"
        '  "severity_assessment": "Detailed reasoning behind why this vulnerability deserves its severity rating.",\n'
        '  "exploitability": "An assessment of how easily this can be exploited by an attacker.",\n'
        '  "business_impact": "Potential impact to business operations and data confidentiality.",\n'
        '  "remediation_steps": ["Step 1...", "Step 2..."]\n'
        "}"
    )
    
    try:
        raw_response = ""
        async with httpx.AsyncClient() as client:
            if active_provider == "gemini":
                raw_response = await _call_gemini(client, prompt)
            elif active_provider == "openai":
                raw_response = await _call_openai(client, prompt)
            else:
                raw_response = await _call_ollama(client, prompt)
                    
        import json
        import re
        clean_json = raw_response.strip()
        json_match = re.search(r'\{.*\}', clean_json, re.DOTALL)
        if json_match:
            clean_json = json_match.group()
        parsed = json.loads(clean_json)
        return parsed
        
    except Exception as e:
        logger.error(f"AI remediation generation failed: {str(e)}")
        return {
            "severity_assessment": "Failed to generate assessment.",
            "exploitability": "Unknown.",
            "business_impact": "Unknown.",
            "remediation_steps": ["Refer to standard remediation practices for this vulnerability."]
        }

def refine_risk_score_sync(title: str, description: str) -> float:
    """
    Calls the AI synchronously to evaluate real-world exploitability and returns a multiplier.
    Returns a float between 1.0 (Low likelihood) and 1.5 (High likelihood).
    """
    import requests
    import re
    
    prompt = (
        "En tant qu'expert en cybersécurité, évaluez la probabilité d'exploitation de cette vulnérabilité "
        "dans le monde réel (exploitabilité, disponibilité d'exploits publics, etc.). "
        f"Titre: {title}\nDescription: {description}\n\n"
        "Répondez UNIQUEMENT par un nombre entre 1.0 (très faible) et 1.5 (très élevée). Ne donnez aucune autre explication."
    )
    
    try:
        content = ""
        if AI_PROVIDER == "gemini" or (GEMINI_API_KEY and AI_PROVIDER not in ["ollama", "openai"]):
            model_name = _get_gemini_model()
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={GEMINI_API_KEY}"
            response = requests.post(
                url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=15.0
            )
            response.raise_for_status()
            content = response.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            
        elif AI_PROVIDER == "openai":
            model_name = AI_MODEL if AI_MODEL else "gpt-4o-mini"
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {AI_API_KEY}"},
                json={
                    "model": model_name,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1
                },
                timeout=15.0
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"].strip()
            
        elif AI_PROVIDER == "ollama":
            try:
                response = requests.post(
                    AI_ENDPOINT,
                    json={
                        "model": _get_ollama_model(),
                        "messages": [{"role": "user", "content": prompt}],
                        "stream": False
                    },
                    timeout=120.0
                )
                response.raise_for_status()
                content = response.json()["message"]["content"].strip()
            except Exception as ollama_err:
                if GEMINI_API_KEY:
                    logger.warning(f"Ollama call failed ({ollama_err}). Falling back to Gemini...")
                    model_name = _get_gemini_model()
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={GEMINI_API_KEY}"
                    resp = requests.post(
                        url,
                        json={"contents": [{"parts": [{"text": prompt}]}]},
                        timeout=15.0
                    )
                    resp.raise_for_status()
                    content = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                else:
                    raise ollama_err
            
        else:
            return 1.0
            
        # Parse the output to a float
        match = re.search(r"1\.[0-5]", content)
        if match:
            multiplier = float(match.group())
            return min(max(multiplier, 1.0), 1.5)
            
        return 1.0
        
    except Exception as e:
        logger.error(f"Failed to refine risk score with AI: {str(e)}")
        return 1.0

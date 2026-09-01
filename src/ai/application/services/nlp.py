import httpx
import os
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama") # "ollama" or "openai"
AI_MODEL = os.getenv("AI_MODEL", "llama3")
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_ENDPOINT = os.getenv("AI_ENDPOINT", "http://host.docker.internal:11434/api/chat")

async def generate_executive_summary(vuln_data: List[Dict], language: str = "French", extra_instructions: str = "") -> str:
    prompt = f"Générez un résumé exécutif en {language} pour le RSSI concernant ces vulnérabilités : {vuln_data}."
    if extra_instructions:
        prompt += f" Instructions supplémentaires: {extra_instructions}"
    
    try:
        async with httpx.AsyncClient() as client:
            if AI_PROVIDER == "openai":
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {AI_API_KEY}"},
                    json={
                        "model": AI_MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.3
                    },
                    timeout=30.0
                )
                data = response.json()
                return data["choices"][0]["message"]["content"]
                
            elif AI_PROVIDER == "ollama":
                response = await client.post(
                    AI_ENDPOINT,
                    json={
                        "model": AI_MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "stream": False
                    },
                    timeout=60.0
                )
                data = response.json()
                return data["message"]["content"]
                
    except Exception as e:
        logger.error(f"AI generation failed: {str(e)}")
        return "Erreur lors de la génération du résumé par l'IA. Veuillez vérifier la configuration du fournisseur ou du réseau."

def refine_risk_score_sync(title: str, description: str) -> float:
    """
    Calls the AI synchronously to evaluate real-world exploitability and returns a multiplier.
    Returns a float between 1.0 (Low likelihood) and 1.5 (High likelihood).
    """
    import requests
    
    prompt = (
        "En tant qu'expert en cybersécurité, évaluez la probabilité d'exploitation de cette vulnérabilité "
        "dans le monde réel (exploitabilité, disponibilité d'exploits publics, etc.). "
        f"Titre: {title}\nDescription: {description}\n\n"
        "Répondez UNIQUEMENT par un nombre entre 1.0 (très faible) et 1.5 (très élevée). Ne donnez aucune autre explication."
    )
    
    try:
        if AI_PROVIDER == "openai":
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {AI_API_KEY}"},
                json={
                    "model": AI_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1
                },
                timeout=15.0
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"].strip()
            
        elif AI_PROVIDER == "ollama":
            response = requests.post(
                AI_ENDPOINT,
                json={
                    "model": AI_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False
                },
                timeout=30.0
            )
            response.raise_for_status()
            content = response.json()["message"]["content"].strip()
            
        else:
            return 1.0
            
        # Parse the output to a float
        import re
        match = re.search(r"1\.[0-5]", content)
        if match:
            multiplier = float(match.group())
            return min(max(multiplier, 1.0), 1.5)
            
        return 1.0
        
    except Exception as e:
        logger.error(f"Failed to refine risk score with AI: {str(e)}")
        return 1.0

"""targets.py - one interface to any model (local Ollama OR a hosted API).

They all speak the OpenAI chat format, so swapping a local model for a hosted one
is a config change, not a code change. No GPU is needed to run small local models.
"""
import os
from openai import OpenAI


class Target:
    def __init__(self, name, model, base_url, api_key="ollama"):
        self.name = name            # label shown in reports, e.g. "llama3.2:3b"
        self.model = model          # the provider's model id
        self.client = OpenAI(base_url=base_url, api_key=api_key)

    def generate(self, system, user, temperature=0.0, max_tokens=512):
        # temperature=0 -> as deterministic as possible so re-runs are comparable.
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""


def ollama_target(model):
    """Local model served by Ollama. api_key is ignored by Ollama
    but the OpenAI client requires a non-empty string."""
    return Target(model, model, base_url="http://localhost:11434/v1", api_key="ollama")


def api_target(name, model, base_url, api_key_env):
    """A hosted model (e.g. OpenRouter/Together/Groq). Reads the key from an env var."""
    return Target(name, model, base_url=base_url, api_key=os.environ.get(api_key_env, ""))

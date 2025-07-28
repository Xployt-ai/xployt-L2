"""test_llm.py
A lightweight script to verify that the OpenAI client can successfully reach the
API and return a response.  Run this once after configuring your `OPENAI_API_KEY`
(e.g. placing it in a `.env` file) to confirm connectivity.

Usage (from repo root):
    python test_llm.py
"""

from __future__ import annotations

import os
from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()  # pick up OPENAI_API_KEY from .env if present


def check_llm(model: str = "gpt-3.5-turbo") -> None:
    """Make a minimal chat completion call and print the raw response.

    Parameters
    ----------
    model: str
        The model name to ping. Defaults to the lower-cost `gpt-3.5-turbo`.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌  OPENAI_API_KEY not found – set it in your environment or .env file.")
        return

    client = OpenAI(api_key=api_key)
    print(f"🔑  API key loaded. Pinging model `{model}` …")

    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Respond with the word Pong"}],
            max_tokens=2,
            temperature=0.0,
        )
        answer = resp.choices[0].message.content.strip()
        print("✅  LLM responded successfully →", answer)
    except Exception as exc:
        print("❌  LLM call failed:")
        print(exc)


if __name__ == "__main__":
    check_llm()

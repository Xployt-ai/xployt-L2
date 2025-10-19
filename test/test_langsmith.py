"""Test script to verify LangSmith integration using @traceable decorator."""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from xployt_lvl2.utils.langsmith_wrapper import get_traced_openai_client, trace_llm_call

print("Testing LangSmith integration with @traceable decorator...\n")


@trace_llm_call(name="format-prompt")
def format_prompt(subject: str) -> list:
    """Format the prompt for the LLM."""
    print("  → Formatting prompt...")
    return [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": f"Say '{subject}'"}
    ]


@trace_llm_call(name="invoke-llm", run_type="llm")
def invoke_llm(messages: list) -> str:
    """Call the OpenAI API."""
    print("  → Calling OpenAI API...")
    client = get_traced_openai_client()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=20
    )
    return response.choices[0].message.content


@trace_llm_call(name="parse-output")
def parse_output(response: str) -> str:
    """Parse and format the output."""
    print("  → Parsing output...")
    return f"LLM Response: {response}"


@trace_llm_call(name="run-pipeline", run_type="chain")
def run_pipeline(subject: str) -> str:
    """Run the complete pipeline."""
    print("\nExecuting pipeline...")
    messages = format_prompt(subject)
    response = invoke_llm(messages)
    return parse_output(response)


if __name__ == "__main__":
    result = run_pipeline("What is the opposite of man?")
    print(f"\n{result}")
    print("\n" + "="*60)
    print("✓ Check your LangSmith dashboard at: https://smith.langchain.com/")
    print("  Project: xployt-lvl2")
    print("\n  You should see a trace chain:")
    print("    run-pipeline (chain)")
    print("      ├─ format-prompt")
    print("      ├─ invoke-llm (llm) ← Shows actual OpenAI API call")
    print("      └─ parse-output")
    print("="*60)
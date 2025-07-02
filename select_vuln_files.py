import os
import json
from dotenv import load_dotenv
from openai import OpenAI

def load_file_structure(file_path="file_structure.json"):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def ask_openai_for_vuln_analysis(file_structure):
    prompt = f"""
You are a senior security auditor working on the Xploit.ai project, which focuses on scanning MERN-stack applications for vulnerabilities.

Given the following file and folder structure (with absolute paths), identify:

1. **folders_to_analyze**: List of absolute paths to folders likely containing security-relevant code (e.g., controllers, routes, services).
2. **standalone_files**: List of absolute paths to standalone files that might contain sensitive logic (e.g., shell scripts, environment loaders).

**Important**: Return your response strictly as a JSON object with the keys "folders_to_analyze" and "standalone_files".

Here is the structure:
{json.dumps(file_structure, indent=2)}
"""

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a senior security auditor."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3
    )

    return response.choices[0].message.content

if __name__ == "__main__":
    load_dotenv()
    file_tree = load_file_structure()
    print("✅ Loaded file structure. Sending to OpenAI...\n")

    result = ask_openai_for_vuln_analysis(file_tree)

    with open("vuln_files_selection.json", "w", encoding="utf-8") as f:
        f.write(result)

    print("✅ Saved OpenAI response to 'vuln_files_selection.json'")
    print(result)

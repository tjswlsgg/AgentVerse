# [GHSA Report] Remote Code Execution (RCE) via Command Injection in CodeTestExecutor

## Description

A Remote Code Execution (RCE) vulnerability exists in AgentVerse's `CodeTestExecutor` due to the insecure use of `subprocess.run(shell=True)`. An attacker can achieve arbitrary code execution on the host system by providing a crafted task description that influences the LLM agent's output, injecting shell metacharacters into the `file_path` field.

### Root Cause
In `agentverse/environments/tasksolving_env/rules/executor/code_test.py`, the `execute_command` function executes system commands using `subprocess.run(command, shell=True)`. The `command` string is constructed by directly interpolating the `file_path` variable extracted from the LLM agent's output without any validation or sanitization. 

If an attacker inputs a malicious task description, they can manipulate the LLM agent into generating a `file_path` containing shell delimiters (e.g., `;`, `&&`, `|`), leading to command injection.

---

## Affected Versions

| Product | Affected Versions | Fixed Version |
| ------- | ----------------- | ------------- |
| AgentVerse | <= 0.1.8.1 | Not yet patched |

---

## Severity

* **CVSS v3.1 Score:** 8.8 (Critical)
* **Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command / OS Command Injection)

---

## Proof of Concept (PoC)

The following pseudocode outlines how the command injection is triggered via unvalidated agent responses:

```python
import subprocess

# 1. Simulated malicious agent output influenced by a crafted task description
response = {
    "file_path": "test.py; touch /tmp/pwned", 
    "code": "print('hello')"
}

# 2. Vulnerable command construction in code_test.py
command = f"python {response['file_path']}"

# 3. Vulnerable execution executing: python test.py; touch /tmp/pwned
subprocess.run(command, shell=True)

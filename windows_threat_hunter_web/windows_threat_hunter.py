# windows_threat_hunter.py 
import sys
import base64

# -------------------------
# Help Section
# -------------------------
def print_help():
    print("""
=== Windows_Threat_Hunter Help ===

Usage:
1. Modes:
   - lookup : Look up a Windows process name to see its expected parent processes, execution paths, risk score, and MITRE techniques.
   - dll    : Look up a DLL to see common paths and notes about its usage.
   - chain  : Analyze a process chain.

2. Input:
   - Paste multiple lines if needed (Ctrl+Shift+V in Linux terminals).
   - Press Enter twice (blank line) to submit pasted content.
   - Type 'back' to cancel.

3. Chain format (if pasting single-line):
   Process|Parent|Path|Command|DLL

4. Exit:
   - Type 'exit' in mode selection to quit the tool.
""")

# -------------------------
ALIASES = {
    "powershell": "powershell.exe",
    "ps": "powershell.exe",
    "pwsh": "pwsh.exe"
}

# -------------------------
PROCESS_DB = {
    "cmd.exe": {"parents": ["explorer.exe", "winlogon.exe"], "paths": ["C:/Windows/System32/cmd.exe"], "risk_score": 10, "mitre": ["T1059"]},
    "conhost.exe": {"parents": ["services.exe", "svchost.exe"], "paths": ["C:/Windows/System32/conhost.exe"], "risk_score": 5, "mitre": ["T1059"]},
    "explorer.exe": {"parents": ["wininit.exe", "userinit.exe"], "paths": ["C:/Windows/explorer.exe"], "risk_score": 5, "mitre": ["T1059"]},
    "winword.exe": {"parents": ["explorer.exe"], "paths": ["C:/Program Files/Microsoft Office/root/Office16/WINWORD.EXE"], "risk_score": 15, "mitre": ["T1204"]},
    "notepad.exe": {"parents": ["explorer.exe"], "paths": ["C:/Windows/System32/notepad.exe"], "risk_score": 5, "mitre": []},
    "powershell.exe": {"parents": ["explorer.exe", "cmd.exe"], "paths": ["C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"], "risk_score": 85, "mitre": ["T1059"]},
    "pwsh.exe": {"parents": ["explorer.exe", "cmd.exe"], "paths": ["C:/Program Files/PowerShell/7/pwsh.exe"], "risk_score": 85, "mitre": ["T1059"]},
    "rundll32.exe": {"parents": ["explorer.exe", "cmd.exe"], "paths": ["C:/Windows/System32/rundll32.exe"], "risk_score": 95, "mitre": ["T1218"]},
    "regsvr32.exe": {"parents": ["explorer.exe", "cmd.exe"], "paths": ["C:/Windows/System32/regsvr32.exe"], "risk_score": 95, "mitre": ["T1218"]},
    "svchost.exe": {"parents": ["services.exe"], "paths": ["C:/Windows/System32/svchost.exe"], "risk_score": 90, "mitre": ["T1055", "T1036"]}
}

# -------------------------
DLL_DB = {
    "ntdll.dll": {"paths": ["C:/Windows/System32/ntdll.dll"], "notes": ["Critical system DLL", "Suspicious if outside System32"]},
    "kernel32.dll": {"paths": ["C:/Windows/System32/kernel32.dll"], "notes": ["Core system DLL", "Used by almost all processes"]},
    "user32.dll": {"paths": ["C:/Windows/System32/user32.dll"], "notes": ["GUI DLL", "Suspicious in non-GUI processes"]},
    "advapi32.dll": {"paths": ["C:/Windows/System32/advapi32.dll"], "notes": ["Security APIs", "Common in privilege abuse"]},
    "shell32.dll": {"paths": ["C:/Windows/System32/shell32.dll"], "notes": ["Explorer-related", "Used in rundll32 attacks"]},
    "scrobj.dll": {"paths": ["C:/Windows/System32/scrobj.dll"], "notes": ["Fileless attack DLL (regsvr32)"]},
    "url.dll": {"paths": ["C:/Windows/System32/url.dll"], "notes": ["Used in LOLBin attacks"]},
    "msvcrt.dll": {"paths": ["C:/Windows/System32/msvcrt.dll"], "notes": ["Standard C runtime"]}
}

# -------------------------
def lookup_process(name):
    name = ALIASES.get(name.lower(), name.lower())
    results = {k: v for k, v in PROCESS_DB.items() if name in k}
    if not results:
        print("No process intel found.")
        return
    for pname, data in results.items():
        print(f"\n[PROCESS] {pname}")
        print(f"  Expected Parents : {', '.join(data['parents'])}")
        print(f"  Expected Paths   : {', '.join(data['paths'])}")
        print(f"  Risk Score       : {data['risk_score']}")
        print(f"  MITRE            : {', '.join(data['mitre'])}")

def lookup_dll(name):
    name = name.lower()
    data = DLL_DB.get(name)
    if not data:
        print(f"No DLL intel found. Investigate path, signature, and loader.")
        return
    print(f"\n[DLL] {name}")
    print(f"  Common Paths: {', '.join(data['paths'])}")
    print(f"  Notes       : {', '.join(data['notes'])}")

# -------------------------
def analyze_powershell(cmd):
    print("\n[PowerShell Analysis]")
    patterns = ["-enc", "iex", "downloadstring", "bypass", "hidden"]
    for p in patterns:
        if p in cmd.lower():
            print(f"[!] Detected pattern: {p}")
    if "-enc" in cmd.lower():
        try:
            encoded = cmd.split()[-1]
            decoded = base64.b64decode(encoded).decode("utf-16le")
            print("\n[DECODED PAYLOAD]")
            print(decoded)
        except:
            print("[!] Failed to decode Base64")

# -------------------------
def analyze_chain(proc, parent=None, path=None, cmd=None, dll=None):
    score = 0
    findings = []
    proc = ALIASES.get(proc.lower(), proc.lower())
    entry = PROCESS_DB.get(proc)

    if not entry:
        findings.append("Unknown process — investigate manually.")
        score += 20
    else:
        if parent and parent.lower() not in [p.lower() for p in entry["parents"]]:
            findings.append(f"Suspicious parent: {parent}")
            score += 30
        if path and not any(path.lower().startswith(p.lower()) for p in entry["paths"]):
            findings.append(f"Suspicious execution path: {path}")
            score += 40

    if dll:
        dll_info = DLL_DB.get(dll.lower())
        if not dll_info:
            findings.append(f"Unknown DLL: {dll}")
            score += 25

    if cmd:
        patterns = ["-enc", "iex", "downloadstring", "bypass", "hidden"]
        for p in patterns:
            if p in cmd.lower():
                findings.append(f"Suspicious command pattern: {p}")
                score += 30

    if score >= 80:
        verdict = "HIGHLY SUSPICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY CLEAN"

    print("\n=== Attack Chain Analysis ===")
    for f in findings:
        print(f"[!] {f}")
    print(f"\nRisk Score: {score}")
    print(f"Verdict: {verdict}")

# -------------------------
def main():
    print_help()
    print("=== Windows_Threat_Hunter ===")
    while True:
        mode = input("\nMode (lookup/chain/dll/exit): ").strip().lower()
        if mode == "exit":
            print("\nHappy Hunting! 🦅")
            break
        if mode not in ["lookup", "chain", "dll"]:
            print("Invalid mode.")
            continue

        # -------------------------
        # READ MULTI-LINE INPUT FOR ALL MODES
        # -------------------------
        print("Paste your input. Press Enter twice (blank line) to finish, or type 'back' to cancel:")
        lines = []
        while True:
            line = sys.stdin.readline()
            if not line or line.strip() == "":
                break
            lines.append(line.strip())
        input_text = " ".join(lines).replace("\n","").replace("\r","").strip()
        if input_text.lower() == "back" or input_text == "":
            continue

        # -------------------------
        # MODE HANDLING
        # -------------------------
        if mode == "lookup":
            lookup_process(input_text)
        elif mode == "dll":
            lookup_dll(input_text)
        elif mode == "chain":
            if "|" in input_text:
                parts = [p.strip() for p in input_text.split("|")]
                proc = parts[0] if len(parts) > 0 else None
                parent = parts[1] if len(parts) > 1 else None
                path = parts[2] if len(parts) > 2 else None
                cmd  = parts[3] if len(parts) > 3 else None
                dll  = parts[4] if len(parts) > 4 else None
            else:
                proc = input_text
                parent = input("Parent (optional): ").strip()
                path = input("Path (optional): ").strip()
                cmd  = input("Command (optional): ").strip()
                dll  = input("DLL (optional): ").strip()

            analyze_chain(proc, parent or None, path or None, cmd or None, dll or None)
            if "powershell" in proc.lower() or "pwsh" in proc.lower():
                if cmd:
                    analyze_powershell(cmd)

if __name__ == "__main__":
    main()
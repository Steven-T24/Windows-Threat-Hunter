from flask import Flask, render_template, request
from windows_threat_hunter import lookup_process, lookup_dll, analyze_chain, analyze_powershell

import io
import sys

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        mode = request.form.get("mode")
        user_input = request.form.get("user_input")

        # Capture the output of print statements
        buffer = io.StringIO()
        sys.stdout = buffer

        if mode == "lookup":
            lookup_process(user_input)
        elif mode == "dll":
            lookup_dll(user_input)
        elif mode == "chain":
            if "|" in user_input:
                parts = [p.strip() for p in user_input.split("|")]
                proc = parts[0] if len(parts) > 0 else None
                parent = parts[1] if len(parts) > 1 else None
                path = parts[2] if len(parts) > 2 else None
                cmd  = parts[3] if len(parts) > 3 else None
                dll  = parts[4] if len(parts) > 4 else None
            else:
                proc = user_input
                parent = None
                path = None
                cmd = None
                dll = None

            analyze_chain(proc, parent, path, cmd, dll)
            if proc and ("powershell" in proc.lower() or "pwsh" in proc.lower()):
                if cmd:
                    analyze_powershell(cmd)

        sys.stdout = sys.__stdout__
        result = buffer.getvalue()

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

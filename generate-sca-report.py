import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

matches = data.get("matches", [])

def badge(s):
    colors = {"Critical": "#d73a49", "High": "#e36209", "Medium": "#f9c513", "Low": "#0075ca", "Negligible": "#6a737d"}
    color = colors.get(s, "#6a737d")
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{s}</span>'

rows = "".join(
    f"<tr><td>{m['artifact']['name']}</td><td>{m['artifact']['version']}</td><td>{badge(m['vulnerability']['severity'])}</td><td>{m['vulnerability']['id']}</td><td>{m['vulnerability'].get('description','')[:120]}</td></tr>"
    for m in matches
)

html = f"""<html><head><title>SCA Report</title>
<style>body{{font-family:sans-serif;padding:20px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:8px;text-align:left}}th{{background:#f4f4f4}}tr:nth-child(even){{background:#fafafa}}</style></head>
<body><h2>Software Composition Analysis Report</h2><p>Total vulnerabilities: {len(matches)}</p>
<table><tr><th>Package</th><th>Version</th><th>Severity</th><th>CVE</th><th>Description</th></tr>{rows}</table></body></html>"""

with open("sca-report.html", "w") as f:
    f.write(html)

print(f"SCA report generated: {len(matches)} vulnerabilities found")

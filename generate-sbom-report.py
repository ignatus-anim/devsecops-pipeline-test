import json, sys

with open(sys.argv[1]) as f:
    sbom = json.load(f)

components = sbom.get("components", [])
rows = "".join(
    f"<tr><td>{c.get('name','')}</td><td>{c.get('version','')}</td><td>{c.get('type','')}</td><td>{', '.join(l.get('license',{}).get('id','?') for l in c.get('licenses',[]))}</td></tr>"
    for c in components
)

html = f"""<html><head><title>SBOM Report</title>
<style>body{{font-family:sans-serif;padding:20px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:8px;text-align:left}}th{{background:#f4f4f4}}tr:nth-child(even){{background:#fafafa}}</style></head>
<body><h2>SBOM Report</h2><p>Total components: {len(components)}</p>
<table><tr><th>Name</th><th>Version</th><th>Type</th><th>License</th></tr>{rows}</table></body></html>"""

with open("sbom-report.html", "w") as f:
    f.write(html)

print(f"SBOM report generated: {len(components)} components")

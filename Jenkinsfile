// ============================================================
// Test Jenkinsfile — Pre-Commit + Build Stages
// For local Jenkins testing of DevSecOps pipeline templates
// ============================================================

pipeline {
    agent any

    environment {
        IMAGE_NAME         = 'test-devsecops-app'
        IMAGE_TAG          = 'latest'
        IMAGE_REF          = "${IMAGE_NAME}:${IMAGE_TAG}"

        SBOM_SOURCE_REPORT    = 'sbom-source.cyclonedx.json'
        SBOM_CONTAINER_REPORT = 'sbom-container.cyclonedx.json'
        GRYPE_SCA_REPORT   = 'grype-sca-report.json'
        GRYPE_IMG_REPORT   = 'grype-image-report.json'
        CHECKOV_REPORT     = 'checkov-report.json'
        GITLEAKS_REPORT    = 'gitleaks-report.json'

        SEVERITY_THRESHOLD = 'critical'
        APPROVED_LICENSES  = 'MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,CC0-1.0,Unlicense,LGPL-2.1'
        GRYPE_DB_AUTO_UPDATE        = 'false'
        GRYPE_DB_MAX_ALLOWED_BUILT_AGE = '2160h'  // 90 days — use cached DB as-is

        // ── Dependency-Track ──────────────────────────────────
        // 172.17.0.1 = docker0 bridge gateway — reaches the host from
        // the Jenkins container on vanilla Docker (no Docker Desktop).
        DTRACK_URL     = 'http://172.17.0.1:8081'
        DTRACK_API_KEY = credentials('dtrack-api-key')
    }

    stages {

        // ── PRE-COMMIT ────────────────────────────────────────
        stage('Prepare') {
            steps {
                script {
                    env.IMAGE_TAG = env.GIT_COMMIT ? env.GIT_COMMIT.take(7) : 'latest'
                    env.IMAGE_REF = "${env.IMAGE_NAME}:${env.IMAGE_TAG}"
                }
            }
        }

        stage('Secret Detection') {
            steps {
                script {
                    def exitCode = sh(
                        script: "gitleaks detect --source . --no-git --config .gitleaks.toml --report-format json --report-path ${GITLEAKS_REPORT} --exit-code 1",
                        returnStatus: true
                    )
                    archiveArtifacts artifacts: "${GITLEAKS_REPORT}", allowEmptyArchive: true
                    if (exitCode != 0) {
                        error("Secret Detection FAILED — secrets detected. Review ${GITLEAKS_REPORT}.")
                    }
                }
            }
        }

        // ── BUILD ─────────────────────────────────────────────
        stage('SBOM Generation') {
            steps {
                sh """
                    syft dir:. \\
                        --exclude './.venv/**' \\
                        --exclude './**/__pycache__/**' \\
                        --exclude './.git/**' \\
                        --exclude './node_modules/**' \\
                        --source-name ${IMAGE_NAME} \\
                        --source-version ${IMAGE_TAG} \\
                        -o cyclonedx-json=${SBOM_SOURCE_REPORT}
                """
                writeFile file: 'generate-sbom-report.py', text: '''
import json
with open("sbom-source.cyclonedx.json") as f:
    sbom = json.load(f)

# Filter out syft file-type components (raw manifest files like
# requirements.txt). We only want real libraries/applications.
all_components = sbom.get("components", [])
components = [c for c in all_components if c.get("type") != "file"]

rows = "".join(
    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
        c.get("name",""), c.get("version",""), c.get("type",""),
        ", ".join(l.get("license",{}).get("id","?") for l in c.get("licenses",[]))
    ) for c in components
)
html = (
    "<html><head><title>SBOM Report</title>"
    "<style>body{font-family:sans-serif;padding:20px}table{border-collapse:collapse;width:100%}"
    "th,td{border:1px solid #ccc;padding:8px}th{background:#f4f4f4}tr:nth-child(even){background:#fafafa}"
    ".note{background:#f0f7ff;border-left:4px solid #0075ca;padding:10px 14px;margin:10px 0;font-size:13px}</style></head>"
    "<body><h2>SBOM Report</h2>"
    "<div class=\\"note\\">This is a component inventory only. For vulnerabilities and severity, see the <strong>SCA Report</strong> and <strong>Container Image Scan Report</strong> in the sidebar.</div>"
    "<p>Total components: " + str(len(components)) + "</p>"
    "<table><tr><th>Name</th><th>Version</th><th>Type</th><th>License</th></tr>" + rows + "</table></body></html>"
)
open("sbom-report.html", "w").write(html)
print("SBOM report generated:", len(components), "components (filtered", len(all_components) - len(components), "file-type entries)")
'''
                sh "python3 generate-sbom-report.py"
                archiveArtifacts artifacts: "${SBOM_SOURCE_REPORT}"
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'sbom-report.html',
                    reportName: 'SBOM Report'
                ])
            }
        }

        stage('Publish SBOM to Dependency-Track') {
            steps {
                script {
                    def httpCode = sh(
                        script: """
                            curl -sS -o dtrack-response.json -w "%{http_code}" \\
                                -X POST ${DTRACK_URL}/api/v1/bom \\
                                -H "X-Api-Key: ${DTRACK_API_KEY}" \\
                                -F "projectName=${IMAGE_NAME}-source" \\
                                -F "projectVersion=${IMAGE_TAG}" \\
                                -F "parentName=${IMAGE_NAME}" \\
                                -F "parentVersion=latest" \\
                                -F "classifier=LIBRARY" \\
                                -F "autoCreate=true" \\
                                -F "bom=@${SBOM_SOURCE_REPORT}" || echo "000"
                        """,
                        returnStdout: true
                    ).trim()

                    archiveArtifacts artifacts: 'dtrack-response.json', allowEmptyArchive: true

                    if (httpCode.startsWith('2')) {
                        echo "Source SBOM uploaded to Dependency-Track: ${IMAGE_NAME}-source@${IMAGE_TAG} (parent=${IMAGE_NAME}, HTTP ${httpCode})"
                    } else {
                        unstable("Dependency-Track upload returned HTTP ${httpCode}. SBOM is still archived in Jenkins — review dtrack-response.json.")
                    }
                }
            }
        }

        stage('Software Composition Analysis') {
            steps {
                script {
                    def exitCode = sh(
                        script: """
                            grype sbom:${SBOM_SOURCE_REPORT} \\
                                --fail-on ${SEVERITY_THRESHOLD} \\
                                --output json \\
                                --file ${GRYPE_SCA_REPORT}
                        """,
                        returnStatus: true
                    )
                    archiveArtifacts artifacts: "${GRYPE_SCA_REPORT}", allowEmptyArchive: true
                    writeFile file: 'generate-sca-report.py', text: '''
import json

with open("grype-sca-report.json") as f:
    data = json.load(f)

matches = data.get("matches", [])

severity_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
severity_colors = {
    "Critical":  "#d73a49",
    "High":      "#e36209",
    "Medium":    "#f9c513",
    "Low":       "#0075ca",
    "Negligible":"#6a737d",
    "Unknown":   "#959da5"
}

# count by severity
counts = {s: 0 for s in severity_order}
for m in matches:
    s = m["vulnerability"]["severity"]
    if s not in counts:
        s = "Unknown"
    counts[s] += 1

# sort matches: Critical first
matches.sort(key=lambda m: severity_order.index(m["vulnerability"]["severity"]) if m["vulnerability"]["severity"] in severity_order else 99)

def badge(s):
    color = severity_colors.get(s, "#6a737d")
    return '<span style="background:{};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{}</span>'.format(color, s)

def exploited_tag(m):
    if m["vulnerability"].get("knownExploited"):
        return ' <span style="background:#b31d28;color:white;padding:1px 6px;border-radius:3px;font-size:11px">KNOWN EXPLOITED</span>'
    return ""

def fix_version(m):
    fix = m["vulnerability"].get("fix", {})
    versions = fix.get("versions", [])
    if versions:
        return ", ".join(versions)
    for md in m.get("matchDetails", []):
        sv = md.get("fix", {}).get("suggestedVersion", "")
        if sv:
            return sv
    state = fix.get("state", "unknown")
    if state == "wont-fix":
        return '<span style="color:#d73a49">No fix available</span>'
    return '<span style="color:#888">{}</span>'.format(state)

# summary cards
cards = "".join(
    '<div style="display:inline-block;margin:6px;padding:14px 28px;border-radius:8px;background:{};color:white;text-align:center">'
    '<div style="font-size:32px;font-weight:bold">{}</div>'
    '<div style="font-size:13px">{}</div></div>'.format(severity_colors[s], counts[s], s)
    for s in severity_order
)

rows = "".join(
    "<tr>"
    "<td>{}{}</td>"
    "<td>{}</td>"
    "<td>{}</td>"
    "<td><a href=\\"https://nvd.nist.gov/vuln/detail/{}\\" target=\\"_blank\\">{}</a></td>"
    "<td style=\\"font-size:12px\\">{}</td>"
    "<td style=\\"color:green;font-weight:bold\\">{}</td>"
    "</tr>".format(
        m["artifact"]["name"],
        exploited_tag(m),
        m["artifact"]["version"],
        badge(m["vulnerability"]["severity"]),
        m["vulnerability"]["id"],
        m["vulnerability"]["id"],
        m["vulnerability"].get("description", "")[:150],
        fix_version(m)
    )
    for m in matches
)

html = (
    "<html><head><title>SCA Report</title>"
    "<style>"
    "body{font-family:sans-serif;padding:20px;background:#fff}"
    "h2{color:#333}"
    "table{border-collapse:collapse;width:100%;margin-top:20px}"
    "th,td{border:1px solid #ddd;padding:10px;vertical-align:top}"
    "th{background:#f4f4f4;font-weight:600}"
    "tr:nth-child(even){background:#fafafa}"
    "a{color:#0075ca}"
    "</style></head>"
    "<body>"
    "<h2>Software Composition Analysis Report</h2>"
    "<p>Total vulnerabilities: <strong>" + str(len(matches)) + "</strong></p>"
    "<div style='margin:16px 0'>" + cards + "</div>"
    "<table>"
    "<tr><th>Package</th><th>Current Version</th><th>Severity</th><th>CVE</th><th>Description</th><th>Fix Version</th></tr>"
    + rows +
    "</table></body></html>"
)

open("sca-report.html", "w").write(html)
print("SCA report generated:", len(matches), "vulnerabilities")
'''
                    sh "python3 generate-sca-report.py"
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'sca-report.html',
                        reportName: 'SCA Report'
                    ])
                    if (exitCode != 0) {
                        unstable("SCA WARNING — vulnerabilities detected. Review ${GRYPE_SCA_REPORT}.")
                    }
                }
            }
        }

        stage('License Compliance') {
            steps {
                script {
                    writeFile file: 'license-check.py', text: """
import json, sys
approved = set("${APPROVED_LICENSES}".split(","))
with open("${SBOM_SOURCE_REPORT}") as f:
    sbom = json.load(f)
violations = []
for component in sbom.get("components", []):
    for lic in component.get("licenses", []):
        spdx_id = lic.get("license", {}).get("id", "UNKNOWN")
        if spdx_id not in approved:
            violations.append("{}@{} -- {}".format(component.get("name","unknown"), component.get("version","?"), spdx_id))
if violations:
    print("LICENSE VIOLATIONS FOUND:")
    for v in violations:
        print("  -", v)
    sys.exit(1)
else:
    print("All licenses compliant.")
"""
                    def exitCode = sh(script: "python3 license-check.py", returnStatus: true)
                    if (exitCode != 0) {
                        error("License Compliance FAILED — unapproved licenses detected.")
                    }
                }
            }
        }

        stage('Build Container Image') {
            steps {
                sh "docker build -t ${IMAGE_REF} ."
            }
        }

        stage('Generate Container SBOM') {
            steps {
                sh """
                    syft docker:${IMAGE_REF} \\
                        --scope all-layers \\
                        --source-name ${IMAGE_NAME}-container \\
                        --source-version ${IMAGE_TAG} \\
                        -o cyclonedx-json=${SBOM_CONTAINER_REPORT}

                    echo '=== Container SBOM — component breakdown by type ==='
                    jq -r '.components | group_by(.type) | map({type: .[0].type, count: length}) | .[]' ${SBOM_CONTAINER_REPORT} || true

                    echo '=== Container SBOM — component breakdown by ecosystem (purl prefix) ==='
                    jq -r '[.components[].purl // empty | split("/")[0]] | group_by(.) | map({purl_type: .[0], count: length}) | .[]' ${SBOM_CONTAINER_REPORT} || true

                    echo '=== Total components:'
                    jq '.components | length' ${SBOM_CONTAINER_REPORT}
                """
                archiveArtifacts artifacts: "${SBOM_CONTAINER_REPORT}"
            }
        }

        stage('Publish Container SBOM to Dependency-Track') {
            steps {
                script {
                    def httpCode = sh(
                        script: """
                            curl -sS -o dtrack-container-response.json -w "%{http_code}" \\
                                -X POST ${DTRACK_URL}/api/v1/bom \\
                                -H "X-Api-Key: ${DTRACK_API_KEY}" \\
                                -F "projectName=${IMAGE_NAME}-container" \\
                                -F "projectVersion=${IMAGE_TAG}" \\
                                -F "parentName=${IMAGE_NAME}" \\
                                -F "parentVersion=latest" \\
                                -F "classifier=CONTAINER" \\
                                -F "autoCreate=true" \\
                                -F "bom=@${SBOM_CONTAINER_REPORT}" || echo "000"
                        """,
                        returnStdout: true
                    ).trim()

                    archiveArtifacts artifacts: 'dtrack-container-response.json', allowEmptyArchive: true

                    if (httpCode.startsWith('2')) {
                        echo "Container SBOM uploaded to Dependency-Track: ${IMAGE_NAME}-container@${IMAGE_TAG} (parent=${IMAGE_NAME}, HTTP ${httpCode})"
                    } else {
                        unstable("Container SBOM upload to Dependency-Track returned HTTP ${httpCode}. SBOM is still archived in Jenkins — review dtrack-container-response.json.")
                    }
                }
            }
        }

        stage('Container Image Scanning') {
            steps {
                script {
                    sh """
                        grype ${IMAGE_REF} \\
                            --output json \\
                            --file ${GRYPE_IMG_REPORT}
                    """
                    archiveArtifacts artifacts: "${GRYPE_IMG_REPORT}", allowEmptyArchive: true
                    writeFile file: 'generate-image-report.py', text: '''
import json

with open("grype-image-report.json") as f:
    data = json.load(f)

matches = data.get("matches", [])

severity_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
severity_colors = {
    "Critical":  "#d73a49",
    "High":      "#e36209",
    "Medium":    "#f9c513",
    "Low":       "#0075ca",
    "Negligible":"#6a737d",
    "Unknown":   "#959da5"
}

counts = {s: 0 for s in severity_order}
for m in matches:
    s = m["vulnerability"]["severity"]
    if s not in counts:
        s = "Unknown"
    counts[s] += 1

matches.sort(key=lambda m: severity_order.index(m["vulnerability"]["severity"]) if m["vulnerability"]["severity"] in severity_order else 99)

def badge(s):
    color = severity_colors.get(s, "#6a737d")
    return \'<span style="background:{};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{}</span>\'.format(color, s)

def exploited_tag(m):
    if m["vulnerability"].get("knownExploited"):
        return \' <span style="background:#b31d28;color:white;padding:1px 6px;border-radius:3px;font-size:11px">KNOWN EXPLOITED</span>\'
    return ""

def fix_version(m):
    fix = m["vulnerability"].get("fix", {})
    versions = fix.get("versions", [])
    if versions:
        return ", ".join(versions)
    for md in m.get("matchDetails", []):
        sv = md.get("fix", {}).get("suggestedVersion", "")
        if sv:
            return sv
    state = fix.get("state", "unknown")
    if state == "wont-fix":
        return \'<span style="color:#d73a49">No fix available</span>\'
    return \'<span style="color:#888">{}</span>\'.format(state)

cards = "".join(
    \'<div style="display:inline-block;margin:6px;padding:14px 28px;border-radius:8px;background:{};color:white;text-align:center">\'
    \'<div style="font-size:32px;font-weight:bold">{}</div>\'
    \'<div style="font-size:13px">{}</div></div>\'.format(severity_colors[s], counts[s], s)
    for s in severity_order
)

rows = "".join(
    "<tr>"
    "<td>{}{}</td>"
    "<td>{}</td>"
    "<td>{}</td>"
    "<td>{}</td>"
    "<td><a href=\\"https://nvd.nist.gov/vuln/detail/{}\\" target=\\"_blank\\">{}</a></td>"
    "<td style=\\"font-size:12px\\">{}</td>"
    "<td style=\\"color:green;font-weight:bold\\">{}</td>"
    "</tr>".format(
        m["artifact"]["name"],
        exploited_tag(m),
        m["artifact"]["version"],
        m["artifact"].get("type", ""),
        badge(m["vulnerability"]["severity"]),
        m["vulnerability"]["id"],
        m["vulnerability"]["id"],
        m["vulnerability"].get("description", "")[:150],
        fix_version(m)
    )
    for m in matches
)

html = (
    "<html><head><title>Container Image Scan Report</title>"
    "<style>"
    "body{font-family:sans-serif;padding:20px;background:#fff}"
    "h2{color:#333}"
    "table{border-collapse:collapse;width:100%;margin-top:20px}"
    "th,td{border:1px solid #ddd;padding:10px;vertical-align:top}"
    "th{background:#f4f4f4;font-weight:600}"
    "tr:nth-child(even){background:#fafafa}"
    "a{color:#0075ca}"
    "</style></head>"
    "<body>"
    "<h2>Container Image Scan Report</h2>"
    "<p>Total vulnerabilities: <strong>" + str(len(matches)) + "</strong></p>"
    "<div style=\'margin:16px 0\'>" + cards + "</div>"
    "<table>"
    "<tr><th>Package</th><th>Current Version</th><th>Type</th><th>Severity</th><th>CVE</th><th>Description</th><th>Fix Version</th></tr>"
    + rows +
    "</table></body></html>"
)

open("image-scan-report.html", "w").write(html)
print("Image scan report generated:", len(matches), "vulnerabilities")
'''
                    sh "python3 generate-image-report.py"
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'image-scan-report.html',
                        reportName: 'Container Image Scan Report'
                    ])
                    def criticalCount = sh(
                        script: "jq '[.matches[] | select(.vulnerability.severity == \"Critical\")] | length' ${GRYPE_IMG_REPORT}",
                        returnStdout: true
                    ).trim().toInteger()
                    if (criticalCount > 0) {
                        error("Container Image Scan FAILED — ${criticalCount} Critical vulnerability(ies) detected. Review ${GRYPE_IMG_REPORT}.")
                    }
                }
            }
        }

        stage('IaC Security Scanning') {
            steps {
                script {
                    sh "mkdir -p checkov-results"
                    def exitCode = sh(
                        script: """
                            /home/linuxbrew/.linuxbrew/bin/checkov -d . \\
                                --framework terraform,cloudformation,kubernetes \\
                                --output json \\
                                --output junitxml \\
                                --output-file-path checkov-results \\
                                --soft-fail-on LOW,MEDIUM \\
                                --hard-fail-on HIGH,CRITICAL
                        """,
                        returnStatus: true
                    )
                    sh "find checkov-results -name '*.json' -exec cp {} ${CHECKOV_REPORT} \\; 2>/dev/null || true"
                    archiveArtifacts artifacts: "${CHECKOV_REPORT}", allowEmptyArchive: true
                    junit allowEmptyResults: true, testResults: 'checkov-results/results_junitxml.xml'
                    if (exitCode != 0) {
                        error("IaC Scanning FAILED — HIGH or CRITICAL misconfigurations detected. See Test Results for per-check details.")
                    }
                }
            }
        }

    }

    post {
        failure {
            echo "Pipeline FAILED. Review archived reports for details."
        }
        success {
            echo "All stages passed."
        }
        always {
            node('') {
                archiveArtifacts artifacts: "*.json", allowEmptyArchive: true
            }
        }
    }
}

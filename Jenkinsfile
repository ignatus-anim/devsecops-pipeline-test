// ============================================================
// Test Jenkinsfile — Pre-Commit + Build Stages
// For local Jenkins testing of DevSecOps pipeline templates
// ============================================================

pipeline {
    agent any

    environment {
        GITLEAKS_VERSION   = '8.18.2'
        SYFT_VERSION       = '1.4.1'
        GRYPE_VERSION      = '0.78.0'
        CHECKOV_VERSION    = '3.2.0'

        IMAGE_NAME         = 'test-devsecops-app'
        IMAGE_TAG          = "${env.GIT_COMMIT?.take(7) ?: 'latest'}"
        IMAGE_REF          = "${IMAGE_NAME}:${IMAGE_TAG}"

        SBOM_REPORT        = 'sbom.cyclonedx.json'
        GRYPE_SCA_REPORT   = 'grype-sca-report.json'
        GRYPE_IMG_REPORT   = 'grype-image-report.json'
        CHECKOV_REPORT     = 'checkov-report.json'
        GITLEAKS_REPORT    = 'gitleaks-report.json'

        SEVERITY_THRESHOLD = 'high'
        APPROVED_LICENSES  = 'MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,CC0-1.0,Unlicense,LGPL-2.1'
    }

    stages {

        // ── PRE-COMMIT ────────────────────────────────────────
        stage('Install Tools') {
            steps {
                sh '''
                    if ! command -v gitleaks &> /dev/null; then
                        curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
                            | tar -xz -C /usr/local/bin gitleaks
                    fi
                    if ! command -v syft &> /dev/null; then
                        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
                            | sh -s -- -b /usr/local/bin v${SYFT_VERSION}
                    fi
                    if ! command -v grype &> /dev/null; then
                        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
                            | sh -s -- -b /usr/local/bin v${GRYPE_VERSION}
                    fi
                    if ! command -v checkov &> /dev/null; then
                        pip install checkov==${CHECKOV_VERSION} --quiet
                    fi
                '''
            }
        }

        stage('Secret Detection') {
            steps {
                script {
                    def exitCode = sh(
                        script: "gitleaks detect --source . --report-format json --report-path ${GITLEAKS_REPORT} --exit-code 1",
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
                sh "syft . -o cyclonedx-json=${SBOM_REPORT}"
                archiveArtifacts artifacts: "${SBOM_REPORT}"
            }
        }

        stage('Software Composition Analysis') {
            steps {
                script {
                    def exitCode = sh(
                        script: """
                            grype sbom:${SBOM_REPORT} \
                                --fail-on ${SEVERITY_THRESHOLD} \
                                --output json \
                                --file ${GRYPE_SCA_REPORT}
                        """,
                        returnStatus: true
                    )
                    archiveArtifacts artifacts: "${GRYPE_SCA_REPORT}", allowEmptyArchive: true
                    if (exitCode != 0) {
                        error("SCA FAILED — vulnerabilities at or above '${SEVERITY_THRESHOLD}' detected. Review ${GRYPE_SCA_REPORT}.")
                    }
                }
            }
        }

        stage('License Compliance') {
            steps {
                script {
                    def exitCode = sh(
                        script: """
                            python3 - <<'EOF'
import json, sys

approved = set("${APPROVED_LICENSES}".split(","))

with open("${SBOM_REPORT}") as f:
    sbom = json.load(f)

violations = []
for component in sbom.get("components", []):
    for lic in component.get("licenses", []):
        spdx_id = lic.get("license", {}).get("id", "UNKNOWN")
        if spdx_id not in approved:
            violations.append(f"{component.get('name', 'unknown')}@{component.get('version', '?')} — {spdx_id}")

if violations:
    print("LICENSE VIOLATIONS FOUND:")
    for v in violations:
        print(f"  - {v}")
    sys.exit(1)
else:
    print("All licenses compliant.")
EOF
                        """,
                        returnStatus: true
                    )
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

        stage('Container Image Scanning') {
            steps {
                script {
                    def exitCode = sh(
                        script: """
                            grype ${IMAGE_REF} \
                                --fail-on ${SEVERITY_THRESHOLD} \
                                --output json \
                                --file ${GRYPE_IMG_REPORT}
                        """,
                        returnStatus: true
                    )
                    archiveArtifacts artifacts: "${GRYPE_IMG_REPORT}", allowEmptyArchive: true
                    if (exitCode != 0) {
                        error("Container Image Scan FAILED — vulnerabilities at or above '${SEVERITY_THRESHOLD}' detected. Review ${GRYPE_IMG_REPORT}.")
                    }
                }
            }
        }

        stage('IaC Security Scanning') {
            steps {
                script {
                    def exitCode = sh(
                        script: """
                            checkov -d . \
                                --framework terraform,cloudformation,kubernetes \
                                --output json \
                                --output-file ${CHECKOV_REPORT} \
                                --soft-fail-on LOW,MEDIUM \
                                --hard-fail-on HIGH,CRITICAL
                        """,
                        returnStatus: true
                    )
                    archiveArtifacts artifacts: "${CHECKOV_REPORT}", allowEmptyArchive: true
                    if (exitCode != 0) {
                        error("IaC Scanning FAILED — HIGH or CRITICAL misconfigurations detected. Review ${CHECKOV_REPORT}.")
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
            archiveArtifacts artifacts: "*.json", allowEmptyArchive: true
        }
    }
}

package trivy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMapsVulnerabilitiesAndLicenses(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "trivy.json")
	report := `{
		"Results": [{
			"Target": "package-lock.json",
			"Type": "npm",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2026-1000",
				"PkgName": "left-pad",
				"InstalledVersion": "1.0.0",
				"FixedVersion": "1.0.1",
				"Severity": "HIGH",
				"Description": "bad package"
			}],
			"Licenses": [{
				"PkgName": "bad-license-package",
				"Name": "GPL-3.0",
				"Category": "HIGH",
				"FilePath": "node_modules/bad/package.json"
			}]
		}]
	}`
	if err := os.WriteFile(reportPath, []byte(report), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	got, err := Parse(reportPath)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(Parse()) = %d, want 2", len(got))
	}

	vuln := got[0]
	if vuln.PackageName != "left-pad" ||
		vuln.InstalledVersion != "1.0.0" ||
		vuln.FixedVersion != "1.0.1" ||
		vuln.CVEID != "CVE-2026-1000" ||
		vuln.Severity != "HIGH" ||
		!vuln.IsVulnerable ||
		!vuln.IsOutdated ||
		vuln.Ecosystem != "NODE" {
		t.Fatalf("unexpected vulnerability: %#v", vuln)
	}

	license := got[1]
	if license.PackageName != "bad-license-package" ||
		license.License != "GPL-3.0" ||
		license.Severity != "HIGH" ||
		!license.HasLicenseIssue ||
		license.IsVulnerable {
		t.Fatalf("unexpected license finding: %#v", license)
	}
}

func TestParseRejectsEmptyPath(t *testing.T) {
	if _, err := Parse(" "); err == nil {
		t.Fatal("Parse() error = nil, want error")
	}
}

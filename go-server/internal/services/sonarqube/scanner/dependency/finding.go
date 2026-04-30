package dependency

import "encoding/json"

type Finding struct {
	// Identity
	Tool     string
	Language string

	// Package info
	PackageName      string
	Ecosystem        string
	InstalledVersion string
	FixedVersion     string
	LatestVersion    string

	// Vulnerability
	CVEID       string
	CVESeverity string
	Description string

	// License
	License         string
	HasLicenseIssue bool

	// Flags
	IsOutdated   bool
	IsVulnerable bool

	// Raw output for JSONB storage
	RawFinding json.RawMessage
}

package parser

import "go-server/internal/services/sonarqube/scanner/dependency"

func ParseMaven(raw []byte) ([]*dependency.Finding, error) {
	return parseDependencyCheck(raw, "mvn-dependency-check", "java")
}

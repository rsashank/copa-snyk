package snyk

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

type SnykReport struct {
	PackageManager  string     `json:"packageManager"`
	Vulnerabilities []SnykVuln `json:"vulnerabilities"`
	DependencyCount int        `json:"dependencyCount"`
	Org             string     `json:"org"`
	IsPrivate       bool       `json:"isPrivate"`
}

type SnykVuln struct {
	ID           string        `json:"id"`
	PackageName  string        `json:"packageName"`
	Version      string        `json:"version"`
	UpgradePath  []interface{} `json:"upgradePath"` // Can contain bool + string
	IsUpgradable bool          `json:"isUpgradable"`
}

type SnykParser struct{}

func NewSnykParser() *SnykParser {
	return &SnykParser{}
}

func parseSnykReport(file string) (*SnykReport, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var report SnykReport
	if err = json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	return &report, nil
}

func (p *SnykParser) Parse(file string) (*v1alpha1.UpdateManifest, error) {
	report, err := parseSnykReport(file)
	if err != nil {
		return nil, err
	}

	// Extract distro info from packageManager (e.g., "debian:11")
	var osType, osVersion string
	if parts := strings.SplitN(report.PackageManager, ":", 2); len(parts) == 2 {
		osType = parts[0]
		osVersion = parts[1]
	}

	manifest := v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata: v1alpha1.Metadata{
			OS: v1alpha1.OS{
				Type:    osType,
				Version: osVersion,
			},
			Config: v1alpha1.Config{
				Arch: "", // Not available in Snyk JSON
			},
		},
	}

	for _, vuln := range report.Vulnerabilities {
		if !vuln.IsUpgradable {
			continue
		}

		// Pick last valid upgrade version string from UpgradePath
		var fixedVersion string
		for i := len(vuln.UpgradePath) - 1; i >= 0; i-- {
			if s, ok := vuln.UpgradePath[i].(string); ok && strings.Contains(s, "@") {
				parts := strings.SplitN(s, "@", 2)
				if len(parts) == 2 {
					fixedVersion = parts[1]
					break
				}
			}
		}

		if fixedVersion == "" || vuln.PackageName == "" || vuln.Version == "" {
			continue
		}

		manifest.Updates = append(manifest.Updates, v1alpha1.UpdatePackage{
			Name:             vuln.PackageName,
			InstalledVersion: vuln.Version,
			FixedVersion:     fixedVersion,
			VulnerabilityID:  vuln.ID,
		})
	}

	if len(manifest.Updates) == 0 {
		return nil, errors.New("no scanning results for os-pkgs found")
	}

	return &manifest, nil
}

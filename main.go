package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

type SnykReport struct {
	Vulnerabilities []SnykVuln `json:"vulnerabilities"`
}

type SnykVuln struct {
	ID             string        `json:"id"`
	PackageName    string        `json:"packageName"`
	Version        string        `json:"version"`
	Language       string        `json:"language"`
	PackageManager string        `json:"packageManager"`
	FixedIn        []string      `json:"fixedIn"` // fixed versions, may be empty
	UpgradePath    []interface{} `json:"upgradePath"`
	IsUpgradable   bool          `json:"isUpgradable"`
	Identifiers    struct {
		CVE []string `json:"CVE"`
	} `json:"identifiers"`
}

type Update struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerabilityID"`
}

type Metadata struct {
	OS struct {
		Type    string `json:"type"`
		Version string `json:"version"`
	} `json:"os"`
	Config struct {
		Arch string `json:"arch"`
	} `json:"config"`
}

type UpdateManifest struct {
	APIVersion string   `json:"apiVersion"`
	Metadata   Metadata `json:"metadata"`
	Updates    []Update `json:"updates"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <snyk-report.json>")
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	var report SnykReport
	if err := json.Unmarshal(data, &report); err != nil {
		panic(err)
	}

	manifest := UpdateManifest{
		APIVersion: "v1alpha1",
	}

	for _, vuln := range report.Vulnerabilities {
		if !vuln.IsUpgradable {
			continue
		}

		fixedVersion := ""
		for i := len(vuln.UpgradePath) - 1; i >= 0; i-- {
			if s, ok := vuln.UpgradePath[i].(string); ok {
				// Snyk strings often look like "curl@7.74.0-1.3+deb11u8"
				if strings.Contains(s, "@") {
					parts := strings.SplitN(s, "@", 2)
					if len(parts) == 2 {
						fixedVersion = parts[1]
						break
					}
				} else {
					// fallback: use the string directly if no '@'
					fixedVersion = s
					break
				}
			}
		}

		if fixedVersion == "" || vuln.PackageName == "" || vuln.Version == "" {
			continue
		}

		cve := ""
		if len(vuln.Identifiers.CVE) > 0 {
			cve = vuln.Identifiers.CVE[0]
		}

		manifest.Updates = append(manifest.Updates, Update{
			Name:             vuln.PackageName,
			InstalledVersion: vuln.Version,
			FixedVersion:     fixedVersion,
			VulnerabilityID:  cve,
		})
	}

	if len(manifest.Updates) == 0 {
		fmt.Println("No OS package upgrades found in report.")
		os.Exit(0)
	}

	out, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(out))
}

package stig

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/aristonllc/stigkube/pkg/models"
)

//go:embed controls.json
var stigData embed.FS

// Controls holds all loaded STIG controls
var Controls []models.Control

// Load reads and parses the embedded controls.json
func Load() error {
	data, err := stigData.ReadFile("controls.json")
	if err != nil {
		return fmt.Errorf("failed to read embedded controls.json: %w", err)
	}

	if err := json.Unmarshal(data, &Controls); err != nil {
		return fmt.Errorf("failed to parse controls.json: %w", err)
	}

	return nil
}

// LoadFromFile reads controls from a specific file path
func LoadFromFile(path string) error {
	data, err := embed.FS.ReadFile(stigData, path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}

	if err := json.Unmarshal(data, &Controls); err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}

	return nil
}

// GetControl returns a control by its V-ID
func GetControl(vulnID string) *models.Control {
	for i := range Controls {
		if Controls[i].ID == vulnID {
			return &Controls[i]
		}
	}
	return nil
}

// GetControlBySTIGID returns a control by its STIG ID (e.g., CNTR-K8-000220)
func GetControlBySTIGID(stigID string) *models.Control {
	for i := range Controls {
		if Controls[i].STIGID == stigID {
			return &Controls[i]
		}
	}
	return nil
}

// GetControlsByCategory returns all controls of a given category (I, II, III)
func GetControlsByCategory(cat string) []models.Control {
	var result []models.Control
	for _, c := range Controls {
		if c.CAT == cat {
			result = append(result, c)
		}
	}
	return result
}

// GetControlCount returns the total number of controls
func GetControlCount() int {
	return len(Controls)
}

package reporter

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aristonllc/stigkube/pkg/models"
)

// PrintSummary outputs a human-readable summary of scan results to stdout
func PrintSummary(result *models.ScanResult) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("STIG COMPLIANCE SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("\nCluster: %s\n", result.ClusterName)
	fmt.Printf("Kubernetes Version: %s\n", result.KubernetesVersion)
	fmt.Printf("Deployment Method: %s\n", result.DeploymentMethod)
	fmt.Printf("Nodes: %d\n", result.NodeCount)
	fmt.Printf("Scan Time: %s\n", result.ScanTimestamp.Format(time.RFC3339))

	fmt.Println("\n" + strings.Repeat("-", 60))
	fmt.Println("SUMMARY")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Printf("\nTotal Checks: %d\n", result.Summary.Total)
	fmt.Printf("  Passed:       %d\n", result.Summary.Pass)
	fmt.Printf("  Failed:       %d\n", result.Summary.Fail)
	fmt.Printf("  Not Reviewed: %d\n", result.Summary.NotReviewed)
	fmt.Printf("  Not Applicable: %d\n", result.Summary.NotApplicable)
	fmt.Printf("  Errors:       %d\n", result.Summary.Error)

	fmt.Println("\nBy Severity:")
	fmt.Printf("  CAT I (High) Failures:   %d\n", result.Summary.HighFail)
	fmt.Printf("  CAT II (Medium) Failures: %d\n", result.Summary.MediumFail)
	fmt.Printf("  CAT III (Low) Failures:  %d\n", result.Summary.LowFail)

	// Print failed findings
	if result.Summary.Fail > 0 {
		fmt.Println("\n" + strings.Repeat("-", 60))
		fmt.Println("FAILED CHECKS")
		fmt.Println(strings.Repeat("-", 60))

		for _, finding := range result.Findings {
			if finding.Status == models.StatusFail {
				printFinding(finding)
			}
		}
	}

	// Print not reviewed findings
	if result.Summary.NotReviewed > 0 {
		fmt.Println("\n" + strings.Repeat("-", 60))
		fmt.Println("NOT REVIEWED (Requires Node Access)")
		fmt.Println(strings.Repeat("-", 60))

		for _, finding := range result.Findings {
			if finding.Status == models.StatusNotReviewed {
				fmt.Printf("\n[%s] %s\n", finding.Control.ID, finding.Control.Title)
				fmt.Printf("  Severity: CAT %s (%s)\n", finding.Control.CAT, finding.Control.Severity)
				fmt.Printf("  Reason: %s\n", finding.Details)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
}

func printFinding(finding models.Finding) {
	fmt.Printf("\n[%s] %s\n", finding.Control.ID, finding.Control.Title)
	fmt.Printf("  STIG ID: %s\n", finding.Control.STIGID)
	fmt.Printf("  Severity: CAT %s (%s)\n", finding.Control.CAT, finding.Control.Severity)
	fmt.Printf("  Status: FAIL\n")
	if finding.Details != "" {
		fmt.Printf("  Details: %s\n", finding.Details)
	}
	if finding.ExpectedValue != "" {
		fmt.Printf("  Expected: %s\n", finding.ExpectedValue)
	}
	if finding.ActualValue != "" {
		fmt.Printf("  Actual: %s\n", finding.ActualValue)
	}
	if finding.NodeName != "" {
		fmt.Printf("  Node: %s\n", finding.NodeName)
	}
}

// WriteJSON writes scan results to a JSON file
func WriteJSON(result *models.ScanResult, outputDir string) error {
	// Ensure output directory exists (0750 per STIG file permission requirements)
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate filename with timestamp
	filename := fmt.Sprintf("scan-results-%s.json", result.ScanTimestamp.Format("2006-01-02-150405"))
	filepath := filepath.Join(outputDir, filename)

	// Marshal to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	// Write file (0600 per STIG file permission requirements)
	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Results written to: %s\n", filepath)
	return nil
}

// WriteXCCDF writes scan results in XCCDF format for STIG Viewer import
func WriteXCCDF(result *models.ScanResult, outputDir string) error {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate filename
	filename := fmt.Sprintf("xccdf-results-%s.xml", result.ScanTimestamp.Format("2006-01-02-150405"))
	fpath := filepath.Join(outputDir, filename)

	// Build XCCDF structure
	xccdf := buildXCCDF(result)

	// Marshal to XML
	data, err := xml.MarshalIndent(xccdf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal XCCDF: %w", err)
	}

	// Add XML header
	xmlData := []byte(xml.Header + string(data))

	// Write file
	if err := os.WriteFile(fpath, xmlData, 0600); err != nil {
		return fmt.Errorf("failed to write XCCDF file: %w", err)
	}

	fmt.Printf("XCCDF results written to: %s\n", fpath)
	return nil
}

// XCCDF XML structures for STIG Viewer compatibility
type xccdfBenchmark struct {
	XMLName   xml.Name         `xml:"Benchmark"`
	XMLNS     string           `xml:"xmlns,attr"`
	ID        string           `xml:"id,attr"`
	TestResult xccdfTestResult `xml:"TestResult"`
}

type xccdfTestResult struct {
	ID          string            `xml:"id,attr"`
	StartTime   string            `xml:"start-time,attr"`
	EndTime     string            `xml:"end-time,attr"`
	Target      string            `xml:"target"`
	TargetFacts []xccdfFact       `xml:"target-facts>fact"`
	RuleResults []xccdfRuleResult `xml:"rule-result"`
	Score       xccdfScore        `xml:"score"`
}

type xccdfFact struct {
	Name  string `xml:"name,attr"`
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type xccdfRuleResult struct {
	IDRef    string `xml:"idref,attr"`
	Severity string `xml:"severity,attr,omitempty"`
	Time     string `xml:"time,attr"`
	Result   string `xml:"result"`
	Message  string `xml:"message,omitempty"`
}

type xccdfScore struct {
	System   string  `xml:"system,attr"`
	Maximum  float64 `xml:"maximum,attr"`
	Value    float64 `xml:",chardata"`
}

func buildXCCDF(result *models.ScanResult) xccdfBenchmark {
	// Map our status values to XCCDF result values
	statusMap := map[string]string{
		models.StatusPass:          "pass",
		models.StatusFail:          "fail",
		models.StatusNotReviewed:   "notchecked",
		models.StatusNotApplicable: "notapplicable",
		models.StatusError:         "error",
	}

	// Build rule results
	var ruleResults []xccdfRuleResult
	for _, finding := range result.Findings {
		xccdfResult := statusMap[finding.Status]
		if xccdfResult == "" {
			xccdfResult = "unknown"
		}

		// Build message with details
		message := finding.Details
		if finding.ActualValue != "" {
			message += fmt.Sprintf(" (Actual: %s)", finding.ActualValue)
		}
		if finding.NodeName != "" {
			message += fmt.Sprintf(" [Node: %s]", finding.NodeName)
		}

		ruleResults = append(ruleResults, xccdfRuleResult{
			IDRef:    finding.Control.STIGID,
			Severity: severityToXCCDF(finding.Control.CAT),
			Time:     result.ScanTimestamp.Format(time.RFC3339),
			Result:   xccdfResult,
			Message:  message,
		})
	}

	// Calculate score (percentage of passing checks)
	var score float64
	if result.Summary.Total > 0 {
		score = float64(result.Summary.Pass) / float64(result.Summary.Total) * 100
	}

	return xccdfBenchmark{
		XMLNS: "http://checklists.nist.gov/xccdf/1.2",
		ID:    "Kubernetes_STIG",
		TestResult: xccdfTestResult{
			ID:        fmt.Sprintf("stigkube-scan-%s", result.ScanTimestamp.Format("20060102-150405")),
			StartTime: result.ScanTimestamp.Format(time.RFC3339),
			EndTime:   result.ScanTimestamp.Format(time.RFC3339),
			Target:    result.ClusterName,
			TargetFacts: []xccdfFact{
				{Name: "urn:stigkube:fact:kubernetes-version", Type: "string", Value: result.KubernetesVersion},
				{Name: "urn:stigkube:fact:deployment-method", Type: "string", Value: result.DeploymentMethod},
				{Name: "urn:stigkube:fact:node-count", Type: "number", Value: fmt.Sprintf("%d", result.NodeCount)},
			},
			RuleResults: ruleResults,
			Score: xccdfScore{
				System:  "urn:xccdf:scoring:default",
				Maximum: 100,
				Value:   score,
			},
		},
	}
}

func severityToXCCDF(cat string) string {
	switch cat {
	case "I":
		return "high"
	case "II":
		return "medium"
	case "III":
		return "low"
	default:
		return "unknown"
	}
}

// strings helper to avoid importing strings for one function
var strings = struct {
	Repeat func(string, int) string
}{
	Repeat: func(s string, count int) string {
		result := ""
		for i := 0; i < count; i++ {
			result += s
		}
		return result
	},
}

package reporting

import (
	"encoding/json"
	"io"

	"github.com/springhawk/springhawk/pkg/models"
)

type JSONReporter struct {
	Indent bool
}

func (r *JSONReporter) WriteScanResult(result *models.ScanResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	if r.Indent {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(result)
}

func (r *JSONReporter) WriteStaticResult(result *models.StaticAnalysisResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	if r.Indent {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(result)
}

func (r *JSONReporter) WriteFinding(f *models.Finding, w io.Writer) error {
	enc := json.NewEncoder(w)
	return enc.Encode(f)
}

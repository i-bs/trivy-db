package bellsoft

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var bellsoftDir = filepath.Join("bell-sw-osv-database", "BELL-CVE")

func NewVulnSrc() osv.OSV {
	sources := map[ecosystem.Type]types.DataSource{
		ecosystem.BellSoft: {
			ID:   vulnerability.BellSoft,
			Name: "BellSoft Security Advisory Database",
			URL:  "https://github.com/bell-sw/osv-database",
		},
	}

	return osv.New(bellsoftDir, vulnerability.BellSoft, sources, osv.WithTransformer(&transformer{}))
}

type transformer struct{}

type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

func (t *transformer) PostParseAffected(advisory osv.Advisory, _ osv.Affected) (osv.Advisory, error) {
	return advisory, nil
}

func (t *transformer) TransformAdvisories(advs []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	var specific DatabaseSpecific
	if err := json.Unmarshal(entry.DatabaseSpecific, &specific); err != nil {
		return nil, oops.Tags("bellsoft").With("vuln_id", entry.ID).With("aliases", entry.Aliases).Wrapf(err, "json decode error")
	}

	severity := convertSeverity(specific.Severity)
	for i := range advs {
		advs[i].Severity = severity
	}

	return advs, nil
}

func convertSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
	case "low":
		return types.SeverityLow
	case "moderate":
		return types.SeverityMedium
	case "high":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}

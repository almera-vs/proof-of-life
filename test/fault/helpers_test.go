//go:build integration

package fault

import (
	"testing"

	"github.com/minio/minio-go/v7"

	"github.com/almera-vs/proof-of-life/internal/report"
	"github.com/almera-vs/proof-of-life/test/harness"
)

type minioObject = minio.ObjectInfo

func c(t *testing.T, r *report.Report) string {
	t.Helper()
	return harness.Check(t, r, "backup.integrity").Reason
}

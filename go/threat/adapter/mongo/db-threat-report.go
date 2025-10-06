package mongo

type threatReportRepository struct {
	threatReport ThreatReportRepository
}

func (inst *threatReportRepository) ThreatReport() ThreatReportRepository {
	// Success
	return inst.threatReport
}

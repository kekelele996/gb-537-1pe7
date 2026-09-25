package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"pki-certificate-rollover-impact/backend/internal/algorithm"
	"pki-certificate-rollover-impact/backend/internal/constants"
	"pki-certificate-rollover-impact/backend/internal/dto"
	"pki-certificate-rollover-impact/backend/internal/model"
	"pki-certificate-rollover-impact/backend/internal/repository"
	"pki-certificate-rollover-impact/backend/internal/util"
)

func driftFixture(t *testing.T) (*gorm.DB, model.TrustAnchor, model.TrustAnchor, model.CertificateChain, model.DependentService) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.TrustAnchor{}, &model.CertificateChain{}, &model.DependentService{}, &model.RolloverScenario{}, &model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2031, 3, 1, 8, 0, 0, 0, time.UTC)
	old := model.TrustAnchor{AnchorCode: "DRIFT-OLD", SubjectDN: "CN=old", SerialNumber: "1", FingerprintSHA256: "1111111111111111111111111111111111111111111111111111111111111111", NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), KeyAlgorithm: "ECDSA", CertificateState: "valid", PemRedacted: "old-public-cert", CreatedAt: now, UpdatedAt: now}
	next := model.TrustAnchor{AnchorCode: "DRIFT-NEW", SubjectDN: "CN=new", SerialNumber: "2", FingerprintSHA256: "2222222222222222222222222222222222222222222222222222222222222222", NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), KeyAlgorithm: "ECDSA", CertificateState: "valid", PemRedacted: "new-public-cert", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&old).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&next).Error; err != nil {
		t.Fatal(err)
	}
	chain := model.CertificateChain{ChainCode: "DRIFT-CHAIN", TrustAnchorID: old.ID, LeafSubject: "CN=leaf", CertificateRefsJSON: "[]", ChainFingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ValidFrom: now.Add(-time.Hour), ValidTo: now.Add(24 * time.Hour), ValidationResult: `{"valid":true}`, ChainState: "validated", SourceChecksum: "source", PublicChainPEM: "public", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&chain).Error; err != nil {
		t.Fatal(err)
	}
	trustRefs, _ := json.Marshal([]uint{old.ID, next.ID})
	dependency := model.DependentService{ServiceCode: "DRIFT-SVC", Name: "Drift Service", OwnerTeam: "PKI Platform", Environment: "production", ChainID: chain.ID, ClientTrustRefsJSON: string(trustRefs), Protocol: "mtls", Criticality: "critical", DependencyEdgesJSON: "[]", ServiceState: "active", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&dependency).Error; err != nil {
		t.Fatal(err)
	}
	return db, old, next, chain, dependency
}

func frozenScenarioFromAssets(t *testing.T, db *gorm.DB, old, next model.TrustAnchor, chain model.CertificateChain, svc model.DependentService, state string, createdBy uint, idempotencyKey string) model.RolloverScenario {
	t.Helper()
	now := time.Date(2031, 3, 1, 8, 0, 0, 0, time.UTC)
	trustRefs := []uint{}
	_ = json.Unmarshal([]byte(svc.ClientTrustRefsJSON), &trustRefs)
	snapshot := algorithm.NewSnapshot(
		algorithm.ScenarioConfig{Name: "drift scenario", OldAnchorID: old.ID, NewAnchorID: next.ID, OverlapStart: now.Add(7 * 24 * time.Hour), OverlapEnd: now.Add(21 * 24 * time.Hour), CandidateChainIDs: []uint{chain.ID}, SimulationTime: now.Add(14 * 24 * time.Hour)},
		[]algorithm.AnchorSnapshot{{ID: old.ID, Code: old.AnchorCode, State: old.CertificateState, NotBefore: old.NotBefore, NotAfter: old.NotAfter}, {ID: next.ID, Code: next.AnchorCode, State: next.CertificateState, NotBefore: next.NotBefore, NotAfter: next.NotAfter}},
		[]algorithm.ChainSnapshot{{ID: chain.ID, Code: chain.ChainCode, AnchorID: chain.TrustAnchorID, LeafSubject: chain.LeafSubject, ValidFrom: chain.ValidFrom, ValidTo: chain.ValidTo, State: chain.ChainState, ValidationValid: true}},
		[]algorithm.ServiceSnapshot{{ID: svc.ID, Code: svc.ServiceCode, ChainID: svc.ChainID, TrustAnchorIDs: trustRefs, Criticality: svc.Criticality, State: svc.ServiceState}},
	)
	result, err := algorithm.Simulate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := snapshot.Hash()
	snapshotJSON, _ := snapshot.Canonical()
	candidateJSON, _ := json.Marshal([]uint{chain.ID})
	affectedJSON, _ := json.Marshal(result.AffectedServices)
	pathsJSON, _ := json.Marshal(result.BrokenPaths)
	evidenceJSON, _ := json.Marshal(result.Evidence)
	key := idempotencyKey
	scenario := model.RolloverScenario{Name: snapshot.Config.Name, OldAnchorID: old.ID, NewAnchorID: next.ID, OverlapStart: snapshot.Config.OverlapStart, OverlapEnd: snapshot.Config.OverlapEnd, CandidateChainIDs: string(candidateJSON), AlgorithmVersion: algorithm.Version, InputHash: hash, InputSnapshot: snapshotJSON, SimulationTime: snapshot.Config.SimulationTime, AffectedServicesJSON: string(affectedJSON), BrokenPathsJSON: string(pathsJSON), PathEvidenceJSON: string(evidenceJSON), ScenarioState: state, Explanation: result.Explanation, CreatedBy: createdBy, CreatedByName: "operator", IdempotencyKey: key, CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&scenario).Error; err != nil {
		t.Fatal(err)
	}
	return scenario
}

func newDriftService(db *gorm.DB) *RolloverScenarioService {
	return NewRolloverScenarioService(
		repository.NewRolloverScenarioRepository(db),
		repository.NewTrustAnchorRepository(db),
		repository.NewCertificateChainRepository(db),
		repository.NewDependentServiceRepository(db),
		repository.NewAuditRepository(db),
		repository.NewTransactionManager(db),
	)
}

func TestReadyToExecutingBlockedWhenAssetsDrift(t *testing.T) {
	db, old, next, chain, svc := driftFixture(t)
	scenario := frozenScenarioFromAssets(t, db, old, next, chain, svc, "ready", 7, "drift-ready-key")
	svcService := newDriftService(db)
	actor := util.Actor{UserID: 7, Username: "operator", Role: string(constants.RolePKIOperator)}

	report, err := svcService.Drift(context.Background(), scenario.ID, actor, "request-drift-clean")
	if err != nil {
		t.Fatal(err)
	}
	if report.Drifted {
		t.Fatalf("freshly frozen scenario must not drift: %+v", report.Changes)
	}

	// asset team moves the service's trust set after the freeze
	oldOnly, _ := json.Marshal([]uint{old.ID})
	if err := db.Model(&model.DependentService{}).Where("id = ?", svc.ID).Update("client_trust_refs_json", string(oldOnly)).Error; err != nil {
		t.Fatal(err)
	}

	report, err = svcService.Drift(context.Background(), scenario.ID, actor, "request-drift-dirty")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Drifted || report.BlockedAction != "start_execution" {
		t.Fatalf("expected drift blocking drill start, got %+v", report)
	}
	if len(report.Changes) != 1 || report.Changes[0].EntityType != "dependent_service" {
		t.Fatalf("expected one service change, got %+v", report.Changes)
	}

	_, err = svcService.Transition(context.Background(), scenario.ID, dto.RolloverScenarioTransitionRequest{ToState: "executing"}, actor, "request-transition-blocked")
	var apiErr *util.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || apiErr.Code != util.CodeSnapshotDrift {
		t.Fatalf("got %#v, want 409 %s", err, util.CodeSnapshotDrift)
	}
}

func TestRefreezePrunesRemovedCandidateChains(t *testing.T) {
	db, old, next, chain, svc := driftFixture(t)
	extra := model.CertificateChain{ChainCode: "DRIFT-CHAIN-EXTRA", TrustAnchorID: next.ID, LeafSubject: "CN=extra", CertificateRefsJSON: "[]", ChainFingerprint: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", ValidFrom: chain.ValidFrom, ValidTo: chain.ValidTo, ValidationResult: `{"valid":true}`, ChainState: "validated", SourceChecksum: "source-extra", PublicChainPEM: "public-extra", CreatedAt: chain.CreatedAt, UpdatedAt: chain.UpdatedAt}
	if err := db.Create(&extra).Error; err != nil {
		t.Fatal(err)
	}
	scenario := frozenScenarioWithChains(t, db, old, next, []model.CertificateChain{chain, extra}, svc, "ready", 7, "drift-prune-key")
	if err := db.Unscoped().Delete(&model.CertificateChain{}, extra.ID).Error; err != nil {
		t.Fatal(err)
	}
	svcService := newDriftService(db)
	actor := util.Actor{UserID: 7, Username: "operator", Role: string(constants.RolePKIOperator)}

	report, err := svcService.Drift(context.Background(), scenario.ID, actor, "request-prune-drift")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Drifted {
		t.Fatal("removed candidate chain must be reported as drift")
	}
	foundRemoved := false
	for _, change := range report.Changes {
		if change.EntityType == "certificate_chain" && change.Kind == "removed" && change.EntityID == extra.ID {
			foundRemoved = true
		}
	}
	if !foundRemoved {
		t.Fatalf("expected removed candidate chain %d in report: %+v", extra.ID, report.Changes)
	}
	refrozen, err := svcService.Refreeze(context.Background(), scenario.ID, actor, "request-prune-refreeze")
	if err != nil {
		t.Fatalf("refreeze should prune removed candidate chains: %v", err)
	}
	if len(refrozen.CandidateChainIDs) != 1 || refrozen.CandidateChainIDs[0] != chain.ID {
		t.Fatalf("expected only the surviving candidate chain, got %+v", refrozen.CandidateChainIDs)
	}
}

func frozenScenarioWithChains(t *testing.T, db *gorm.DB, old, next model.TrustAnchor, chains []model.CertificateChain, svc model.DependentService, state string, createdBy uint, idempotencyKey string) model.RolloverScenario {
	t.Helper()
	now := time.Date(2031, 3, 1, 8, 0, 0, 0, time.UTC)
	trustRefs := []uint{}
	_ = json.Unmarshal([]byte(svc.ClientTrustRefsJSON), &trustRefs)
	chainSnapshots := make([]algorithm.ChainSnapshot, 0, len(chains))
	chainIDs := make([]uint, 0, len(chains))
	for _, item := range chains {
		chainSnapshots = append(chainSnapshots, algorithm.ChainSnapshot{ID: item.ID, Code: item.ChainCode, AnchorID: item.TrustAnchorID, LeafSubject: item.LeafSubject, ValidFrom: item.ValidFrom, ValidTo: item.ValidTo, State: item.ChainState, ValidationValid: true})
		chainIDs = append(chainIDs, item.ID)
	}
	snapshot := algorithm.NewSnapshot(
		algorithm.ScenarioConfig{Name: "drift scenario", OldAnchorID: old.ID, NewAnchorID: next.ID, OverlapStart: now.Add(7 * 24 * time.Hour), OverlapEnd: now.Add(21 * 24 * time.Hour), CandidateChainIDs: chainIDs, SimulationTime: now.Add(14 * 24 * time.Hour)},
		[]algorithm.AnchorSnapshot{{ID: old.ID, Code: old.AnchorCode, State: old.CertificateState, NotBefore: old.NotBefore, NotAfter: old.NotAfter}, {ID: next.ID, Code: next.AnchorCode, State: next.CertificateState, NotBefore: next.NotBefore, NotAfter: next.NotAfter}},
		chainSnapshots,
		[]algorithm.ServiceSnapshot{{ID: svc.ID, Code: svc.ServiceCode, ChainID: svc.ChainID, TrustAnchorIDs: trustRefs, Criticality: svc.Criticality, State: svc.ServiceState}},
	)
	result, err := algorithm.Simulate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := snapshot.Hash()
	snapshotJSON, _ := snapshot.Canonical()
	candidateJSON, _ := json.Marshal(chainIDs)
	affectedJSON, _ := json.Marshal(result.AffectedServices)
	pathsJSON, _ := json.Marshal(result.BrokenPaths)
	evidenceJSON, _ := json.Marshal(result.Evidence)
	scenario := model.RolloverScenario{Name: snapshot.Config.Name, OldAnchorID: old.ID, NewAnchorID: next.ID, OverlapStart: snapshot.Config.OverlapStart, OverlapEnd: snapshot.Config.OverlapEnd, CandidateChainIDs: string(candidateJSON), AlgorithmVersion: algorithm.Version, InputHash: hash, InputSnapshot: snapshotJSON, SimulationTime: snapshot.Config.SimulationTime, AffectedServicesJSON: string(affectedJSON), BrokenPathsJSON: string(pathsJSON), PathEvidenceJSON: string(evidenceJSON), ScenarioState: state, Explanation: result.Explanation, CreatedBy: createdBy, CreatedByName: "operator", IdempotencyKey: idempotencyKey, CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&scenario).Error; err != nil {
		t.Fatal(err)
	}
	return scenario
}

func TestRefreezeClearsResultAndReturnsScenarioToDraft(t *testing.T) {
	db, old, next, chain, svc := driftFixture(t)
	scenario := frozenScenarioFromAssets(t, db, old, next, chain, svc, "ready", 7, "drift-refreeze-key")
	svcService := newDriftService(db)
	actor := util.Actor{UserID: 7, Username: "operator", Role: string(constants.RolePKIOperator)}

	// anchor lifecycle change after freeze
	if err := db.Model(&model.TrustAnchor{}).Where("id = ?", old.ID).Update("certificate_state", "expired").Error; err != nil {
		t.Fatal(err)
	}

	refrozen, err := svcService.Refreeze(context.Background(), scenario.ID, actor, "request-refreeze")
	if err != nil {
		t.Fatal(err)
	}
	if refrozen.ScenarioState != "draft" {
		t.Fatalf("expected draft after refreeze, got %s", refrozen.ScenarioState)
	}
	if len(refrozen.AffectedServicesJSON) != 0 || len(refrozen.BrokenPathsJSON) != 0 || len(refrozen.PathEvidenceJSON) != 0 {
		t.Fatal("prior simulation results must be cleared")
	}
	if refrozen.InputHash == scenario.InputHash {
		t.Fatal("input hash must reflect the refrozen assets")
	}
	if refrozen.Historical {
		t.Fatal("refrozen scenario must not be historical")
	}

	// old idempotency key must be released for a fresh simulation
	var stored model.RolloverScenario
	if err := db.First(&stored, scenario.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.IdempotencyKey != "" || stored.DurationMS != 0 || stored.ReplayVerified {
		t.Fatalf("stale simulation fields survived refreeze: %+v", stored)
	}

	// the new snapshot matches current assets, so drift is clean again
	report, err := svcService.Drift(context.Background(), scenario.ID, actor, "request-drift-after-refreeze")
	if err != nil {
		t.Fatal(err)
	}
	if report.Drifted {
		t.Fatalf("refrozen scenario must match current assets, got %+v", report.Changes)
	}
}

func TestVerifiedScenarioKeepsSnapshotAndBecomesHistorical(t *testing.T) {
	db, old, next, chain, svc := driftFixture(t)
	scenario := frozenScenarioFromAssets(t, db, old, next, chain, svc, "verified", 7, "drift-verified-key")
	if err := db.Model(&model.RolloverScenario{}).Where("id = ?", scenario.ID).Updates(map[string]any{"verified_by": 9, "verified_by_name": "reviewer"}).Error; err != nil {
		t.Fatal(err)
	}
	svcService := newDriftService(db)
	actor := util.Actor{UserID: 9, Username: "reviewer", Role: string(constants.RoleSecurityReviewer)}

	// chain is deprecated after independent verification
	if err := db.Model(&model.CertificateChain{}).Where("id = ?", chain.ID).Update("chain_state", "deprecated").Error; err != nil {
		t.Fatal(err)
	}

	report, err := svcService.Drift(context.Background(), scenario.ID, actor, "request-verified-drift")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Drifted || !report.Historical {
		t.Fatalf("verified scenario with drift should be historical, got %+v", report)
	}
	if report.BlockedAction != "" {
		t.Fatal("verified scenarios do not start drills, nothing should be blocked")
	}

	// original snapshot and result must be preserved
	var stored model.RolloverScenario
	if err := db.First(&stored, scenario.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.InputHash != scenario.InputHash || stored.InputSnapshot != scenario.InputSnapshot {
		t.Fatal("historical scenario must retain its original frozen snapshot")
	}
	if stored.ScenarioState != "verified" || !stored.Historical || stored.HistoricalAt == nil {
		t.Fatalf("verified historical flags not persisted: %+v", stored)
	}

	// refreeze must be refused even for an administrator
	admin := util.Actor{UserID: 1, Username: "admin", Role: string(constants.RoleAdmin)}
	_, err = svcService.Refreeze(context.Background(), scenario.ID, admin, "request-refreeze-historical")
	var apiErr *util.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Fatalf("got %#v, want 409 refusing historical refreeze", err)
	}
}

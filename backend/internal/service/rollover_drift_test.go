package service

import (
	"context"
	"errors"
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"net/http"
	"pki-certificate-rollover-impact/backend/internal/constants"
	"pki-certificate-rollover-impact/backend/internal/dto"
	"pki-certificate-rollover-impact/backend/internal/model"
	"pki-certificate-rollover-impact/backend/internal/repository"
	"pki-certificate-rollover-impact/backend/internal/util"
	"testing"
	"time"
)

func newDriftTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.TrustAnchor{}, &model.CertificateChain{}, &model.DependentService{}, &model.RolloverScenario{}, &model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func seedDriftAssets(t *testing.T, db *gorm.DB) (model.CertificateChain, time.Time) {
	t.Helper()
	now := time.Date(2032, 4, 2, 8, 0, 0, 0, time.UTC)
	anchors := []model.TrustAnchor{
		{AnchorCode: "DRIFT-OLD", SubjectDN: "CN=old", SerialNumber: "1", FingerprintSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), KeyAlgorithm: "ECDSA", CertificateState: "valid", PemRedacted: "public certificate", CreatedAt: now, UpdatedAt: now},
		{AnchorCode: "DRIFT-NEW", SubjectDN: "CN=new", SerialNumber: "2", FingerprintSHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), KeyAlgorithm: "ECDSA", CertificateState: "valid", PemRedacted: "public certificate", CreatedAt: now, UpdatedAt: now},
	}
	if err := db.Create(&anchors).Error; err != nil {
		t.Fatal(err)
	}
	chain := model.CertificateChain{ChainCode: "DRIFT-CHAIN", TrustAnchorID: anchors[0].ID, LeafSubject: "CN=leaf", CertificateRefsJSON: "[]", ChainFingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", ValidFrom: now.Add(-time.Hour), ValidTo: now.Add(72 * time.Hour), ValidationResult: `{"valid":true}`, ChainState: "validated", SourceChecksum: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", PublicChainPEM: "public chain", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&chain).Error; err != nil {
		t.Fatal(err)
	}
	trust, _ := encode([]uint{anchors[0].ID, anchors[1].ID})
	service := model.DependentService{ServiceCode: "DRIFT-SVC", Name: "Drift Service", OwnerTeam: "Payments", Environment: "production", ChainID: chain.ID, ClientTrustRefsJSON: trust, Protocol: "mtls", Criticality: "high", DependencyEdgesJSON: "[]", ServiceState: "active", CreatedAt: now, UpdatedAt: now}
	if err := db.Create(&service).Error; err != nil {
		t.Fatal(err)
	}
	return chain, now
}

func newDriftService(db *gorm.DB) *RolloverScenarioService {
	return NewRolloverScenarioService(repository.NewRolloverScenarioRepository(db), repository.NewTrustAnchorRepository(db), repository.NewCertificateChainRepository(db), repository.NewDependentServiceRepository(db), repository.NewAuditRepository(db), repository.NewTransactionManager(db))
}

func createReadyScenario(t *testing.T, service *RolloverScenarioService, chain model.CertificateChain, now time.Time, actor util.Actor) dto.RolloverScenarioResponse {
	t.Helper()
	request := dto.CreateRolloverScenarioRequest{Name: "drift rehearsal", OldAnchorID: chain.TrustAnchorID, NewAnchorID: chain.TrustAnchorID + 1, OverlapStart: now.Add(time.Hour), OverlapEnd: now.Add(2 * time.Hour), CandidateChainIDs: []uint{chain.ID}, SimulationTime: now.Add(90 * time.Minute)}
	created, err := service.Create(context.Background(), request, actor, "request-create")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Simulate(context.Background(), created.ID, "drift-key-"+created.Name, actor, "request-simulate"); err != nil {
		t.Fatal(err)
	}
	ready, err := service.Transition(context.Background(), created.ID, dto.RolloverScenarioTransitionRequest{ToState: "ready"}, actor, "request-ready")
	if err != nil {
		t.Fatal(err)
	}
	return ready
}

func TestDriftBlocksDrillStartAndRefreezeRestoresDraft(t *testing.T) {
	db := newDriftTestDB(t)
	chain, now := seedDriftAssets(t, db)
	service := newDriftService(db)
	actor := util.Actor{UserID: 7, Username: "operator", Role: string(constants.RolePKIOperator)}
	ready := createReadyScenario(t, service, chain, now, actor)

	if err := db.Model(&model.TrustAnchor{}).Where("id = ?", chain.TrustAnchorID).Update("certificate_state", "revoked").Error; err != nil {
		t.Fatal(err)
	}
	drift, err := service.CheckDrift(context.Background(), ready.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !drift.Changed || drift.Historical || len(drift.Changes) != 1 {
		t.Fatalf("expected one anchor change, got %#v", drift)
	}
	if drift.Changes[0].EntityType != "trust_anchor" || drift.Changes[0].Change != "modified" {
		t.Fatalf("unexpected drift item %#v", drift.Changes[0])
	}
	if drift.FrozenHash != ready.InputHash || drift.CurrentHash == ready.InputHash {
		t.Fatalf("drift hashes are inconsistent: %#v", drift)
	}

	_, err = service.Transition(context.Background(), ready.ID, dto.RolloverScenarioTransitionRequest{ToState: "executing"}, actor, "request-executing")
	var apiErr *util.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || apiErr.Code != util.CodeSnapshotDrift {
		t.Fatalf("got %#v, want 409 %s", err, util.CodeSnapshotDrift)
	}

	refrozen, err := service.Refreeze(context.Background(), ready.ID, actor, "request-refreeze")
	if err != nil {
		t.Fatal(err)
	}
	if refrozen.ScenarioState != "draft" || len(refrozen.AffectedServicesJSON) != 0 || len(refrozen.BrokenPathsJSON) != 0 || len(refrozen.PathEvidenceJSON) != 0 {
		t.Fatalf("refreeze must clear results and return to draft, got %#v", refrozen)
	}
	if refrozen.InputHash == ready.InputHash {
		t.Fatal("refreeze must store the hash of the current assets")
	}
	var stored model.RolloverScenario
	if err := db.First(&stored, ready.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.IdempotencyKey != nil || stored.ReplayVerified || stored.DurationMS != 0 {
		t.Fatalf("refreeze must release the idempotency key and clear run metadata: %#v", stored)
	}

	drift, err = service.CheckDrift(context.Background(), ready.ID)
	if err != nil {
		t.Fatal(err)
	}
	if drift.Changed || len(drift.Changes) != 0 || drift.CurrentHash != refrozen.InputHash {
		t.Fatalf("refrozen scenario must match current assets, got %#v", drift)
	}
	simulated, reused, err := service.Simulate(context.Background(), ready.ID, "drift-key-fresh", actor, "request-resimulate")
	if err != nil || reused || simulated.ScenarioState != "simulated" {
		t.Fatalf("re-simulation after refreeze failed: reused=%v err=%v", reused, err)
	}
}

func TestDrillStartAllowedWhenAssetsMatchFrozenSnapshot(t *testing.T) {
	db := newDriftTestDB(t)
	chain, now := seedDriftAssets(t, db)
	service := newDriftService(db)
	actor := util.Actor{UserID: 7, Username: "operator", Role: string(constants.RolePKIOperator)}
	ready := createReadyScenario(t, service, chain, now, actor)

	drift, err := service.CheckDrift(context.Background(), ready.ID)
	if err != nil {
		t.Fatal(err)
	}
	if drift.Changed {
		t.Fatalf("no drift expected, got %#v", drift.Changes)
	}
	executing, err := service.Transition(context.Background(), ready.ID, dto.RolloverScenarioTransitionRequest{ToState: "executing"}, actor, "request-executing")
	if err != nil || executing.ScenarioState != "executing" {
		t.Fatalf("drill start should be recorded, got state=%v err=%v", executing.ScenarioState, err)
	}
}

func TestVerifiedScenarioIsHistoricalAndCannotRefreeze(t *testing.T) {
	db := newDriftTestDB(t)
	chain, now := seedDriftAssets(t, db)
	service := newDriftService(db)
	creator := util.Actor{UserID: 7, Username: "operator", Role: string(constants.RolePKIOperator)}
	reviewer := util.Actor{UserID: 9, Username: "reviewer", Role: string(constants.RoleSecurityReviewer)}
	ready := createReadyScenario(t, service, chain, now, creator)
	if _, err := service.Transition(context.Background(), ready.ID, dto.RolloverScenarioTransitionRequest{ToState: "executing"}, creator, "request-executing"); err != nil {
		t.Fatal(err)
	}
	verified, err := service.Transition(context.Background(), ready.ID, dto.RolloverScenarioTransitionRequest{ToState: "verified"}, reviewer, "request-verify")
	if err != nil || verified.ScenarioState != "verified" {
		t.Fatalf("verification failed: %v", err)
	}

	if err := db.Model(&model.DependentService{}).Where("service_code = ?", "DRIFT-SVC").Update("criticality", "low").Error; err != nil {
		t.Fatal(err)
	}
	drift, err := service.CheckDrift(context.Background(), verified.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !drift.Changed || !drift.Historical {
		t.Fatalf("verified scenario must be reported as historical drift, got %#v", drift)
	}
	if drift.Changes[0].EntityType != "dependent_service" {
		t.Fatalf("unexpected drift item %#v", drift.Changes[0])
	}

	_, err = service.Refreeze(context.Background(), verified.ID, creator, "request-refreeze")
	var apiErr *util.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || apiErr.Code != util.CodeHistoricalRecord {
		t.Fatalf("got %#v, want 409 %s", err, util.CodeHistoricalRecord)
	}
	var stored model.RolloverScenario
	if err := db.First(&stored, verified.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.InputHash != verified.InputHash || stored.ScenarioState != "verified" {
		t.Fatal("verified scenario snapshot must remain untouched")
	}
}

func TestCheckDriftRequiresExistingScenario(t *testing.T) {
	db := newDriftTestDB(t)
	service := newDriftService(db)
	_, err := service.CheckDrift(context.Background(), 404)
	var apiErr *util.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Fatalf("got %#v, want 404", err)
	}
}

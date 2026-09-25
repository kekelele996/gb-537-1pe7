package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"gorm.io/gorm"

	"pki-certificate-rollover-impact/backend/internal/algorithm"
	"pki-certificate-rollover-impact/backend/internal/constants"
	"pki-certificate-rollover-impact/backend/internal/dto"
	"pki-certificate-rollover-impact/backend/internal/model"
	"pki-certificate-rollover-impact/backend/internal/util"
)

// Drift checks the frozen snapshot against the assets currently registered.
// Independently verified scenarios keep their original snapshot forever: when
// their inputs have drifted they are only flagged as historical records.
func (s *RolloverScenarioService) Drift(ctx context.Context, id uint, actor util.Actor, requestID string) (dto.ScenarioDriftResponse, error) {
	scenario, err := s.scenarios.GetByID(ctx, id, false)
	if err != nil {
		return dto.ScenarioDriftResponse{}, util.NotFound("rollover scenario")
	}
	report, err := s.buildDriftReport(ctx, scenario)
	if err != nil {
		return dto.ScenarioDriftResponse{}, err
	}
	historical := scenario.Historical
	if report.Drifted && scenario.ScenarioState == string(constants.ScenarioVerified) && !scenario.Historical {
		now := s.now()
		err = s.transactions.WithinTransaction(ctx, func(txCtx context.Context) error {
			marked, markErr := s.scenarios.MarkHistorical(txCtx, id, now)
			if markErr != nil {
				return util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to flag historical scenario", markErr)
			}
			if !marked {
				return nil
			}
			historical = true
			after := scenario
			after.Historical = true
			after.HistoricalAt = &now
			return recordAudit(txCtx, s.audits, actor, requestID, "rollover_scenario", id, "mark_historical", scenario, after, scenario.InputHash, scenario.AlgorithmVersion, &scenario.SimulationTime, 0, "independently verified snapshot retained as historical record after asset drift")
		})
		if err != nil {
			return dto.ScenarioDriftResponse{}, err
		}
	}
	return driftResponse(scenario, report, historical), nil
}

// Refreeze rebuilds the frozen snapshot from the current assets, clears the old
// simulation result, and returns the scenario to draft. Verified historical
// scenarios are immutable and must be cloned instead.
func (s *RolloverScenarioService) Refreeze(ctx context.Context, id uint, actor util.Actor, requestID string) (dto.RolloverScenarioResponse, error) {
	scenario, err := s.scenarios.GetByID(ctx, id, false)
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.NotFound("rollover scenario")
	}
	if err := requireScenarioOwnership(actor, scenario); err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	if scenario.ScenarioState == string(constants.ScenarioVerified) || scenario.Historical {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeStateTransition, "independently verified scenarios are retained as historical records and cannot be refrozen")
	}
	if scenario.ScenarioState == string(constants.ScenarioExecuting) || scenario.ScenarioState == string(constants.ScenarioRollback) {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeStateTransition, "scenarios in "+scenario.ScenarioState+" state cannot be refrozen")
	}
	candidateIDs, err := decodeUintList(scenario.CandidateChainIDs)
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusUnprocessableEntity, util.CodeValidation, "frozen candidate chains are invalid", err)
	}
	currentSnapshot, availableCandidateIDs, err := s.currentSnapshot(ctx, scenario, candidateIDs)
	if err != nil {
		return dto.RolloverScenarioResponse{}, err
	}
	if len(availableCandidateIDs) == 0 {
		return dto.RolloverScenarioResponse{}, util.NewError(http.StatusConflict, util.CodeStateTransition, "every candidate chain was removed; edit the scenario candidates before refreezing")
	}
	inputHash, err := currentSnapshot.Hash()
	if err != nil {
		return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to hash refrozen input", err)
	}
	snapshotJSON, _ := currentSnapshot.Canonical()
	candidateJSON, _ := encode(availableCandidateIDs)
	before := scenario
	updates := map[string]any{
		"input_hash":             inputHash,
		"input_snapshot":         snapshotJSON,
		"candidate_chain_ids":    candidateJSON,
		"affected_services_json": "[]",
		"broken_paths_json":      "[]",
		"path_evidence_json":     "[]",
		"explanation":            "Inputs were refrozen from the current assets; prior simulation results were cleared.",
		"duration_ms":            0,
		"replay_verified":        false,
		"idempotency_key":        nil,
		"rollback_record":        "",
	}
	err = s.transactions.WithinTransaction(ctx, func(txCtx context.Context) error {
		changed, refreezeErr := s.scenarios.Refreeze(txCtx, id, []string{string(constants.ScenarioDraft), string(constants.ScenarioSimulated), string(constants.ScenarioReady)}, updates)
		if refreezeErr != nil {
			return refreezeErr
		}
		if !changed {
			return util.NewError(http.StatusConflict, util.CodeConflict, "scenario state changed concurrently")
		}
		after := scenario
		after.ScenarioState = string(constants.ScenarioDraft)
		after.InputHash = inputHash
		after.InputSnapshot = snapshotJSON
		after.CandidateChainIDs = candidateJSON
		after.AffectedServicesJSON = "[]"
		after.BrokenPathsJSON = "[]"
		after.PathEvidenceJSON = "[]"
		after.Explanation = updates["explanation"].(string)
		after.DurationMS = 0
		after.ReplayVerified = false
		after.IdempotencyKey = ""
		after.RollbackRecord = ""
		after.Historical = false
		after.HistoricalAt = nil
		return recordAudit(txCtx, s.audits, actor, requestID, "rollover_scenario", id, "refreeze", before, after, inputHash, algorithm.Version, &scenario.SimulationTime, 0, "refroze current assets and cleared prior simulation results")
	})
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return dto.RolloverScenarioResponse{}, util.WrapError(http.StatusConflict, util.CodeConflict, "the refrozen inputs already belong to another scenario", err)
		}
		return dto.RolloverScenarioResponse{}, err
	}
	return s.Get(ctx, id)
}

// ensureNoDrift blocks the ready -> executing drill-start transition whenever
// the frozen inputs no longer match the current assets.
func (s *RolloverScenarioService) ensureNoDrift(ctx context.Context, scenario model.RolloverScenario) error {
	report, err := s.buildDriftReport(ctx, scenario)
	if err != nil {
		return err
	}
	if report.Drifted {
		return util.NewError(http.StatusConflict, util.CodeSnapshotDrift, driftConflictMessage(report.Changes))
	}
	return nil
}

func (s *RolloverScenarioService) buildDriftReport(ctx context.Context, scenario model.RolloverScenario) (algorithm.DriftReport, error) {
	frozen, err := algorithm.DecodeSnapshot(scenario.InputSnapshot)
	if err != nil {
		return algorithm.DriftReport{}, util.WrapError(http.StatusUnprocessableEntity, util.CodeValidation, "frozen scenario snapshot is invalid", err)
	}
	candidateIDs, err := decodeUintList(scenario.CandidateChainIDs)
	if err != nil {
		return algorithm.DriftReport{}, util.WrapError(http.StatusUnprocessableEntity, util.CodeValidation, "frozen candidate chains are invalid", err)
	}
	current, _, err := s.currentSnapshot(ctx, scenario, candidateIDs)
	if err != nil {
		return algorithm.DriftReport{}, err
	}
	return algorithm.DetectDrift(frozen, current, s.now()), nil
}

func (s *RolloverScenarioService) currentSnapshot(ctx context.Context, scenario model.RolloverScenario, candidateIDs []uint) (algorithm.Snapshot, []uint, error) {
	anchors, _, err := s.anchors.List(ctx, dto.TrustAnchorQuery{Page: 1, PageSize: 200})
	if err != nil {
		return algorithm.Snapshot{}, nil, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to load current trust anchors", err)
	}
	chains, _, err := s.chains.List(ctx, dto.CertificateChainQuery{Page: 1, PageSize: 200})
	if err != nil {
		return algorithm.Snapshot{}, nil, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to load current certificate chains", err)
	}
	services, err := s.services.All(ctx)
	if err != nil {
		return algorithm.Snapshot{}, nil, util.WrapError(http.StatusInternalServerError, util.CodeInternal, "unable to load current dependency graph", err)
	}
	existingChains := map[uint]bool{}
	for _, chain := range chains {
		existingChains[chain.ID] = true
	}
	availableCandidateIDs := make([]uint, 0, len(candidateIDs))
	for _, id := range candidateIDs {
		if existingChains[id] {
			availableCandidateIDs = append(availableCandidateIDs, id)
		}
	}
	snapshot, err := buildSnapshot(scenario.Name, scenario.OldAnchorID, scenario.NewAnchorID, scenario.OverlapStart, scenario.OverlapEnd, scenario.SimulationTime, availableCandidateIDs, anchors, chains, services)
	if err != nil {
		return algorithm.Snapshot{}, nil, util.WrapError(http.StatusUnprocessableEntity, util.CodeValidation, "current rollover assets are invalid: "+err.Error(), err)
	}
	return snapshot, availableCandidateIDs, nil
}

func driftResponse(scenario model.RolloverScenario, report algorithm.DriftReport, historical bool) dto.ScenarioDriftResponse {
	changes := make([]dto.ScenarioDriftChange, 0, len(report.Changes))
	for _, change := range report.Changes {
		changes = append(changes, dto.ScenarioDriftChange{EntityType: change.EntityType, EntityID: change.EntityID, EntityCode: change.EntityCode, Kind: change.Kind, Fields: change.Fields, Before: change.Before, After: change.After})
	}
	fieldChanges := make([]dto.ScenarioDriftFieldChange, 0, len(report.FieldChanges))
	for _, field := range report.FieldChanges {
		fieldChanges = append(fieldChanges, dto.ScenarioDriftFieldChange{Field: field.Field, Before: field.Before, After: field.After})
	}
	blocked := ""
	if report.Drifted && scenario.ScenarioState == string(constants.ScenarioReady) {
		blocked = "start_execution"
	}
	return dto.ScenarioDriftResponse{ScenarioID: scenario.ID, ScenarioState: scenario.ScenarioState, Historical: historical, Drifted: report.Drifted, Changes: changes, FieldChanges: fieldChanges, CheckedAt: report.CheckedAt, FrozenHash: report.FrozenHash, CurrentHash: report.CurrentHash, BlockedAction: blocked}
}

func driftConflictMessage(changes []algorithm.Change) string {
	anchors, chains, services := 0, 0, 0
	for _, change := range changes {
		switch change.EntityType {
		case "trust_anchor":
			anchors++
		case "certificate_chain":
			chains++
		case "dependent_service":
			services++
		}
	}
	parts := []string{}
	if anchors > 0 {
		parts = append(parts, fmt.Sprintf("%d trust anchor change(s)", anchors))
	}
	if chains > 0 {
		parts = append(parts, fmt.Sprintf("%d certificate chain change(s)", chains))
	}
	if services > 0 {
		parts = append(parts, fmt.Sprintf("%d dependent service change(s)", services))
	}
	return "frozen assets no longer match the current inventory (" + strings.Join(parts, ", ") + "); review the drift report and refreeze before recording drill start"
}

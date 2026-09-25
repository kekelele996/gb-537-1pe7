package algorithm

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ChangeKind describes how a frozen entity differs from the current asset.
const (
	ChangeKindAdded    = "added"
	ChangeKindRemoved  = "removed"
	ChangeKindModified = "modified"
)

// Change is a single drift item between a frozen snapshot and the current assets.
type Change struct {
	EntityType string   `json:"entity_type"`
	EntityID   uint     `json:"entity_id"`
	EntityCode string   `json:"entity_code"`
	Kind       string   `json:"kind"`
	Fields     []string `json:"fields"`
	Before     string   `json:"before,omitempty"`
	After      string   `json:"after,omitempty"`
}

// FieldChange captures one modified field for the UI detail view.
type FieldChange struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// DriftReport compares a frozen snapshot against the assets currently registered.
type DriftReport struct {
	Drifted      bool          `json:"drifted"`
	Changes      []Change      `json:"changes"`
	FieldChanges []FieldChange `json:"field_changes"`
	CheckedAt    time.Time     `json:"checked_at"`
	FrozenHash   string        `json:"frozen_hash"`
	CurrentHash  string        `json:"current_hash"`
}

type anchorFields struct {
	Code      string
	State     string
	NotBefore time.Time
	NotAfter  time.Time
	Revoked   bool
}

type chainFields struct {
	Code            string
	AnchorID        uint
	LeafSubject     string
	ValidFrom       time.Time
	ValidTo         time.Time
	State           string
	ValidationValid bool
}

type serviceFields struct {
	Code           string
	ChainID        uint
	TrustAnchorIDs []uint
	DependencyIDs  []uint
	Criticality    string
	State          string
}

// DetectDrift compares the frozen snapshot against the snapshot built from the
// current assets and reports every added, removed, or modified entity.
func DetectDrift(frozen, current Snapshot, checkedAt time.Time) DriftReport {
	changes := []Change{}
	fieldChanges := []FieldChange{}

	changes = append(changes, diffAnchors(frozen.Anchors, current.Anchors, &fieldChanges)...)
	changes = append(changes, diffChains(frozen.Chains, current.Chains, &fieldChanges)...)
	changes = append(changes, diffServices(frozen.Services, current.Services, &fieldChanges)...)

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].EntityType != changes[j].EntityType {
			return changes[i].EntityType < changes[j].EntityType
		}
		if changes[i].EntityID != changes[j].EntityID {
			return changes[i].EntityID < changes[j].EntityID
		}
		return changes[i].Kind < changes[j].Kind
	})
	frozenHash, _ := frozen.Hash()
	currentHash, _ := current.Hash()
	return DriftReport{Drifted: len(changes) > 0, Changes: changes, FieldChanges: fieldChanges, CheckedAt: checkedAt.UTC(), FrozenHash: frozenHash, CurrentHash: currentHash}
}

func diffAnchors(frozen, current []AnchorSnapshot, fieldChanges *[]FieldChange) []Change {
	frozenMap := map[uint]AnchorSnapshot{}
	currentMap := map[uint]AnchorSnapshot{}
	for _, anchor := range frozen {
		frozenMap[anchor.ID] = anchor
	}
	for _, anchor := range current {
		currentMap[anchor.ID] = anchor
	}
	changes := []Change{}
	for id, frozenAnchor := range frozenMap {
		currentAnchor, ok := currentMap[id]
		if !ok {
			changes = append(changes, Change{EntityType: "trust_anchor", EntityID: id, EntityCode: frozenAnchor.Code, Kind: ChangeKindRemoved, Fields: []string{"existence"}})
			continue
		}
		before := anchorFieldsOf(frozenAnchor)
		after := anchorFieldsOf(currentAnchor)
		fields := []string{}
		if before.State != after.State {
			fields = append(fields, "state")
		}
		if before.Revoked != after.Revoked {
			fields = append(fields, "revoked")
		}
		if !before.NotBefore.Equal(after.NotBefore) {
			fields = append(fields, "not_before")
		}
		if !before.NotAfter.Equal(after.NotAfter) {
			fields = append(fields, "not_after")
		}
		if len(fields) > 0 {
			changes = append(changes, Change{EntityType: "trust_anchor", EntityID: id, EntityCode: currentAnchor.Code, Kind: ChangeKindModified, Fields: fields})
			appendFieldChanges(fieldChanges, "trust_anchor", id, currentAnchor.Code, fields,
				map[string][2]string{
					"state":      {before.State, after.State},
					"revoked":    {fmt.Sprint(before.Revoked), fmt.Sprint(after.Revoked)},
					"not_before": {formatTime(before.NotBefore), formatTime(after.NotBefore)},
					"not_after":  {formatTime(before.NotAfter), formatTime(after.NotAfter)},
				})
		}
	}
	for id, currentAnchor := range currentMap {
		if _, ok := frozenMap[id]; ok {
			continue
		}
		changes = append(changes, Change{EntityType: "trust_anchor", EntityID: id, EntityCode: currentAnchor.Code, Kind: ChangeKindAdded, Fields: []string{"existence"}})
	}
	return changes
}

func diffChains(frozen, current []ChainSnapshot, fieldChanges *[]FieldChange) []Change {
	frozenMap := map[uint]ChainSnapshot{}
	currentMap := map[uint]ChainSnapshot{}
	for _, chain := range frozen {
		frozenMap[chain.ID] = chain
	}
	for _, chain := range current {
		currentMap[chain.ID] = chain
	}
	changes := []Change{}
	for id, frozenChain := range frozenMap {
		currentChain, ok := currentMap[id]
		if !ok {
			changes = append(changes, Change{EntityType: "certificate_chain", EntityID: id, EntityCode: frozenChain.Code, Kind: ChangeKindRemoved, Fields: []string{"existence"}})
			continue
		}
		before := chainFieldsOf(frozenChain)
		after := chainFieldsOf(currentChain)
		fields := []string{}
		if before.AnchorID != after.AnchorID {
			fields = append(fields, "anchor_id")
		}
		if before.LeafSubject != after.LeafSubject {
			fields = append(fields, "leaf_subject")
		}
		if before.State != after.State {
			fields = append(fields, "state")
		}
		if before.ValidationValid != after.ValidationValid {
			fields = append(fields, "validation_valid")
		}
		if !before.ValidFrom.Equal(after.ValidFrom) {
			fields = append(fields, "valid_from")
		}
		if !before.ValidTo.Equal(after.ValidTo) {
			fields = append(fields, "valid_to")
		}
		if len(fields) > 0 {
			changes = append(changes, Change{EntityType: "certificate_chain", EntityID: id, EntityCode: currentChain.Code, Kind: ChangeKindModified, Fields: fields})
			appendFieldChanges(fieldChanges, "certificate_chain", id, currentChain.Code, fields,
				map[string][2]string{
					"anchor_id":        {fmt.Sprint(before.AnchorID), fmt.Sprint(after.AnchorID)},
					"leaf_subject":     {before.LeafSubject, after.LeafSubject},
					"state":            {before.State, after.State},
					"validation_valid": {fmt.Sprint(before.ValidationValid), fmt.Sprint(after.ValidationValid)},
					"valid_from":       {formatTime(before.ValidFrom), formatTime(after.ValidFrom)},
					"valid_to":         {formatTime(before.ValidTo), formatTime(after.ValidTo)},
				})
		}
	}
	for id, currentChain := range currentMap {
		if _, ok := frozenMap[id]; ok {
			continue
		}
		changes = append(changes, Change{EntityType: "certificate_chain", EntityID: id, EntityCode: currentChain.Code, Kind: ChangeKindAdded, Fields: []string{"existence"}})
	}
	return changes
}

func diffServices(frozen, current []ServiceSnapshot, fieldChanges *[]FieldChange) []Change {
	frozenMap := map[uint]ServiceSnapshot{}
	currentMap := map[uint]ServiceSnapshot{}
	for _, service := range frozen {
		frozenMap[service.ID] = service
	}
	for _, service := range current {
		currentMap[service.ID] = service
	}
	changes := []Change{}
	for id, frozenService := range frozenMap {
		currentService, ok := currentMap[id]
		if !ok {
			changes = append(changes, Change{EntityType: "dependent_service", EntityID: id, EntityCode: frozenService.Code, Kind: ChangeKindRemoved, Fields: []string{"existence"}})
			continue
		}
		before := serviceFieldsOf(frozenService)
		after := serviceFieldsOf(currentService)
		fields := []string{}
		if before.ChainID != after.ChainID {
			fields = append(fields, "chain_id")
		}
		if !sameUintSet(before.TrustAnchorIDs, after.TrustAnchorIDs) {
			fields = append(fields, "client_trust_refs")
		}
		if !sameUintSet(before.DependencyIDs, after.DependencyIDs) {
			fields = append(fields, "dependency_edges")
		}
		if before.Criticality != after.Criticality {
			fields = append(fields, "criticality")
		}
		if before.State != after.State {
			fields = append(fields, "state")
		}
		if len(fields) > 0 {
			changes = append(changes, Change{EntityType: "dependent_service", EntityID: id, EntityCode: currentService.Code, Kind: ChangeKindModified, Fields: fields})
			appendFieldChanges(fieldChanges, "dependent_service", id, currentService.Code, fields,
				map[string][2]string{
					"chain_id":          {fmt.Sprint(before.ChainID), fmt.Sprint(after.ChainID)},
					"client_trust_refs": {formatUintSet(before.TrustAnchorIDs), formatUintSet(after.TrustAnchorIDs)},
					"dependency_edges":  {formatUintSet(before.DependencyIDs), formatUintSet(after.DependencyIDs)},
					"criticality":       {before.Criticality, after.Criticality},
					"state":             {before.State, after.State},
				})
		}
	}
	for id, currentService := range currentMap {
		if _, ok := frozenMap[id]; ok {
			continue
		}
		changes = append(changes, Change{EntityType: "dependent_service", EntityID: id, EntityCode: currentService.Code, Kind: ChangeKindAdded, Fields: []string{"existence"}})
	}
	return changes
}

func appendFieldChanges(fieldChanges *[]FieldChange, entityType string, entityID uint, entityCode string, fields []string, values map[string][2]string) {
	for _, field := range fields {
		pair := values[field]
		*fieldChanges = append(*fieldChanges, FieldChange{Field: entityType + "#" + fmt.Sprint(entityID) + " " + entityCode + "." + field, Before: pair[0], After: pair[1]})
	}
}

func anchorFieldsOf(anchor AnchorSnapshot) anchorFields {
	return anchorFields{Code: anchor.Code, State: anchor.State, NotBefore: anchor.NotBefore.UTC(), NotAfter: anchor.NotAfter.UTC(), Revoked: anchor.Revoked}
}
func chainFieldsOf(chain ChainSnapshot) chainFields {
	return chainFields{Code: chain.Code, AnchorID: chain.AnchorID, LeafSubject: chain.LeafSubject, ValidFrom: chain.ValidFrom.UTC(), ValidTo: chain.ValidTo.UTC(), State: chain.State, ValidationValid: chain.ValidationValid}
}
func serviceFieldsOf(service ServiceSnapshot) serviceFields {
	return serviceFields{Code: service.Code, ChainID: service.ChainID, TrustAnchorIDs: sortedUnique(append([]uint{}, service.TrustAnchorIDs...)), DependencyIDs: sortedUnique(append([]uint{}, service.DependencyIDs...)), Criticality: service.Criticality, State: service.State}
}

func sameUintSet(left, right []uint) bool {
	if len(left) != len(right) {
		return false
	}
	seen := map[uint]bool{}
	for _, value := range left {
		seen[value] = true
	}
	for _, value := range right {
		if !seen[value] {
			return false
		}
	}
	return true
}

func formatUintSet(values []uint) string {
	if len(values) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprint(value))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339) }

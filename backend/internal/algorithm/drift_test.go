package algorithm

import (
	"strings"
	"testing"
	"time"
)

func driftFixture() (time.Time, Snapshot) {
	now := time.Date(2032, 4, 2, 8, 0, 0, 0, time.UTC)
	snapshot := NewSnapshot(
		ScenarioConfig{Name: "drift", OldAnchorID: 1, NewAnchorID: 2, OverlapStart: now.Add(time.Hour), OverlapEnd: now.Add(2 * time.Hour), CandidateChainIDs: []uint{1}, SimulationTime: now.Add(90 * time.Minute)},
		[]AnchorSnapshot{{ID: 1, Code: "ROOT-OLD", State: "valid", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}, {ID: 2, Code: "ROOT-NEW", State: "valid", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}},
		[]ChainSnapshot{{ID: 1, Code: "CHAIN-A", AnchorID: 1, LeafSubject: "CN=leaf", ValidFrom: now.Add(-time.Hour), ValidTo: now.Add(24 * time.Hour), State: "validated", ValidationValid: true}},
		[]ServiceSnapshot{{ID: 1, Code: "SVC-A", ChainID: 1, TrustAnchorIDs: []uint{1}, DependencyIDs: []uint{2}, Criticality: "high", State: "active"}, {ID: 2, Code: "SVC-B", ChainID: 1, TrustAnchorIDs: []uint{1}, Criticality: "low", State: "active"}},
	)
	return now, snapshot
}

func TestDiffSnapshotsIsEmptyForIdenticalInput(t *testing.T) {
	_, frozen := driftFixture()
	_, current := driftFixture()
	if items := DiffSnapshots(frozen, current); len(items) != 0 {
		t.Fatalf("expected no drift, got %#v", items)
	}
}

func TestDiffSnapshotsReportsModifiedAnchor(t *testing.T) {
	now, frozen := driftFixture()
	_, current := driftFixture()
	current.Anchors[0].State = "revoked"
	current.Anchors[0].Revoked = true
	current.Anchors[0].NotAfter = now.Add(time.Hour)
	items := DiffSnapshots(frozen, current)
	if len(items) != 1 {
		t.Fatalf("expected one drift item, got %#v", items)
	}
	item := items[0]
	if item.EntityType != DriftAnchor || item.EntityID != 1 || item.Change != DriftModified || item.Code != "ROOT-OLD" {
		t.Fatalf("unexpected drift item %#v", item)
	}
	for _, fragment := range []string{"certificate_state valid -> revoked", "revoked false -> true", "not_after"} {
		if !containsText(item.Detail, fragment) {
			t.Fatalf("detail %q misses %q", item.Detail, fragment)
		}
	}
}

func TestDiffSnapshotsReportsAddedRemovedAndModifiedEntities(t *testing.T) {
	_, frozen := driftFixture()
	_, current := driftFixture()
	current.Chains = current.Chains[:0]                                                                                                 // chain removed
	current.Services[0].DependencyIDs = []uint{}                                                                                        // service modified
	current.Services = append(current.Services, ServiceSnapshot{ID: 3, Code: "SVC-C", ChainID: 1, Criticality: "low", State: "active"}) // service added
	current.AlgorithmVersion = "trust-path-window-v9.9.9"                                                                               // algorithm modified
	items := DiffSnapshots(frozen, current)
	if len(items) != 4 {
		t.Fatalf("expected four drift items, got %#v", items)
	}
	assertDrift(t, items[0], DriftAlgorithm, 0, DriftModified)
	assertDrift(t, items[1], DriftChain, 1, DriftRemoved)
	assertDrift(t, items[2], DriftService, 1, DriftModified)
	assertDrift(t, items[3], DriftService, 3, DriftAdded)
	if !containsText(items[2].Detail, "dependency edges [2] -> []") {
		t.Fatalf("unexpected service detail %q", items[2].Detail)
	}
}

func TestDiffSnapshotsReportsServiceTrustAndChainChanges(t *testing.T) {
	_, frozen := driftFixture()
	_, current := driftFixture()
	current.Services[1].TrustAnchorIDs = []uint{1, 2}
	current.Services[1].ChainID = 9
	current.Services[1].State = "inactive"
	current.Chains[0].State = "deprecated"
	items := DiffSnapshots(frozen, current)
	if len(items) != 2 {
		t.Fatalf("expected two drift items, got %#v", items)
	}
	assertDrift(t, items[0], DriftChain, 1, DriftModified)
	assertDrift(t, items[1], DriftService, 2, DriftModified)
	for _, fragment := range []string{"chain_id 1 -> 9", "client trust refs [1] -> [1,2]", "service_state active -> inactive"} {
		if !containsText(items[1].Detail, fragment) {
			t.Fatalf("detail %q misses %q", items[1].Detail, fragment)
		}
	}
}

func assertDrift(t *testing.T, item DriftItem, entityType string, id uint, change string) {
	t.Helper()
	if item.EntityType != entityType || item.EntityID != id || item.Change != change {
		t.Fatalf("unexpected drift item %#v, want %s/%d/%s", item, entityType, id, change)
	}
}

func containsText(value, fragment string) bool { return strings.Contains(value, fragment) }

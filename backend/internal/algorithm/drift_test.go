package algorithm

import (
	"testing"
	"time"
)

func driftPair(t *testing.T) (Snapshot, Snapshot) {
	t.Helper()
	frozen := syntheticSnapshot()
	current := syntheticSnapshot()
	return frozen, current
}

func TestDetectDriftCleanWhenAssetsUnchanged(t *testing.T) {
	frozen, current := driftPair(t)
	// reorder current entities and trust sets to prove comparison is set based
	current.Anchors[0], current.Anchors[1] = current.Anchors[1], current.Anchors[0]
	current.Services[0].TrustAnchorIDs = []uint{2, 1}
	current = NewSnapshot(current.Config, current.Anchors, current.Chains, current.Services)

	report := DetectDrift(frozen, current, time.Now())
	if report.Drifted {
		t.Fatalf("unchanged assets must not drift, got %+v", report.Changes)
	}
	if report.FrozenHash != report.CurrentHash {
		t.Fatal("canonical hashes should match after normalization")
	}
	if len(report.Changes) != 0 {
		t.Fatalf("expected no changes, got %+v", report.Changes)
	}
}

func TestDetectDriftReportsAnchorChainAndServiceChanges(t *testing.T) {
	frozen, current := driftPair(t)

	// anchor state change
	current.Anchors[0].State = "expired"
	// chain validity change
	for index := range current.Chains {
		if current.Chains[index].ID == 10 {
			current.Chains[index].State = "deprecated"
		}
	}
	// service trust-set change
	for index := range current.Services {
		if current.Services[index].ID == 102 {
			current.Services[index].TrustAnchorIDs = []uint{1, 2}
		}
	}

	report := DetectDrift(frozen, current, time.Now())
	if !report.Drifted {
		t.Fatal("expected drift")
	}
	counts := map[string]map[string]int{}
	for _, change := range report.Changes {
		if counts[change.EntityType] == nil {
			counts[change.EntityType] = map[string]int{}
		}
		counts[change.EntityType][change.Kind]++
	}
	if counts["trust_anchor"]["modified"] != 1 || counts["certificate_chain"]["modified"] != 1 || counts["dependent_service"]["modified"] != 1 {
		t.Fatalf("unexpected change counts: %+v", counts)
	}
}

func TestDetectDriftReportsAddedAndRemovedEntities(t *testing.T) {
	frozen, current := driftPair(t)
	// new anchor registered after the freeze
	current.Anchors = append(current.Anchors, AnchorSnapshot{ID: 9, Code: "future", State: "valid", NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)})
	current = NewSnapshot(current.Config, current.Anchors, current.Chains, current.Services)
	// chain removed after the freeze
	prunedChains := []ChainSnapshot{}
	for _, chain := range current.Chains {
		if chain.ID != 11 {
			prunedChains = append(prunedChains, chain)
		}
	}
	current.Chains = prunedChains
	current = NewSnapshot(current.Config, current.Anchors, current.Chains, current.Services)
	// service removed after the freeze
	prunedServices := []ServiceSnapshot{}
	for _, service := range current.Services {
		if service.ID != 102 {
			prunedServices = append(prunedServices, service)
		}
	}
	current.Services = prunedServices
	current = NewSnapshot(current.Config, current.Anchors, current.Chains, current.Services)

	report := DetectDrift(frozen, current, time.Now())
	if !report.Drifted {
		t.Fatal("expected drift for added/removed entities")
	}
	kinds := map[string]string{}
	for _, change := range report.Changes {
		kinds[change.EntityType+"/"+change.EntityCode] = change.Kind
	}
	if kinds["trust_anchor/future"] != ChangeKindAdded {
		t.Fatalf("missing added anchor: %+v", kinds)
	}
	if kinds["certificate_chain/new-chain"] != ChangeKindRemoved {
		t.Fatalf("missing removed chain: %+v", kinds)
	}
	if kinds["dependent_service/client"] != ChangeKindRemoved {
		t.Fatalf("missing removed service: %+v", kinds)
	}
}

package manifest

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSessionFinalizationContract(t *testing.T) {
	data, err := os.ReadFile("../../../tests/session_finalization_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name     string `json:"name"`
		Manifest string `json:"manifest"`
		Expected *bool  `json:"expected"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range cases {
		t.Run(fixture.Name, func(t *testing.T) {
			parsed, err := LoadManifest(writeTmp(t, fixture.Manifest))
			if fixture.Expected == nil {
				if err == nil {
					t.Fatal("non-boolean finalizer was accepted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if parsed.Session.Commands["finish"].Finalize != *fixture.Expected {
					t.Fatal("finalizer authority was not preserved")
				}
			}
		})
	}
}

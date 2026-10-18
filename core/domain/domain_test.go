package domain

import "testing"

func TestStateMachineValidTransitions(t *testing.T) {
	valid := [][2]State{
		{StatePending, StateRunning}, {StateRunning, StatePaused},
		{StatePaused, StateRunning}, {StateRunning, StateVerifying},
		{StateVerifying, StateCompleted}, {StateFailed, StatePending},
	}
	for _, p := range valid {
		if err := ValidateTransition(p[0], p[1]); err != nil {
			t.Errorf("transição %s->%s deveria ser válida: %v", p[0], p[1], err)
		}
	}
}

func TestStateMachineInvalidTransitions(t *testing.T) {
	invalid := [][2]State{
		{StateCompleted, StateRunning}, // terminal
		{StateCancelled, StatePending}, // terminal
		{StatePending, StateCompleted}, // salto proibido
		{StatePaused, StateVerifying},  // tem de correr primeiro
		{StateRunning, StateCompleted}, // exige Verifying intermediário
	}
	for _, p := range invalid {
		if err := ValidateTransition(p[0], p[1]); err == nil {
			t.Errorf("transição %s->%s deveria ser INVÁLIDA", p[0], p[1])
		}
	}
}

func TestPolicyBlocksCompletedWithoutVerify(t *testing.T) {
	task := &DownloadTask{ID: "t1", State: StateRunning, Policy: DownloadPolicy{RequireIntegrity: IntegritySHA256}}
	if err := task.Transition(StateCompleted); err == nil {
		t.Fatal("política com integridade exigida NÃO pode ir Running->Completed sem Verifying")
	}
	if err := task.Transition(StateVerifying); err != nil {
		t.Fatalf("Running->Verifying deve ser válido: %v", err)
	}
	if err := task.Transition(StateCompleted); err != nil {
		t.Fatalf("Verifying->Completed deve ser válido: %v", err)
	}
}

func TestErrorRedactionKeepsQueryOut(t *testing.T) {
	src := DownloadSource{Kind: SourceHTTP, URL: "https://cdn.example.com/f/file.zip?token=SEGREDO&sig=abc"}
	r := src.Redacted()
	if contains(r, "SEGREDO") || contains(r, "sig=") {
		t.Errorf("redação vazou query string: %s", r)
	}
	if !contains(r, "cdn.example.com/f/file.zip") {
		t.Errorf("redação deveria manter host+path: %s", r)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

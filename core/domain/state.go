package domain

import "fmt"

// State é o estado de uma tarefa de download. Os valores são instáveis
// (máquina de estados) e estáveis (pontos de repouso persistentes).
type State int

const (
	StatePending   State = iota // na fila, ainda não iniciado
	StateRunning                // a transferir
	StatePaused                 // pausado pelo utilizador
	StateVerifying              // verificação de integridade final em curso
	StateCompleted              // concluído E verificado conforme política
	StateFailed                 // falha terminal (não retomar automaticamente)
	StateCancelled              // cancelado pelo utilizador
)

func (s State) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateRunning:
		return "running"
	case StatePaused:
		return "paused"
	case StateVerifying:
		return "verifying"
	case StateCompleted:
		return "completed"
	case StateFailed:
		return "failed"
	case StateCancelled:
		return "cancelled"
	}
	return fmt.Sprintf("state(%d)", int(s))
}

// Terminal reporta se o estado é final (sem transições possíveis).
func (s State) Terminal() bool { return s == StateCompleted || s == StateCancelled }

// transitions define EXPLICITAMENTE as arestas válidas da máquina de estados.
// Qualquer outra transição deve ser recusada — por exemplo, nunca se chega a
// Completed sem passar por Verifying quando a política exige verificação final.
var transitions = map[State][]State{
	StatePending:   {StateRunning, StateCancelled, StateFailed},
	StateRunning:   {StatePaused, StateVerifying, StateFailed, StateCancelled},
	StatePaused:    {StateRunning, StateCancelled},
	StateVerifying: {StateCompleted, StateFailed, StatePaused, StateCancelled},
	StateCompleted: nil,
	StateFailed:    {StatePending, StateCancelled}, // retry explícito do utilizador
	StateCancelled: nil,
}

// CanTransitionTo valida uma transição individual.
func (s State) CanTransitionTo(next State) bool {
	for _, t := range transitions[s] {
		if t == next {
			return true
		}
	}
	return false
}

// ValidateTransition devolve erro descritivo se a transição for inválida.
func ValidateTransition(from, to State) error {
	if !from.CanTransitionTo(to) {
		return fmt.Errorf("domain: transição de estado inválida: %s -> %s", from, to)
	}
	return nil
}

package config

import (
	"encoding/json"
	"testing"
)

func TestDefaultRoundTrip(t *testing.T) {
	b, _ := json.Marshal(Default())
	c, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if c.Queue.MaxConcurrentTasks != 3 || c.Commercial.PriceBRLCents != 800 {
		t.Fatalf("defaults perdidos: %+v", c)
	}
}

func TestFutureSchemaRejectedExplicitly(t *testing.T) {
	_, err := Parse([]byte(`{"schema_version": 99}`))
	if err == nil {
		t.Fatal("config de versão futura deve ser recusada com erro claro, não interpretada às cegas")
	}
}

func TestOldSchemaRequiresMigration(t *testing.T) {
	_, err := Parse([]byte(`{"schema_version": 0}`))
	if err == nil {
		t.Fatal("versão antiga deve exigir migração explícita")
	}
}

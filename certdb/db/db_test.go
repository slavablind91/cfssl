package db

import (
	"reflect"
	"testing"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/dbconf"
)

func TestNewAccessor(t *testing.T) {
	type args struct {
		cfg *dbconf.DBConfig
	}
	tests := []struct {
		name    string
		args    args
		want    certdb.Accessor
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAccessor(tt.args.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAccessor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAccessor() = %v, want %v", got, tt.want)
			}
		})
	}
}

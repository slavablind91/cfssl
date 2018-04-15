package redis

import (
	"errors"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/go-redis/redis"
)

func getTestAccessor() *Accessor {
	return &Accessor{db: redis.NewClient(&redis.Options{Addr: "localhost:6379"})}
}

func hasCerts(a []certdb.CertificateRecord) bool {
	return (len(a) > 0)
}

func hasOCSP(a []certdb.OCSPRecord) bool {
	return (len(a) > 0)
}

func Test_wrapError(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "Test wrapError",
			args:    args{errors.New("test")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := wrapError(tt.args.err); (err != nil) != tt.wantErr {
				t.Errorf("wrapError() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_certKeyFromCertRec(t *testing.T) {
	type args struct {
		cr *certdb.CertificateRecord
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test certKeyFromCertRec",
			args: args{&certdb.CertificateRecord{
				Serial: "1",
				AKI:    "2",
			}},
			want: "cert:1:2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := certKeyFromCertRec(tt.args.cr); got != tt.want {
				t.Errorf("certKeyFromCertRec() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_certKeyFromSerialAKI(t *testing.T) {
	type args struct {
		serial string
		aki    string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test certKeyFromSerialAKI",
			args: args{serial: "1", aki: "2"},
			want: "cert:1:2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := certKeyFromSerialAKI(tt.args.serial, tt.args.aki); got != tt.want {
				t.Errorf("certKeyFromSerialAKI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ocspKeyFromOCSPRec(t *testing.T) {
	type args struct {
		or *certdb.OCSPRecord
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test ocspKeyFromOCSPRec",
			args: args{&certdb.OCSPRecord{
				Serial: "1",
				AKI:    "2",
			}},
			want: "ocsp:1:2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ocspKeyFromOCSPRec(tt.args.or); got != tt.want {
				t.Errorf("ocspKeyFromOCSPRec() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ocspKeyFromSerialAKI(t *testing.T) {
	type args struct {
		serial string
		aki    string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test ocspKeyFromSerialAKI",
			args: args{serial: "1", aki: "2"},
			want: "ocsp:1:2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ocspKeyFromSerialAKI(tt.args.serial, tt.args.aki); got != tt.want {
				t.Errorf("ocspKeyFromSerialAKI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccessor_checkDB(t *testing.T) {
	tests := []struct {
		name    string
		a       *Accessor
		wantErr bool
	}{
		{
			name:    "Test checkDB",
			a:       getTestAccessor(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.a.checkDB(); (err != nil) != tt.wantErr {
				t.Errorf("Accessor.checkDB() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccessor_InsertCertificate(t *testing.T) {
	type args struct {
		cr certdb.CertificateRecord
	}
	tests := []struct {
		name    string
		a       *Accessor
		args    args
		wantErr bool
	}{
		{
			name:    "Test InsertCertificate unexpired",
			a:       getTestAccessor(),
			args:    args{certdb.CertificateRecord{Serial: "0", Expiry: time.Now().Add(time.Hour)}},
			wantErr: false,
		},
		{
			name:    "Test InsertCertificate expired",
			a:       getTestAccessor(),
			args:    args{certdb.CertificateRecord{Serial: "1"}},
			wantErr: false,
		},
		{
			name:    "Test InsertCertificate revoked",
			a:       getTestAccessor(),
			args:    args{certdb.CertificateRecord{Serial: "2", Status: "revoked"}},
			wantErr: false,
		},
		{
			name: "Test InsertCertificate revoked expired",
			a:    getTestAccessor(),
			args: args{certdb.CertificateRecord{
				Serial: "3",
				Expiry: time.Now().Add(time.Hour),
			}},
			wantErr: false,
		},
		{
			name: "Test InsertCertificate revoked unexpired",
			a:    getTestAccessor(),
			args: args{certdb.CertificateRecord{
				Serial: "4",
				Expiry: time.Now().Add(time.Hour),
				Status: "revoked",
			}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.a.InsertCertificate(tt.args.cr); (err != nil) != tt.wantErr {
				t.Errorf("Accessor.InsertCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccessor_GetCertificate(t *testing.T) {
	type args struct {
		serial string
		aki    string
	}
	tests := []struct {
		name    string
		a       *Accessor
		args    args
		want    []certdb.CertificateRecord
		wantErr bool
	}{
		{
			name:    "Test GetCertificate",
			a:       getTestAccessor(),
			args:    args{serial: "1", aki: ""},
			want:    []certdb.CertificateRecord{certdb.CertificateRecord{Serial: "1"}},
			wantErr: false,
		},
		{
			name:    "Test GetCertificate",
			a:       getTestAccessor(),
			args:    args{serial: "111", aki: ""},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.a.GetCertificate(tt.args.serial, tt.args.aki)
			if (err != nil) != tt.wantErr {
				t.Errorf("Accessor.GetCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Accessor.GetCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkUnexpired(t *testing.T) {
	type args struct {
		expiry time.Time
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test checkUnexpired",
			args: args{time.Now().Add(time.Hour).UTC()},
			want: true,
		},
		{
			name: "Test checkUnexpired",
			args: args{time.Now().Add(-time.Hour).UTC()},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Printf("%+v\n", tt)
			if got := checkUnexpired(tt.args.expiry); got != tt.want {
				t.Errorf("checkUnexpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkRevokedUnexpired(t *testing.T) {
	type args struct {
		status string
		expiry time.Time
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test checkRevokedUnexpired",
			args: args{
				status: "revoked",
				expiry: time.Now().Add(time.Hour).UTC(),
			},
			want: true,
		},
		{
			name: "Test checkRevokedUnexpired",
			args: args{
				status: "revoked",
				expiry: time.Now().Add(-time.Hour).UTC(),
			},
			want: false,
		},
		{
			name: "Test checkRevokedUnexpired",
			args: args{
				status: "",
				expiry: time.Now().Add(time.Hour).UTC(),
			},
			want: false,
		},
		{
			name: "Test checkRevokedUnexpired",
			args: args{
				status: "",
				expiry: time.Now().Add(-time.Hour).UTC(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkRevokedUnexpired(tt.args.status, tt.args.expiry); got != tt.want {
				t.Errorf("checkRevokedUnexpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccessor_GetUnexpiredCertificates(t *testing.T) {
	tests := []struct {
		name    string
		a       *Accessor
		wantHas bool
		wantErr bool
	}{
		{
			name:    "Test GetUnexpiredCertificates",
			a:       getTestAccessor(),
			wantHas: true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.a.GetUnexpiredCertificates()
			if (err != nil) != tt.wantErr {
				t.Errorf("Accessor.GetUnexpiredCertificates() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if hasCerts(got) != tt.wantHas {
				t.Errorf("Accessor.GetUnexpiredCertificates() = %v, wantHas %v", len(got), tt.wantHas)
			}
		})
	}
}

func TestAccessor_GetRevokedAndUnexpiredCertificates(t *testing.T) {
	tests := []struct {
		name    string
		a       *Accessor
		wantHas bool
		wantErr bool
	}{
		{
			name:    "Test GetRevokedAndUnexpiredCertificates",
			a:       getTestAccessor(),
			wantHas: true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.a.GetRevokedAndUnexpiredCertificates()
			if (err != nil) != tt.wantErr {
				t.Errorf("Accessor.GetRevokedAndUnexpiredCertificates() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if hasCerts(got) != tt.wantHas {
				t.Errorf("Accessor.GetRevokedAndUnexpiredCertificates() = %v, wantHas %v", len(got), tt.wantHas)
			}
		})
	}
}

func TestAccessor_GetRevokedAndUnexpiredCertificatesByLabel(t *testing.T) {
	type args struct {
		label string
	}
	tests := []struct {
		name    string
		a       *Accessor
		args    args
		wantHas bool
		wantErr bool
	}{
		{
			name:    "Test GetRevokedAndUnexpiredCertificatesByLabel",
			a:       getTestAccessor(),
			args:    args{""},
			wantHas: true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.a.GetRevokedAndUnexpiredCertificatesByLabel(tt.args.label)
			if (err != nil) != tt.wantErr {
				t.Errorf("Accessor.GetRevokedAndUnexpiredCertificatesByLabel() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if hasCerts(got) != tt.wantHas {
				t.Errorf("Accessor.GetRevokedAndUnexpiredCertificatesByLabel() = %v, want %v", got, tt.wantHas)
			}
		})
	}
}

func TestAccessor_RevokeCertificate(t *testing.T) {
	type args struct {
		serial     string
		aki        string
		reasonCode int
	}
	tests := []struct {
		name    string
		a       *Accessor
		args    args
		wantErr bool
	}{
		{
			name:    "Test RevokeCertificate",
			a:       getTestAccessor(),
			args:    args{serial: "0"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.a.RevokeCertificate(tt.args.serial, tt.args.aki, tt.args.reasonCode); (err != nil) != tt.wantErr {
				t.Errorf("Accessor.RevokeCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccessor_InsertOCSP(t *testing.T) {
	type args struct {
		rr certdb.OCSPRecord
	}
	tests := []struct {
		name    string
		a       *Accessor
		args    args
		wantErr bool
	}{
		{
			name:    "Test InsertOCSP",
			a:       getTestAccessor(),
			args:    args{certdb.OCSPRecord{Serial: "0"}},
			wantErr: false,
		},
		{
			name: "Test InsertOCSP",
			a:    getTestAccessor(),
			args: args{certdb.OCSPRecord{
				Serial: "1",
				Expiry: time.Now().UTC().Add(-time.Hour),
			}},
			wantErr: false,
		},
		{
			name: "Test InsertOCSP",
			a:    getTestAccessor(),
			args: args{certdb.OCSPRecord{
				Serial: "2",
				Expiry: time.Now().UTC().Add(time.Hour),
			}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.a.InsertOCSP(tt.args.rr); (err != nil) != tt.wantErr {
				t.Errorf("Accessor.InsertOCSP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccessor_GetOCSP(t *testing.T) {
	type args struct {
		serial string
		aki    string
	}
	tests := []struct {
		name    string
		a       *Accessor
		args    args
		wantHas bool
		wantErr bool
	}{
		{
			name:    "Test GetOCSP",
			a:       getTestAccessor(),
			args:    args{serial: "0"},
			wantHas: true,
			wantErr: false,
		},
		{
			name:    "Test GetOCSP",
			a:       getTestAccessor(),
			args:    args{serial: "111999"},
			wantHas: false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.a.GetOCSP(tt.args.serial, tt.args.aki)
			if (err != nil) != tt.wantErr {
				t.Errorf("Accessor.GetOCSP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if hasOCSP(got) != tt.wantHas {
				t.Errorf("Accessor.GetOCSP() = %v, want %v", got, tt.wantHas)
			}
		})
	}
}

func TestAccessor_GetUnexpiredOCSPs(t *testing.T) {
	tests := []struct {
		name    string
		a       *Accessor
		wantHas bool
		wantErr bool
	}{
		{
			name:    "Test GetUnexpiredOCSPs",
			a:       getTestAccessor(),
			wantHas: true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.a.GetUnexpiredOCSPs()
			if (err != nil) != tt.wantErr {
				t.Errorf("Accessor.GetUnexpiredOCSPs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if hasOCSP(got) != tt.wantHas {
				t.Errorf("Accessor.GetUnexpiredOCSPs() = %v, want %v", got, tt.wantHas)
			}
		})
	}
}

func TestAccessor_UpdateOCSP(t *testing.T) {
	type args struct {
		serial string
		aki    string
		body   string
		expiry time.Time
	}
	tests := []struct {
		name    string
		a       *Accessor
		args    args
		wantErr bool
	}{
		{
			name:    "Test UpdateOCSP",
			a:       getTestAccessor(),
			args:    args{serial: "2"},
			wantErr: false,
		},
		{
			name:    "Test UpdateOCSP",
			a:       getTestAccessor(),
			args:    args{serial: "222"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.a.UpdateOCSP(tt.args.serial, tt.args.aki, tt.args.body, tt.args.expiry); (err != nil) != tt.wantErr {
				t.Errorf("Accessor.UpdateOCSP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccessor_UpsertOCSP(t *testing.T) {
	type args struct {
		serial string
		aki    string
		body   string
		expiry time.Time
	}
	tests := []struct {
		name    string
		a       *Accessor
		args    args
		wantErr bool
	}{
		{
			name:    "Test UpsertOCSP",
			a:       getTestAccessor(),
			args:    args{serial: "1"},
			wantErr: false,
		},
		{
			name:    "Test UpsertOCSP",
			a:       getTestAccessor(),
			args:    args{serial: "111"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.a.UpsertOCSP(tt.args.serial, tt.args.aki, tt.args.body, tt.args.expiry); (err != nil) != tt.wantErr {
				t.Errorf("Accessor.UpsertOCSP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

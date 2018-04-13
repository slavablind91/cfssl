package redis

import (
	"errors"
	"strconv"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/dbconf"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/go-redis/redis"
)

// Accessor implements certdb.Accessor interface.
type Accessor struct {
	db *redis.Client
}

func wrapError(err error) error {
	if err != nil {
		return cferr.Wrap(cferr.CertStoreError, cferr.Unknown, err)
	}

	return nil
}

const revokedStatus string = "revoked"

const certKeyPrefix string = "cert"

func certKeyFromCertRec(cr *certdb.CertificateRecord) string {
	return certKeyPrefix + ":" + cr.Serial + ":" + cr.AKI
}

func certKeyFromSerialAKI(serial, aki string) string {
	return certKeyPrefix + ":" + serial + ":" + aki
}

const ocspKeyPrefix string = "ocsp"

func ocspKeyFromOCSPRec(or *certdb.OCSPRecord) string {
	return ocspKeyPrefix + ":" + or.Serial + ":" + or.AKI
}

func ocspKeyFromSerialAKI(serial, aki string) string {
	return ocspKeyPrefix + ":" + serial + ":" + aki
}

const (
	serialField    string = "serial_number"
	akiField       string = "authority_key_identifier"
	calabelField   string = "ca_label"
	statusField    string = "status"
	reasonField    string = "reason"
	expiryField    string = "expiry"
	revokedatField string = "revoked_at"
	pemField       string = "pem"
	bodyField      string = "body"
)

// NewAccessor returns a new Accessor.
func NewAccessor(cfg *dbconf.DBConfig) (*Accessor, error) {
	opt, err := redis.ParseURL(cfg.DataSourceName)

	if err != nil {
		return nil, wrapError(err)
	}

	accessor := &Accessor{
		db: redis.NewClient(opt),
	}

	return accessor, nil
}

func (a *Accessor) checkDB() error {
	if a.db == nil {
		return cferr.Wrap(cferr.CertStoreError, cferr.Unknown,
			errors.New("unknown db object in redis.Accessor"))
	}

	if err := a.db.Ping().Err(); err != nil {
		return wrapError(err)
	}

	return nil
}

// SetDB changes the underlying redis.Client.
func (a *Accessor) SetDB(db *redis.Client) {
	a.db = db
}

// InsertCertificate puts a certdb.CertificateRecord into db.
func (a *Accessor) InsertCertificate(cr certdb.CertificateRecord) error {
	// insert is equal to update/replace
	err := a.checkDB()
	if err != nil {
		return err
	}

	key := certKeyFromCertRec(&cr)

	crmap := make(map[string]interface{})
	crmap[serialField] = cr.Serial
	crmap[akiField] = cr.AKI
	crmap[calabelField] = cr.CALabel
	crmap[statusField] = cr.Status
	crmap[reasonField] = strconv.Itoa(cr.Reason)
	crmap[expiryField] = cr.Expiry.Format(time.RFC3339)
	crmap[revokedatField] = cr.RevokedAt.Format(time.RFC3339)
	crmap[pemField] = cr.PEM

	err = a.db.HMSet(key, crmap).Err()

	if err != nil {
		return wrapError(err)
	}

	return nil
}

// GetCertificate gets a certdb.CertificateRecord indexed by serial.
func (a *Accessor) GetCertificate(serial, aki string) ([]certdb.CertificateRecord, error) {
	err := a.checkDB()
	if err != nil {
		return nil, err
	}
	key := certKeyFromSerialAKI(serial, aki)

	crmap, err := a.db.HGetAll(key).Result()

	if err != nil {
		return nil, wrapError(err)
	}

	var crs []certdb.CertificateRecord

	reason, err := strconv.Atoi(crmap[reasonField])
	if err != nil {
		return nil, wrapError(err)
	}

	expiry, err := time.Parse(time.RFC3339, crmap[expiryField])
	if err != nil {
		return nil, wrapError(err)
	}

	revat, err := time.Parse(time.RFC3339, crmap[revokedatField])
	if err != nil {
		return nil, wrapError(err)
	}

	cr := certdb.CertificateRecord{
		Serial:    crmap[serialField],
		AKI:       crmap[akiField],
		CALabel:   crmap[calabelField],
		Status:    crmap[statusField],
		Reason:    reason,
		Expiry:    expiry,
		RevokedAt: revat,
		PEM:       crmap[pemField],
	}

	if err != nil {
		return nil, wrapError(err)
	}

	crs = append(crs, cr)

	return crs, nil
}

type filterType int

const (
	unexpired filterType = iota
	unexpiredRevoked
	unexpiredRevokedLabel
)

func checkUnexpired(expiry time.Time) bool {
	return checkUnexpired(expiry)
}

func checkRevokedUnexpired(status string, expiry time.Time) bool {
	return (status == revokedStatus && checkUnexpired(expiry))
}

func (a *Accessor) getCertificates(filter filterType, va ...string) ([]certdb.CertificateRecord, error) {
	err := a.checkDB()
	if err != nil {
		return nil, err
	}

	var recs []certdb.CertificateRecord

	it := a.db.Scan(0, certKeyPrefix+":*", 0).Iterator()

	for it.Next() {
		crmap, err := a.db.HGetAll(it.Val()).Result()
		if err != nil {
			return nil, wrapError(err)
		}

		expiry, err := time.Parse(time.RFC3339, crmap[expiryField])
		if err != nil {
			return nil, wrapError(err)
		}

		revat, err := time.Parse(time.RFC3339, crmap[revokedatField])
		if err != nil {
			return nil, wrapError(err)
		}

		reason, err := strconv.Atoi(crmap[reasonField])
		if err != nil {
			return nil, wrapError(err)
		}

		switch filter {
		case unexpired:
			if !checkUnexpired(expiry) {
				continue
			}
		case unexpiredRevoked:
			if !checkRevokedUnexpired(crmap[statusField], expiry) {
				continue
			}
		case unexpiredRevokedLabel:
			if len(va) == 0 {
				continue
			}
			label := va[0]
			if !(checkRevokedUnexpired(crmap[statusField], expiry) && crmap[calabelField] == label) {
				continue
			}
		default:
			continue
		}

		rec := certdb.CertificateRecord{
			Serial:    crmap[serialField],
			AKI:       crmap[akiField],
			CALabel:   crmap[calabelField],
			Status:    crmap[statusField],
			Reason:    reason,
			Expiry:    expiry,
			RevokedAt: revat,
			PEM:       crmap[pemField],
		}
		recs = append(recs, rec)
	}

	if it.Err() != nil {
		return nil, wrapError(it.Err())
	}

	return recs, nil
}

// GetUnexpiredCertificates gets all unexpired certificate from db.
func (a *Accessor) GetUnexpiredCertificates() ([]certdb.CertificateRecord, error) {
	return a.getCertificates(unexpired)
}

// GetRevokedAndUnexpiredCertificates gets all revoked and unexpired certificate from db (for CRLs).
func (a *Accessor) GetRevokedAndUnexpiredCertificates() ([]certdb.CertificateRecord, error) {
	return a.getCertificates(unexpiredRevoked)
}

// GetRevokedAndUnexpiredCertificatesByLabel gets all revoked and unexpired certificate from db (for CRLs) with specified ca_label.
func (a *Accessor) GetRevokedAndUnexpiredCertificatesByLabel(label string) ([]certdb.CertificateRecord, error) {
	return a.getCertificates(unexpiredRevoked, label)
}

// RevokeCertificate updates a certificate with a given serial number and marks it revoked.
func (a *Accessor) RevokeCertificate(serial, aki string, reasonCode int) error {
	err := a.checkDB()
	if err != nil {
		return err
	}
	key := certKeyFromSerialAKI(serial, aki)

	crmap := make(map[string]interface{})
	crmap[statusField] = revokedStatus
	crmap[reasonField] = reasonCode
	crmap[revokedatField] = time.Now().UTC()

	err = a.db.HMSet(key, crmap).Err()

	if err != nil {
		return wrapError(err)
	}

	return nil
}

// InsertOCSP puts a new certdb.OCSPRecord into the db.
func (a *Accessor) InsertOCSP(rr certdb.OCSPRecord) error {
	err := a.checkDB()
	if err != nil {
		return err
	}

	key := ocspKeyFromOCSPRec(&rr)

	rrmap := make(map[string]interface{})
	rrmap[serialField] = rr.Serial
	rrmap[akiField] = rr.AKI
	rrmap[bodyField] = rr.Body
	rrmap[expiryField] = rr.Expiry

	err = a.db.HMSet(key, rrmap).Err()

	if err != nil {
		return wrapError(err)
	}

	return nil
}

// GetOCSP retrieves a certdb.OCSPRecord from db by serial and aki.
func (a *Accessor) GetOCSP(serial, aki string) ([]certdb.OCSPRecord, error) {
	err := a.checkDB()
	if err != nil {
		return nil, err
	}

	key := ocspKeyFromSerialAKI(serial, aki)

	rrmap, err := a.db.HGetAll(key).Result()

	if err != nil {
		return nil, wrapError(err)
	}

	var rrs []certdb.OCSPRecord

	expiry, err := time.Parse(time.RFC3339, rrmap[expiryField])
	if err != nil {
		return nil, wrapError(err)
	}

	rr := certdb.OCSPRecord{
		Serial: rrmap[serialField],
		AKI:    rrmap[akiField],
		Body:   rrmap[bodyField],
		Expiry: expiry,
	}

	if err != nil {
		return nil, wrapError(err)
	}

	rrs = append(rrs, rr)

	return rrs, nil
}

// GetUnexpiredOCSPs retrieves all unexpired certdb.OCSPRecord from db.
func (a *Accessor) GetUnexpiredOCSPs() ([]certdb.OCSPRecord, error) {
	err := a.checkDB()
	if err != nil {
		return nil, err
	}

	var recs []certdb.OCSPRecord

	it := a.db.Scan(0, ocspKeyPrefix+":*", 0).Iterator()

	for it.Next() {
		rrmap, err := a.db.HGetAll(it.Val()).Result()
		if err != nil {
			return nil, wrapError(err)
		}

		expiry, err := time.Parse(time.RFC3339, rrmap[expiryField])
		if err != nil {
			return nil, wrapError(err)
		}

		if checkUnexpired(expiry) {
			rec := certdb.OCSPRecord{
				Serial: rrmap[serialField],
				AKI:    rrmap[akiField],
				Body:   rrmap[bodyField],
				Expiry: expiry,
			}
			recs = append(recs, rec)
		}
	}

	if it.Err() != nil {
		return nil, wrapError(it.Err())
	}

	return recs, nil
}

// UpdateOCSP updates a ocsp response record with a given serial number.
func (a *Accessor) UpdateOCSP(serial, aki, body string, expiry time.Time) error {
	err := a.checkDB()
	if err != nil {
		return err
	}

	key := ocspKeyFromSerialAKI(serial, aki)

	rrmap := make(map[string]interface{})
	rrmap[serialField] = serial
	rrmap[akiField] = aki
	rrmap[bodyField] = body
	rrmap[expiryField] = expiry.UTC().Format(time.RFC3339)

	err = a.db.HMSet(key, rrmap).Err()

	if err != nil {
		return wrapError(err)
	}

	return nil
}

// UpsertOCSP update a ocsp response record with a given serial number.
func (a *Accessor) UpsertOCSP(serial, aki, body string, expiry time.Time) error {
	return a.UpdateOCSP(serial, aki, body, expiry)
}

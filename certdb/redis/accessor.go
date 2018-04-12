package redis

import (
	"errors"
	"strconv"
	"time"
	// "fmt"
	// "time"

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

// NewAccessor returns a new Accessor.
func NewAccessor(cfg *dbconf.DBConfig) (*Accessor, error) {
	opt, err := redis.ParseURL(cfg.DataSourceName)

	if err != nil {
		return nil, err
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
	return nil
}

// SetDB changes the underlying redis.Client.
func (a *Accessor) SetDB(db *redis.Client) {
	a.db = db
}

// updateCertificateRecord update(replace) given CertificateRecord
func (a *Accessor) updateCertificateRecord(cr *certdb.CertificateRecord) error {
	key := certKeyFromCertRec(cr)

	crmap := make(map[string]interface{})
	crmap["serial_number"] = cr.Serial
	crmap["authority_key_identifier"] = cr.AKI
	crmap["ca_label"] = cr.CALabel
	crmap["status"] = cr.Status
	crmap["reason"] = strconv.Itoa(cr.Reason)
	crmap["expiry"] = cr.Expiry.Format(time.RFC3339)
	crmap["revoked_at"] = cr.RevokedAt.Format(time.RFC3339)
	crmap["pem"] = cr.PEM

	err := a.db.HMSet(key, crmap).Err()

	if err != nil {
		return wrapError(err)
	}

	return nil
}

// InsertCertificate puts a certdb.CertificateRecord into db.
func (a *Accessor) InsertCertificate(cr certdb.CertificateRecord) error {
	// insert is equal to update/replace
	err := a.checkDB()
	if err != nil {
		return err
	}

	return a.updateCertificateRecord(&cr)
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

	reason, err := strconv.Atoi(crmap["reason"])
	if err != nil {
		return nil, wrapError(err)
	}

	expiry, err := time.Parse(time.RFC3339, crmap["expiry"])
	if err != nil {
		return nil, wrapError(err)
	}

	revat, err := time.Parse(time.RFC3339, crmap["revoked_at"])
	if err != nil {
		return nil, wrapError(err)
	}

	cr := certdb.CertificateRecord{
		Serial:    crmap["serial_number"],
		AKI:       crmap["authority_key_identifier"],
		CALabel:   crmap["ca_label"],
		Status:    crmap["status"],
		Reason:    reason,
		Expiry:    expiry,
		RevokedAt: revat,
		PEM:       crmap["pem"],
	}

	if err != nil {
		return nil, wrapError(err)
	}

	crs = append(crs, cr)

	return crs, nil
}

func checkUnexpired(expiry time.Time) bool {
	return time.Now().UTC().Before(expiry)
}

// GetUnexpiredCertificates gets all unexpired certificate from db.
func (a *Accessor) GetUnexpiredCertificates() ([]certdb.CertificateRecord, error) {
	err := a.checkDB()
	if err != nil {
		return nil, err
	}

	var recs []certdb.CertificateRecord

	it := a.db.Scan(0, certKeyPrefix+":*", 0).Iterator()

	for it.Next() {
		recmap, err := a.db.HGetAll(it.Val()).Result()
		if err != nil {
			return nil, wrapError(err)
		}

		expiry, err := time.Parse(time.RFC3339, recmap["expiry"])
		if err != nil {
			return nil, wrapError(err)
		}

		revat, err := time.Parse(time.RFC3339, recmap["revoked_at"])
		if err != nil {
			return nil, wrapError(err)
		}

		reason, err := strconv.Atoi(recmap["reason"])
		if err != nil {
			return nil, wrapError(err)
		}

		if checkUnexpired(expiry) {
			rec := certdb.CertificateRecord{
				Serial:    recmap["serial_number"],
				AKI:       recmap["authority_key_identifier"],
				CALabel:   recmap["ca_label"],
				Status:    recmap["status"],
				Reason:    reason,
				Expiry:    expiry,
				RevokedAt: revat,
				PEM:       recmap["pem"],
			}
			recs = append(recs, rec)
		}
	}

	if it.Err() != nil {
		return nil, wrapError(it.Err())
	}

	return recs, nil
}

// GetRevokedAndUnexpiredCertificates gets all revoked and unexpired certificate from db (for CRLs).
func (a *Accessor) GetRevokedAndUnexpiredCertificates() ([]certdb.CertificateRecord, error) {
	err := a.checkDB()
	if err != nil {
		return nil, err
	}

	var recs []certdb.CertificateRecord

	it := a.db.Scan(0, certKeyPrefix+":*", 0).Iterator()

	for it.Next() {
		recmap, err := a.db.HGetAll(it.Val()).Result()
		if err != nil {
			return nil, wrapError(err)
		}

		expiry, err := time.Parse(time.RFC3339, recmap["expiry"])
		if err != nil {
			return nil, wrapError(err)
		}

		revat, err := time.Parse(time.RFC3339, recmap["revoked_at"])
		if err != nil {
			return nil, wrapError(err)
		}

		reason, err := strconv.Atoi(recmap["reason"])
		if err != nil {
			return nil, wrapError(err)
		}

		if checkRevokedUnexpired(recmap["status"], expiry) {
			rec := certdb.CertificateRecord{
				Serial:    recmap["serial_number"],
				AKI:       recmap["authority_key_identifier"],
				CALabel:   recmap["ca_label"],
				Status:    recmap["status"],
				Reason:    reason,
				Expiry:    expiry,
				RevokedAt: revat,
				PEM:       recmap["pem"],
			}
			recs = append(recs, rec)
		}
	}

	if it.Err() != nil {
		return nil, wrapError(it.Err())
	}

	return recs, nil
}

func checkRevokedUnexpired(status string, expiry time.Time) bool {
	return (status == revokedStatus && time.Now().UTC().Before(expiry))
}

// GetRevokedAndUnexpiredCertificatesByLabel gets all revoked and unexpired certificate from db (for CRLs) with specified ca_label.
func (a *Accessor) GetRevokedAndUnexpiredCertificatesByLabel(label string) ([]certdb.CertificateRecord, error) {
	err := a.checkDB()
	if err != nil {
		return nil, err
	}

	var recs []certdb.CertificateRecord

	it := a.db.Scan(0, certKeyPrefix+":*", 0).Iterator()

	for it.Next() {
		recmap, err := a.db.HGetAll(it.Val()).Result()
		if err != nil {
			return nil, wrapError(err)
		}

		expiry, err := time.Parse(time.RFC3339, recmap["expiry"])
		if err != nil {
			return nil, wrapError(err)
		}

		revat, err := time.Parse(time.RFC3339, recmap["revoked_at"])
		if err != nil {
			return nil, wrapError(err)
		}

		reason, err := strconv.Atoi(recmap["reason"])
		if err != nil {
			return nil, wrapError(err)
		}

		if checkRevokedUnexpired(recmap["status"], expiry) && recmap["ca_label"] == label {
			rec := certdb.CertificateRecord{
				Serial:    recmap["serial_number"],
				AKI:       recmap["authority_key_identifier"],
				CALabel:   recmap["ca_label"],
				Status:    recmap["status"],
				Reason:    reason,
				Expiry:    expiry,
				RevokedAt: revat,
				PEM:       recmap["pem"],
			}
			recs = append(recs, rec)
		}
	}

	if it.Err() != nil {
		return nil, wrapError(it.Err())
	}

	return recs, nil
}

// RevokeCertificate updates a certificate with a given serial number and marks it revoked.
func (a *Accessor) RevokeCertificate(serial, aki string, reasonCode int) error {
	err := a.checkDB()
	if err != nil {
		return err
	}
	key := certKeyFromSerialAKI(serial, aki)

	crmap := make(map[string]interface{})
	crmap["status"] = revokedStatus
	crmap["reason"] = reasonCode
	crmap["revoked_at"] = time.Now().UTC()

	err = a.db.HMSet(key, crmap).Err()

	if err != nil {
		return wrapError(err)
	}

	return nil
}

// updateCertificateRecord update(replace) given CertificateRecord
func (a *Accessor) updateOCSPRecord(rr *certdb.OCSPRecord) error {
	key := ocspKeyFromOCSPRec(rr)

	rrmap := make(map[string]interface{})
	rrmap["serial_number"] = rr.Serial
	rrmap["authority_key_identifier"] = rr.AKI
	rrmap["body"] = rr.Body
	rrmap["expiry"] = rr.Expiry

	err := a.db.HMSet(key, rrmap).Err()

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

	a.updateOCSPRecord(&rr)

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

	expiry, err := time.Parse(time.RFC3339, rrmap["expiry"])
	if err != nil {
		return nil, wrapError(err)
	}

	rr := certdb.OCSPRecord{
		Serial: rrmap["serial_number"],
		AKI:    rrmap["authority_key_identifier"],
		Body:   rrmap["body"],
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
		recmap, err := a.db.HGetAll(it.Val()).Result()
		if err != nil {
			return nil, wrapError(err)
		}

		expiry, err := time.Parse(time.RFC3339, recmap["expiry"])
		if err != nil {
			return nil, wrapError(err)
		}

		now := time.Now().UTC()
		if now.Before(expiry) {
			rec := certdb.OCSPRecord{
				Serial: recmap["serial_number"],
				AKI:    recmap["authority_key_identifier"],
				Body:   recmap["body"],
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
	key := ocspKeyFromSerialAKI(serial, aki)

	rrmap := make(map[string]interface{})
	rrmap["serial_number"] = serial
	rrmap["authority_key_identifier"] = aki
	rrmap["body"] = body
	rrmap["expiry"] = expiry.UTC().Format(time.RFC3339)

	err := a.db.HMSet(key, rrmap).Err()

	if err != nil {
		return wrapError(err)
	}

	return nil
}

// UpsertOCSP update a ocsp response record with a given serial number.
func (a *Accessor) UpsertOCSP(serial, aki, body string, expiry time.Time) error {
	err := a.checkDB()
	if err != nil {
		return err
	}

	return a.UpdateOCSP(serial, aki, body, expiry)
}

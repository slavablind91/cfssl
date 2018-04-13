package db

import (
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/dbconf"
	"github.com/cloudflare/cfssl/certdb/redis"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/log"
	"github.com/jmoiron/sqlx"
)

// NewAccessor returns a new Accessor.
func NewAccessor(cfg *dbconf.DBConfig) (certdb.Accessor, error) {
	log.Debug("Create new Accessor for: ", cfg.DriverName)
	if cfg.DriverName == "redis" {
		accessor, err := redis.NewAccessor(cfg)
		if err != nil {
			return nil, err
		}
		log.Debugf("Accessor created: %+v", accessor)
		return accessor, nil
	}

	db, err := sqlx.Open(cfg.DriverName, cfg.DataSourceName)
	if err != nil {
		log.Error("no database specified!")
		return nil, err
	}

	return sql.NewAccessor(db), nil
}

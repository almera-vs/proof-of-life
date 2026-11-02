package fingerprint

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const userSchemas = `n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'`

func notExtensionMember(classOID, objOID string) string {
	return `NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = '` + classOID + `'::regclass AND d.objid = ` + objOID + ` AND d.deptype = 'e')`
}

const relName = `quote_ident(n.nspname) || '.' || quote_ident(c.relname)`

const heartbeatFilter = `NOT (n.nspname = 'public' AND c.relname = 'pol_heartbeat')`

var schemaQueries = []string{

	`SELECT 'relation', ` + relName + `,
	        'kind=' || c.relkind::text || ' persistence=' || c.relpersistence::text
	        || coalesce(' bound=' || pg_get_expr(c.relpartbound, c.oid), '')
	        || CASE WHEN c.relkind IN ('v','m') THEN ' view=' || pg_get_viewdef(c.oid) ELSE '' END
	 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	 WHERE c.relkind IN ('r','p','v','m','f','c') AND ` + userSchemas + ` AND ` + heartbeatFilter + `
	   AND ` + notExtensionMember("pg_class", "c.oid"),

	`SELECT 'column', ` + relName + ` || '.' || quote_ident(a.attname),
	        'position=' || (row_number() OVER (PARTITION BY a.attrelid ORDER BY a.attnum))::text
	        || ' type=' || format_type(a.atttypid, a.atttypmod)
	        || ' notnull=' || a.attnotnull::text
	        || ' identity=' || a.attidentity::text
	        || ' generated=' || a.attgenerated::text
	        || coalesce(' default=' || pg_get_expr(ad.adbin, ad.adrelid), '')
	        || coalesce(' collation=' || (SELECT co.collname FROM pg_collation co WHERE co.oid = a.attcollation AND a.attcollation <> t.typcollation), '')
	 FROM pg_attribute a
	 JOIN pg_class c ON c.oid = a.attrelid
	 JOIN pg_namespace n ON n.oid = c.relnamespace
	 JOIN pg_type t ON t.oid = a.atttypid
	 LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
	 WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r','p','v','m','f','c')
	   AND ` + userSchemas + ` AND ` + heartbeatFilter + ` AND ` + notExtensionMember("pg_class", "c.oid"),

	`SELECT 'index', ` + relName + `, regexp_replace(pg_get_indexdef(c.oid), ' TABLESPACE \S+', '')
	 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace
	 WHERE ` + userSchemas + ` AND i.indrelid <> coalesce(to_regclass('public.pol_heartbeat')::oid, 0)
	   AND ` + notExtensionMember("pg_class", "c.oid"),

	`SELECT 'constraint', quote_ident(n.nspname) || '.' || coalesce(quote_ident(rel.relname), quote_ident(ty.typname)) || '.' || quote_ident(con.conname),
	        regexp_replace(pg_get_constraintdef(con.oid), ' USING INDEX TABLESPACE \S+', '')
	 FROM pg_constraint con
	 JOIN pg_namespace n ON n.oid = con.connamespace
	 LEFT JOIN pg_class rel ON rel.oid = con.conrelid
	 LEFT JOIN pg_type ty ON ty.oid = con.contypid
	 WHERE ` + userSchemas + ` AND coalesce(rel.relname, '') <> 'pol_heartbeat'
	   AND ` + notExtensionMember("pg_constraint", "con.oid"),

	`SELECT 'function', quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' || pg_get_function_identity_arguments(p.oid) || ')',
	        CASE WHEN p.prokind = 'a' THEN 'aggregate' ELSE pg_get_functiondef(p.oid) END
	 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
	 WHERE ` + userSchemas + ` AND ` + notExtensionMember("pg_proc", "p.oid"),

	`SELECT 'sequence', ` + relName + `,
	        'type=' || format_type(s.seqtypid, NULL) || ' increment=' || s.seqincrement::text || ' min=' || s.seqmin::text
	        || ' max=' || s.seqmax::text || ' start=' || s.seqstart::text || ' cache=' || s.seqcache::text || ' cycle=' || s.seqcycle::text
	 FROM pg_sequence s JOIN pg_class c ON c.oid = s.seqrelid JOIN pg_namespace n ON n.oid = c.relnamespace
	 WHERE ` + userSchemas + ` AND ` + notExtensionMember("pg_class", "c.oid"),

	`SELECT 'type', quote_ident(n.nspname) || '.' || quote_ident(t.typname),
	        CASE t.typtype
	          WHEN 'e' THEN 'enum=' || coalesce((SELECT string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder) FROM pg_enum e WHERE e.enumtypid = t.oid), '')
	          WHEN 'd' THEN 'domain=' || format_type(t.typbasetype, t.typtypmod) || ' notnull=' || t.typnotnull::text || coalesce(' default=' || t.typdefault, '')
	          ELSE 'range=' || coalesce((SELECT format_type(r.rngsubtype, NULL) FROM pg_range r WHERE r.rngtypid = t.oid), '')
	        END
	 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
	 WHERE t.typtype IN ('e','d','r') AND ` + userSchemas + ` AND ` + notExtensionMember("pg_type", "t.oid"),

	`SELECT 'trigger', ` + relName + ` || '.' || quote_ident(tg.tgname), pg_get_triggerdef(tg.oid)
	 FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
	 WHERE NOT tg.tgisinternal AND ` + userSchemas + ` AND ` + notExtensionMember("pg_trigger", "tg.oid"),
}

const tableCountsQuery = `SELECT ` + relName + `, c.reltuples::bigint::text, coalesce(s.n_mod_since_analyze, 0)::text
 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 LEFT JOIN pg_stat_all_tables s ON s.relid = c.oid
 WHERE c.relkind = 'r' AND c.relpersistence = 'p' AND ` + userSchemas + ` AND ` + heartbeatFilter + `
   AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')`

func ReadSchema(ctx context.Context, q Querier, db string) ([]Object, error) {
	var out []Object
	for _, sql := range schemaQueries {
		rows, err := q.Query(ctx, db, sql)
		if err != nil {
			return nil, fmt.Errorf("read schema: %w", err)
		}
		for _, r := range rows {
			if len(r) != 3 {
				return nil, fmt.Errorf("read schema: expected 3 columns, got %d", len(r))
			}
			out = append(out, Object{Kind: r[0], Identity: r[1], Definition: r[2]})
		}
	}
	SortObjects(out)
	return out, nil
}

func ReadTableCounts(ctx context.Context, q Querier, db string) ([]TableCount, error) {
	rows, err := q.Query(ctx, db, tableCountsQuery)
	if err != nil {
		return nil, fmt.Errorf("read row estimates: %w", err)
	}
	out := make([]TableCount, 0, len(rows))
	for _, r := range rows {
		if len(r) != 3 {
			return nil, fmt.Errorf("read row estimates: expected 3 columns, got %d", len(r))
		}
		out = append(out, TableCount{Table: r[0], Estimate: ParseInt(r[1]), Modified: max(ParseInt(r[2]), 0)})
	}
	return out, nil
}

func ExactCount(ctx context.Context, q Querier, db, table string) (int64, error) {
	rows, err := q.Query(ctx, db, "SELECT count(*) FROM "+QuoteTable(table))
	if err != nil {
		return 0, fmt.Errorf("count %s: %w", table, err)
	}
	if len(rows) != 1 || len(rows[0]) != 1 {
		return 0, fmt.Errorf("count %s: unexpected result shape", table)
	}
	return strconv.ParseInt(rows[0][0], 10, 64)
}

func SingleValue(ctx context.Context, q Querier, db, sql string) (string, error) {
	rows, err := q.Query(ctx, db, sql)
	if err != nil {
		return "", err
	}
	if len(rows) != 1 || len(rows[0]) != 1 {
		cols := 0
		if len(rows) > 0 {
			cols = len(rows[0])
		}
		return "", fmt.Errorf("expected exactly one row with one column, got %d rows and %d columns", len(rows), cols)
	}
	return rows[0][0], nil
}

type CaptureInput struct {
	Drill       string
	Label       string
	StopLSN     string
	StopTime    time.Time
	ExactTables []string
	Assertions  map[string]string
}

func Capture(ctx context.Context, conn *Conn, in CaptureInput) (*Snapshot, error) {
	s := &Snapshot{
		Version: 1, Drill: in.Drill, CapturedAt: time.Now().UTC(), BackupLabel: in.Label,
		BackupStopLSN: in.StopLSN, BackupStopTime: in.StopTime.UTC(), Database: conn.Database(),
		ExactCounts: map[string]int64{}, Assertions: map[string]Value{},
	}
	catalog := conn.WithSearchPath("pg_catalog")
	rows, err := catalog.Query(ctx, "", `SELECT current_setting('server_version'), current_setting('server_version_num'),
	  pg_encoding_to_char(d.encoding), d.datcollate, d.datctype, (SELECT rolname FROM pg_roles WHERE oid = 10)
	  FROM pg_database d WHERE d.datname = current_database()`)
	if err != nil {
		return nil, fmt.Errorf("read server settings: %w", err)
	}
	if len(rows) != 1 || len(rows[0]) != 6 {
		return nil, fmt.Errorf("read server settings: unexpected result shape")
	}
	r := rows[0]
	s.ServerVersion, s.Encoding, s.Collate, s.Ctype, s.Bootstrap = strings.Fields(r[0])[0], r[2], r[3], r[4], r[5]
	if s.ServerMajor, err = MajorFromNum(r[1]); err != nil {
		return nil, err
	}
	if s.Extensions, err = readExtensions(ctx, catalog, ""); err != nil {
		return nil, err
	}
	if s.Objects, err = ReadSchema(ctx, catalog, ""); err != nil {
		return nil, err
	}
	s.SchemaHash = Hash(s.Objects)
	if s.Tables, err = ReadTableCounts(ctx, catalog, ""); err != nil {
		return nil, err
	}
	user := conn.WithSearchPath("public")
	for _, t := range in.ExactTables {
		if s.ExactCounts[t], err = ExactCount(ctx, user, "", t); err != nil {
			return nil, err
		}
	}
	for name, sql := range in.Assertions {
		raw, err := SingleValue(ctx, user, "", BindParameters(sql, in.StopTime, in.StopLSN))
		if err != nil {
			return nil, fmt.Errorf("assertion %s: %w", name, err)
		}
		s.Assertions[name] = NewValue(raw)
	}
	return s, nil
}

func readExtensions(ctx context.Context, q Querier, db string) (map[string]string, error) {
	rows, err := q.Query(ctx, db, `SELECT extname, extversion FROM pg_extension`)
	if err != nil {
		return nil, fmt.Errorf("read extensions: %w", err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r[0]] = r[1]
	}
	return out, nil
}

func ReadSettings(ctx context.Context, q Querier, db string) (encoding, collate, ctype string, err error) {
	rows, err := q.Query(ctx, db, `SELECT pg_encoding_to_char(encoding), datcollate, datctype FROM pg_database WHERE datname = current_database()`)
	if err != nil {
		return "", "", "", fmt.Errorf("read database settings: %w", err)
	}
	if len(rows) != 1 || len(rows[0]) != 3 {
		return "", "", "", fmt.Errorf("read database settings: unexpected result shape")
	}
	return rows[0][0], rows[0][1], rows[0][2], nil
}

func ReadExtensions(ctx context.Context, q Querier, db string) (map[string]string, error) {
	return readExtensions(ctx, q, db)
}

func MajorFromNum(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("unrecognised server_version_num %q", s)
	}
	return n / 10000, nil
}

type Conn struct {
	conn *pgx.Conn
	path string
}

func Connect(ctx context.Context, dsn string, readOnly bool) (*Conn, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %s", sanitizeDSNError(err))
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.RuntimeParams["application_name"] = "pol"
	cfg.RuntimeParams["statement_timeout"] = "600000"
	cfg.RuntimeParams["lock_timeout"] = "5000"
	if readOnly {
		cfg.RuntimeParams["default_transaction_read_only"] = "on"
	}
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to the fingerprint database: %s", sanitizeDSNError(err))
	}
	return &Conn{conn: c}, nil
}

func TLSNote(dsn string) string {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return ""
	}
	host := cfg.Host
	if strings.HasPrefix(host, "/") || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return ""
	}
	verified := cfg.TLSConfig != nil && (!cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.VerifyPeerCertificate != nil)
	if !verified || len(cfg.Fallbacks) > 0 {
		return "the fingerprint connection to " + host + " does not verify the server's certificate; use sslmode=verify-full"
	}
	return ""
}

func sanitizeDSNError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "://") || strings.Contains(msg, "password") {
		return "the connection string is invalid or the connection was refused; check host, port, role and password"
	}
	return msg
}

func (c *Conn) Close(ctx context.Context) error { return c.conn.Close(ctx) }

func (c *Conn) Database() string { return c.conn.Config().Database }

func (c *Conn) WithSearchPath(path string) *Conn { return &Conn{conn: c.conn, path: path} }

func (c *Conn) Query(ctx context.Context, _, sql string) ([][]string, error) {
	if c.path != "" {
		if _, err := c.conn.Exec(ctx, "SELECT set_config('search_path', '"+c.path+"', false)"); err != nil {
			return nil, fmt.Errorf("set search_path: %w", err)
		}
	}
	rows, err := c.conn.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("run query: %w", err)
	}
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		raw := rows.RawValues()
		row := make([]string, len(raw))
		for i, v := range raw {
			row[i] = string(v)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("run query: %w", err)
	}
	return out, nil
}

func (c *Conn) RoleWarnings(ctx context.Context) ([]string, error) {
	rows, err := c.Query(ctx, "", `SELECT rolsuper::text, rolcreaterole::text, rolcreatedb::text, rolbypassrls::text FROM pg_roles WHERE rolname = current_user`)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || len(rows[0]) != 4 {
		return nil, fmt.Errorf("read role attributes: unexpected result shape")
	}
	var out []string
	for i, name := range []string{"superuser", "createrole", "createdb", "bypassrls"} {
		if rows[0][i] == "true" || rows[0][i] == "t" {
			out = append(out, "the fingerprint role has "+name+"; it should be read-only (see deploy/sql/roles.sql)")
		}
	}
	return out, nil
}

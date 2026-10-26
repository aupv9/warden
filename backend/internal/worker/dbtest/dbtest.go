// Package dbtest is a stand-in for a pgx transaction in unit tests. In strict
// mode (New) each statement must match the next expected step by SQL prefix; in
// loose mode (Loose) the longest matching prefix answers, any number of times.
// Real SQL is covered by the integration tests; this covers the Go around it.
package dbtest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type Step struct {
	Prefix   string  // the statement, whitespace-collapsed, must start with this
	Rows     [][]any // result rows for Query / QueryRow
	Affected int64   // rows affected for Exec
	Err      error
	Args     func(args []any) error // optional argument check
	Do       func(args []any) Step  // optional: compute the result from the arguments
}

// Call is one executed statement.
type Call struct {
	SQL  string
	Args []any
}

type DB struct {
	t     testing.TB
	mu    sync.Mutex
	steps []Step
	next  int
	loose bool
	calls []Call
}

// New expects exactly steps, in order.
func New(t testing.TB, steps ...Step) *DB {
	return &DB{t: t, steps: steps}
}

// Loose answers any statement with the step of the longest matching prefix, as
// often as it comes and in any order (concurrent callers). On equal prefixes
// the later step wins, so a test can override a default.
func Loose(t testing.TB, steps ...Step) *DB {
	return &DB{t: t, steps: steps, loose: true}
}

// Calls returns the executed statements whose SQL starts with prefix.
func (d *DB) Calls(prefix string) []Call {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Call
	for _, c := range d.calls {
		if strings.HasPrefix(c.SQL, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// Done fails the test if expected statements were not executed (strict mode).
func (d *DB) Done() {
	d.t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.loose && d.next != len(d.steps) {
		d.t.Errorf("dbtest: %d of %d statements executed; next expected %q", d.next, len(d.steps), d.steps[d.next].Prefix)
	}
}

func norm(sql string) string { return strings.Join(strings.Fields(sql), " ") }

var ErrUnexpected = errors.New("dbtest: unexpected statement")

func (d *DB) match(s string) (Step, bool) {
	if d.loose {
		best, found := Step{}, false
		for _, st := range d.steps {
			if strings.HasPrefix(s, st.Prefix) && (!found || len(st.Prefix) >= len(best.Prefix)) {
				best, found = st, true
			}
		}
		if !found {
			d.t.Errorf("dbtest: unexpected statement %q", s)
		}
		return best, found
	}
	if d.next >= len(d.steps) {
		d.t.Errorf("dbtest: unexpected statement %q", s)
		return Step{}, false
	}
	st := d.steps[d.next]
	if !strings.HasPrefix(s, st.Prefix) {
		d.t.Errorf("dbtest: statement %d: got %q, want prefix %q", d.next, s, st.Prefix)
		return Step{}, false
	}
	d.next++
	return st, true
}

func (d *DB) take(sql string, args []any) (Step, error) {
	d.mu.Lock()
	s := norm(sql)
	d.calls = append(d.calls, Call{SQL: s, Args: args})
	st, ok := d.match(s)
	d.mu.Unlock()
	if !ok {
		return Step{}, ErrUnexpected
	}
	if st.Args != nil {
		if err := st.Args(args); err != nil {
			d.t.Errorf("dbtest: %q: %v", st.Prefix, err)
		}
	}
	if st.Do != nil {
		st = st.Do(args)
	}
	return st, nil
}

func (d *DB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	st, err := d.take(sql, args)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	if st.Err != nil {
		return pgconn.CommandTag{}, st.Err
	}
	return pgconn.NewCommandTag(fmt.Sprintf("UPDATE %d", st.Affected)), nil
}

func (d *DB) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	st, err := d.take(sql, args)
	if err != nil {
		return nil, err
	}
	if st.Err != nil {
		return nil, st.Err
	}
	return &rows{data: st.Rows, i: -1}, nil
}

func (d *DB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	st, err := d.take(sql, args)
	if err == nil {
		err = st.Err
	}
	return row{rows: &rows{data: st.Rows, i: -1}, err: err}
}

type row struct {
	rows *rows
	err  error
}

func (r row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if !r.rows.Next() {
		return pgx.ErrNoRows
	}
	return r.rows.Scan(dest...)
}

type rows struct {
	data [][]any
	i    int
}

func (r *rows) Close()                                       {}
func (r *rows) Err() error                                   { return nil }
func (r *rows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT") }
func (r *rows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *rows) RawValues() [][]byte                          { return nil }
func (r *rows) Conn() *pgx.Conn                              { return nil }
func (r *rows) TypeMap() *pgtype.Map                         { return nil }
func (r *rows) Values() ([]any, error)                       { return r.data[r.i], nil }

func (r *rows) Next() bool {
	r.i++
	return r.i < len(r.data)
}

// Scan assigns each value to the matching destination pointer; nil leaves the
// destination's zero value (NULL).
func (r *rows) Scan(dest ...any) error {
	vals := r.data[r.i]
	if len(vals) != len(dest) {
		return fmt.Errorf("dbtest: scan %d columns into %d destinations", len(vals), len(dest))
	}
	for i, v := range vals {
		dv := reflect.ValueOf(dest[i])
		if dv.Kind() != reflect.Pointer || dv.IsNil() {
			return fmt.Errorf("dbtest: destination %d is not a pointer", i)
		}
		target := dv.Elem()
		if v == nil {
			target.SetZero()
			continue
		}
		val := reflect.ValueOf(v)
		switch {
		case target.Kind() == reflect.Pointer && val.Type().AssignableTo(target.Type().Elem()):
			p := reflect.New(target.Type().Elem())
			p.Elem().Set(val)
			target.Set(p)
		case val.Type().AssignableTo(target.Type()):
			target.Set(val)
		case val.Kind() == target.Kind() && val.Type().ConvertibleTo(target.Type()):
			target.Set(val.Convert(target.Type()))
		default:
			return fmt.Errorf("dbtest: can't scan %T into %s", v, target.Type())
		}
	}
	return nil
}

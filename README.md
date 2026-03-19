<p align="center">
  <img src="docs/logo_alpha.png" height="200" alt="safesession logo">
</p>

# safesession

safesession is a PostgreSQL extension that locks a session into read-only
mode.  Once loaded, every transaction in the session is forced read-only:
INSERT, UPDATE, DELETE, DDL and modifying CTEs are all rejected.

The primary use case is **safe database access for AI agents and automated
tools** (e.g. MCP servers).  Connection setup is typically controlled by the
application, not the agent — so the application loads safesession before
handing the connection over, and the agent cannot undo the protection.

See the [pgsql-hackers discussion](https://www.postgresql.org/message-id/flat/CADsUR0B9bcJQKYHyUMnWcODGzF5%2BAdeToawULkkTKfrq32Z-8w%40mail.gmail.com)
for background.

## How it works

safesession installs two hooks — ExecutorStart and ProcessUtility.  On the
first statement after `LOAD`, the hooks set `default_transaction_read_only`
and `transaction_read_only` to `on` at the session level.  This means:

- Every new transaction starts with `XactReadOnly = true` automatically.
- Core PostgreSQL enforcement takes over from there:
  `ExecCheckXactReadOnly()` blocks DML and modifying CTEs,
  `PreventCommandIfReadOnly()` blocks DDL and other write utility commands.
- `check_transaction_read_only()` in core prevents the agent from flipping
  `transaction_read_only` back to off within the same transaction.
- After the initial setup, the hooks short-circuit immediately (checking
  only that `XactReadOnly` is still true), adding near-zero overhead.

No shared memory, no background workers, no SQL-callable functions.

## Activation

safesession is activated per-session with the `LOAD` command:

```sql
LOAD 'safesession';
```

This is typically done by the application at connection startup, before the
AI agent begins issuing queries.  Once loaded, the hooks remain active for
the lifetime of the session — there is no way to unload them.

**Warning:** if safesession is added to `shared_preload_libraries`, it will
force **every session in the entire cluster** into read-only mode.  This is almost certainly not
what you want.  Use `LOAD` for per-session activation instead.

## Installation

### Building within the PostgreSQL source tree

```sh
cd contrib/safesession
make
make install
make check        # runs a temporary instance for regression tests
```

### Building with PGXS

```sh
cd safesession
export USE_PGXS=1
make
make install
make installcheck
```

## Example

```
postgres=# CREATE TABLE t(i int);
CREATE TABLE
postgres=# INSERT INTO t VALUES (1);
INSERT 0 1
postgres=# LOAD 'safesession';
LOAD
postgres=# SELECT * FROM t;
 i
---
 1
(1 row)

postgres=# INSERT INTO t VALUES (2);
ERROR:  cannot execute INSERT in a read-only transaction
postgres=# CREATE TABLE t2(i int);
ERROR:  cannot execute CREATE TABLE in a read-only transaction
postgres=# SET transaction_read_only = off;
ERROR:  cannot set transaction read-only mode inside a read-only transaction
```

## Limitations

- **Session scope only.**  safesession protects the session it is loaded
  into.  Other sessions are unaffected.
- **Maintenance commands.**  `VACUUM`, `ANALYZE` and `CHECKPOINT` are
  classified as read-only by core and are not blocked.
- **Background processes.**  The checkpointer, background writer, WAL writer
  and autovacuum continue to operate normally — safesession does not make the
  physical database files read-only.

## Based on pg_readonly

safesession is derived from
[pg_readonly](https://github.com/pierreforstmann/pg_readonly) by Pierre
Forstmann, which provides cluster-wide read-only mode via shared memory and
SQL functions.  safesession strips that down to per-session, load-and-forget
protection with no SQL interface.

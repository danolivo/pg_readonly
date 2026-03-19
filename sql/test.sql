--
-- test.sql
--
-- safesession.blocked_commands is set in safesession.conf at server startup.
-- It cannot be changed at runtime (PGC_POSTMASTER).
--

-- Setup: create test objects before activating safesession
create table t(i int);

create function f(IN p int, OUT i int) returns int as $$
begin
  insert into t(i) values (f.p) returning t.i into f.i;
end$$
language plpgsql;

-- Activate safesession: from now on the session is read-only
LOAD 'safesession';

-- Show the blocked_commands setting (set at startup)
SHOW safesession.blocked_commands;

-- SELECTs still work
select * from t;

-- DML is blocked
insert into t values (1);

-- Volatile function that attempts a write is blocked
select f(1);

-- DDL is blocked
CREATE TABLE t2(i int);

-- DO block with DML is blocked
DO $$ BEGIN INSERT INTO t VALUES (99); END $$;

select * from t;

-- Modifying CTE is blocked
with inserted as (insert into t values(3) returning 3) select * from inserted;

-- Large object creation is blocked
SELECT lo_create(0);

-- Maintenance commands are blocked per safesession.blocked_commands
VACUUM t;
ANALYZE t;
CLUSTER t;
REINDEX TABLE t;
CHECKPOINT;

-- Cannot change at runtime
SET safesession.blocked_commands = '';

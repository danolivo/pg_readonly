/*-------------------------------------------------------------------------
 *
 * safesession is a PostgreSQL extension which allows to set a session
 * read only: no INSERT,UPDATE,DELETE and no DDL can be run.
 *
 * Activated by LOAD 'safesession' — from that point on, every
 * transaction in the session is forced into read-only mode.
 *
 * Additionally, utility commands that core considers safe in read-only
 * transactions (VACUUM, ANALYZE, CLUSTER, REINDEX, CHECKPOINT) can be
 * blocked via the safesession.blocked_commands GUC.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (c) 2020, Pierre Forstmann.
 *
 *-------------------------------------------------------------------------
*/
#include "postgres.h"
#include "access/xact.h"
#include "executor/executor.h"
#include "nodes/parsenodes.h"
#include "tcop/utility.h"
#include "utils/guc.h"

#define SAFESESSION_VERSION "0.1"

#ifdef PG_MODULE_MAGIC_EXT
PG_MODULE_MAGIC_EXT(
	.name = "safesession",
	.version = SAFESESSION_VERSION
);
#else
PG_MODULE_MAGIC;
#endif

/* GUC: comma-separated list of utility commands to block */
static char *ss_blocked_commands = NULL;

/* Parsed flags from ss_blocked_commands */
static bool block_vacuum = false;
static bool block_analyze = false;
static bool block_cluster = false;
static bool block_reindex = false;
static bool block_checkpoint = false;

/* Saved hook values in case of unload */
static ExecutorStart_hook_type prev_executor_start_hook = NULL;
static ProcessUtility_hook_type prev_process_utility_hook = NULL;

/*---- Function declarations ----*/

void		_PG_init(void);

static void ss_exec(QueryDesc *queryDesc, int eflags);
static void ss_utility(PlannedStmt *pstmt, const char *queryString,
					   bool readOnlyTree,
					   ProcessUtilityContext context,
					   ParamListInfo params,
					   QueryEnvironment *queryEnv,
					   DestReceiver *dest, QueryCompletion *qc);

/*
 * Parse the blocked_commands GUC value and set flags accordingly.
 */
static void
ss_parse_blocked_commands(void)
{
	block_vacuum = false;
	block_analyze = false;
	block_cluster = false;
	block_reindex = false;
	block_checkpoint = false;

	if (ss_blocked_commands == NULL || ss_blocked_commands[0] == '\0')
		return;

	if (strcasestr(ss_blocked_commands, "vacuum"))
		block_vacuum = true;
	if (strcasestr(ss_blocked_commands, "analyze"))
		block_analyze = true;
	if (strcasestr(ss_blocked_commands, "cluster"))
		block_cluster = true;
	if (strcasestr(ss_blocked_commands, "reindex"))
		block_reindex = true;
	if (strcasestr(ss_blocked_commands, "checkpoint"))
		block_checkpoint = true;
}

/*
 * GUC assign hook for safesession.blocked_commands.
 */
static void
ss_assign_blocked_commands(const char *newval, void *extra)
{
	/* Flags will be re-parsed on next use; cache the result now. */
	ss_blocked_commands = (char *) newval;
	ss_parse_blocked_commands();
}

/*
 * Module load callback.
 */
void
_PG_init(void)
{
	DefineCustomStringVariable("safesession.blocked_commands",
							   "Comma-separated list of utility commands "
							   "to block in read-only mode "
							   "(vacuum, analyze, cluster, reindex, checkpoint).",
							   NULL,
							   &ss_blocked_commands,
							   "",
							   PGC_SIGHUP,
							   0,
							   NULL,
							   ss_assign_blocked_commands,
							   NULL);

	prev_executor_start_hook = ExecutorStart_hook;
	ExecutorStart_hook = ss_exec;
	prev_process_utility_hook = ProcessUtility_hook;
	ProcessUtility_hook = ss_utility;
}

/*
 * Set transaction_read_only for the current transaction via the GUC
 * machinery.  Using GUC_ACTION_LOCAL means the value is automatically
 * reverted at transaction end — no manual restore is needed.
 *
 * Once set, the user cannot revert to read-write mode within the same
 * transaction: check_transaction_read_only() in variable.c rejects the
 * read-only -> read-write transition after the first snapshot is taken.
 */
static void
ss_set_xact_readonly(void)
{
	if (XactReadOnly)
		return;

	set_config_option("transaction_read_only", "on",
					  PGC_USERSET, PGC_S_SESSION,
					  GUC_ACTION_LOCAL, true, 0, false);
}

/*
 * Check whether the utility command should be blocked by safesession.
 *
 * Core's ClassifyUtilityCommandAsReadOnly() allows VACUUM, ANALYZE,
 * CLUSTER, REINDEX and CHECKPOINT in read-only transactions.  This
 * function provides an additional layer of blocking for those commands
 * when configured via safesession.blocked_commands.
 */
static void
ss_check_blocked_utility(Node *parsetree)
{
	switch (nodeTag(parsetree))
	{
		case T_VacuumStmt:
			{
				VacuumStmt *stmt = (VacuumStmt *) parsetree;

				if (stmt->is_vacuumcmd && block_vacuum)
					ereport(ERROR,
							(errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION),
							 errmsg("VACUUM is blocked by safesession")));
				if (!stmt->is_vacuumcmd && block_analyze)
					ereport(ERROR,
							(errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION),
							 errmsg("ANALYZE is blocked by safesession")));
				break;
			}
		case T_ClusterStmt:
			if (block_cluster)
				ereport(ERROR,
						(errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION),
						 errmsg("CLUSTER is blocked by safesession")));
			break;
		case T_ReindexStmt:
			if (block_reindex)
				ereport(ERROR,
						(errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION),
						 errmsg("REINDEX is blocked by safesession")));
			break;
		case T_CheckPointStmt:
			if (block_checkpoint)
				ereport(ERROR,
						(errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION),
						 errmsg("CHECKPOINT is blocked by safesession")));
			break;
		default:
			break;
	}
}

/*
 * ExecutorStart hook.
 *
 * Set transaction_read_only = on via GUC machinery.  The downstream
 * standard_ExecutorStart will then call ExecCheckXactReadOnly(), which
 * enforces all the read-only checks: DML blocking, temp table exemptions,
 * modifying CTE detection, etc.
 */
static void
ss_exec(QueryDesc *queryDesc, int eflags)
{
	ss_set_xact_readonly();

	if (prev_executor_start_hook)
		(*prev_executor_start_hook)(queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);
}

/*
 * ProcessUtility hook.
 *
 * Set transaction_read_only = on via GUC machinery.  The downstream
 * standard_ProcessUtility uses ClassifyUtilityCommandAsReadOnly() +
 * PreventCommandIfReadOnly() to block DDL and other write commands.
 *
 * Additionally, check safesession.blocked_commands for utility commands
 * that core allows in read-only transactions but the administrator
 * wants to block.
 */
static void
ss_utility(PlannedStmt *pstmt, const char *queryString,
		   bool readOnlyTree,
		   ProcessUtilityContext context,
		   ParamListInfo params,
		   QueryEnvironment *queryEnv,
		   DestReceiver *dest, QueryCompletion *qc)
{
	ss_set_xact_readonly();
	ss_check_blocked_utility(pstmt->utilityStmt);

	if (prev_process_utility_hook)
		(*prev_process_utility_hook)(pstmt, queryString, readOnlyTree,
									 context, params, queryEnv,
									 dest, qc);
	else
		standard_ProcessUtility(pstmt, queryString, readOnlyTree,
								context, params, queryEnv,
								dest, qc);
}

/* -------------------------------------------------------------------------
 *
 * pg_authorization.c
 *
 * PostgreSQL Authorization Plugin
 *
 * This extension provides a framework for external authorization decisions.
 * It integrates with PostgreSQL's permission system through hooks and allows
 * authorization decisions to be delegated to external policy engines like
 * Cedar, OPA, or custom authorization services.
 *
 * Features:
 * - Intercepts DML permission checks (SELECT, INSERT, UPDATE, DELETE)
 * - Intercepts DDL operations via object_access_hook
 * - Intercepts utility commands via ProcessUtility_hook
 * - Supports external authorization service integration via HTTP/libcurl
 * - Configurable via GUC variables
 *
 * Copyright (c) 2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		contrib/pg_authorization/pg_authorization.c
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include <curl/curl.h>

#include "catalog/objectaccess.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_authid.h"
#include "commands/dbcommands.h"
#include "executor/executor.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "nodes/nodes.h"
#include "parser/parse_relation.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/authorization_hook.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

PG_MODULE_MAGIC;

/* SQL-callable functions */
PG_FUNCTION_INFO_V1(pg_authorization_is_enabled);

/* GUC variables */
static char *pg_authorization_url = NULL;
static int pg_authorization_timeout = 5000;	/* milliseconds */
static bool pg_authorization_enabled = true;
static bool pg_authorization_log_decisions = false;

/* Saved hook entries (for chaining) */
static object_access_hook_type prev_object_access_hook = NULL;
static ExecutorCheckPerms_hook_type prev_executor_check_perms_hook = NULL;
static ProcessUtility_hook_type prev_process_utility_hook = NULL;
static universal_authorization_hook_type prev_universal_auth_hook = NULL;

/* Forward declarations */
void		_PG_init(void);

static void pg_authorization_object_access(ObjectAccessType access,
										   Oid classId,
										   Oid objectId,
										   int subId,
										   void *arg);

static bool pg_authorization_exec_check_perms(List *rangeTable,
											  List *rteperminfos,
											  bool ereport_on_violation);

static void pg_authorization_utility(PlannedStmt *pstmt,
									 const char *queryString,
									 bool readOnlyTree,
									 ProcessUtilityContext context,
									 ParamListInfo params,
									 QueryEnvironment *queryEnv,
									 DestReceiver *dest,
									 QueryCompletion *qc);

static AuthorizationResult pg_authorization_hook(AuthorizationInfo *auth_info);

/* libcurl callback for response data */
static size_t
pg_auth_curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	StringInfo buf = (StringInfo) userp;

	appendBinaryStringInfo(buf, (char *) contents, realsize);
	return realsize;
}

/*
 * Call external authorization service.
 *
 * Returns the authorization result based on the external service response.
 */
static AuthorizationResult
call_external_authorization(AuthorizationInfo *auth_info)
{
	CURL	   *curl;
	CURLcode	res;
	StringInfoData request_body;
	StringInfoData response_body;
	struct curl_slist *headers = NULL;
	long		response_code;
	AuthorizationResult result = PG_AUTH_RESULT_IGNORE;
	char	   *privileges_str;

	/* Check if URL is configured */
	if (pg_authorization_url == NULL || pg_authorization_url[0] == '\0')
	{
		return PG_AUTH_RESULT_IGNORE;
	}

	curl = curl_easy_init();
	if (!curl)
	{
		ereport(WARNING,
				(errmsg("pg_authorization: failed to initialize curl")));
		return PG_AUTH_RESULT_IGNORE;
	}

	initStringInfo(&request_body);
	initStringInfo(&response_body);

	/* Build JSON request body */
	appendStringInfoString(&request_body, "{");

	/* Event type */
	appendStringInfo(&request_body, "\"event_type\":\"%s\"",
					 GetAuthorizationEventTypeName(auth_info->event_type));

	/* Role information */
	appendStringInfo(&request_body, ",\"roleid\":%u", auth_info->roleid);
	if (auth_info->rolename)
		appendStringInfo(&request_body, ",\"rolename\":\"%s\"", auth_info->rolename);

	/* Database information */
	appendStringInfo(&request_body, ",\"dboid\":%u", auth_info->dboid);
	if (auth_info->dbname)
		appendStringInfo(&request_body, ",\"dbname\":\"%s\"", auth_info->dbname);

	/* Event-specific information */
	switch (auth_info->event_type)
	{
		case PG_AUTH_EVENT_DML:
			appendStringInfo(&request_body, ",\"relid\":%u",
							 auth_info->info.dml.relid);
			if (auth_info->info.dml.relname)
				appendStringInfo(&request_body, ",\"relname\":\"%s\"",
								 auth_info->info.dml.relname);
			if (auth_info->info.dml.schemaname)
				appendStringInfo(&request_body, ",\"schemaname\":\"%s\"",
								 auth_info->info.dml.schemaname);

			privileges_str = AclModeToPrivilegeString(auth_info->info.dml.required_perms);
			appendStringInfo(&request_body, ",\"required_perms\":\"%s\"",
							 privileges_str);
			pfree(privileges_str);
			break;

		case PG_AUTH_EVENT_DDL:
		case PG_AUTH_EVENT_UTILITY:
			appendStringInfo(&request_body, ",\"classid\":%u",
							 auth_info->info.ddl.classid);
			appendStringInfo(&request_body, ",\"objectid\":%u",
							 auth_info->info.ddl.objectid);
			if (auth_info->info.ddl.objectname)
				appendStringInfo(&request_body, ",\"objectname\":\"%s\"",
								 auth_info->info.ddl.objectname);
			if (auth_info->info.ddl.schemaname)
				appendStringInfo(&request_body, ",\"schemaname\":\"%s\"",
								 auth_info->info.ddl.schemaname);
			if (auth_info->info.ddl.command_tag)
				appendStringInfo(&request_body, ",\"command_tag\":\"%s\"",
								 auth_info->info.ddl.command_tag);
			appendStringInfo(&request_body, ",\"is_internal\":%s",
							 auth_info->info.ddl.is_internal ? "true" : "false");
			break;

		default:
			break;
	}

	/* Query string (if available, truncate for safety) */
	if (auth_info->query_string)
	{
		char	   *escaped_query;
		int			max_len = 1000;	/* Limit query string length */
		int			query_len = strlen(auth_info->query_string);

		if (query_len > max_len)
			query_len = max_len;

		/* Simple JSON string escaping */
		escaped_query = palloc(query_len * 2 + 1);
		{
			const char *src = auth_info->query_string;
			char	   *dst = escaped_query;
			int			i;

			for (i = 0; i < query_len && *src; i++, src++)
			{
				if (*src == '"' || *src == '\\')
					*dst++ = '\\';
				else if (*src == '\n')
				{
					*dst++ = '\\';
					*dst++ = 'n';
					continue;
				}
				else if (*src == '\r')
				{
					*dst++ = '\\';
					*dst++ = 'r';
					continue;
				}
				else if (*src == '\t')
				{
					*dst++ = '\\';
					*dst++ = 't';
					continue;
				}
				*dst++ = *src;
			}
			*dst = '\0';
		}

		appendStringInfo(&request_body, ",\"query\":\"%s\"", escaped_query);
		pfree(escaped_query);
	}

	appendStringInfoString(&request_body, "}");

	/* Setup curl request */
	curl_easy_setopt(curl, CURLOPT_URL, pg_authorization_url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body.data);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pg_auth_curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, pg_authorization_timeout);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);

	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	/* Perform the request */
	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
	{
		ereport(WARNING,
				(errmsg("pg_authorization: curl request failed: %s",
						curl_easy_strerror(res))));
		result = PG_AUTH_RESULT_IGNORE;
	}
	else
	{
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

		if (response_code == 200)
		{
			/* Parse response - look for "result" field */
			if (strstr(response_body.data, "\"grant\"") != NULL ||
				strstr(response_body.data, "\"GRANT\"") != NULL)
				result = PG_AUTH_RESULT_GRANT;
			else if (strstr(response_body.data, "\"deny\"") != NULL ||
					 strstr(response_body.data, "\"DENY\"") != NULL)
				result = PG_AUTH_RESULT_DENY;
			else
				result = PG_AUTH_RESULT_IGNORE;
		}
		else
		{
			ereport(WARNING,
					(errmsg("pg_authorization: external service returned status %ld",
							response_code)));
			result = PG_AUTH_RESULT_IGNORE;
		}
	}

	/* Cleanup */
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	pfree(request_body.data);
	pfree(response_body.data);

	/* Log decision if enabled */
	if (pg_authorization_log_decisions)
	{
		ereport(LOG,
				(errmsg("pg_authorization: event=%s, role=%u, result=%s",
						GetAuthorizationEventTypeName(auth_info->event_type),
						auth_info->roleid,
						GetAuthorizationResultName(result))));
	}

	return result;
}

/*
 * Universal authorization hook callback.
 *
 * This is called for ACL checks and allows us to intercept
 * authorization decisions.
 */
static AuthorizationResult
pg_authorization_hook(AuthorizationInfo *auth_info)
{
	AuthorizationResult result;

	/* Chain to previous hook if any */
	if (prev_universal_auth_hook)
	{
		result = prev_universal_auth_hook(auth_info);
		if (result != PG_AUTH_RESULT_IGNORE)
			return result;
	}

	/* Check if plugin is enabled */
	if (!pg_authorization_enabled)
		return PG_AUTH_RESULT_IGNORE;

	/* Call external authorization service */
	return call_external_authorization(auth_info);
}

/*
 * Object access hook callback.
 *
 * Called for DDL operations (CREATE, ALTER, DROP, etc.)
 */
static void
pg_authorization_object_access(ObjectAccessType access,
							   Oid classId,
							   Oid objectId,
							   int subId,
							   void *arg)
{
	/* Chain to previous hook first */
	if (prev_object_access_hook)
		prev_object_access_hook(access, classId, objectId, subId, arg);

	/* Check if plugin is enabled */
	if (!pg_authorization_enabled)
		return;

	/* Only handle events if we have an external service configured */
	if (pg_authorization_url == NULL || pg_authorization_url[0] == '\0')
		return;

	/* Build authorization info and call hook */
	{
		AuthorizationInfo auth_info;
		AuthorizationResult result;

		InitAuthorizationInfo(&auth_info, PG_AUTH_EVENT_DDL, GetUserId());

		auth_info.info.ddl.classid = classId;
		auth_info.info.ddl.objectid = objectId;
		auth_info.info.ddl.subid = subId;

		/* Set command tag based on access type */
		switch (access)
		{
			case OAT_POST_CREATE:
				auth_info.info.ddl.command_tag = "CREATE";
				auth_info.info.ddl.is_internal =
					arg ? ((ObjectAccessPostCreate *) arg)->is_internal : false;
				break;
			case OAT_DROP:
				auth_info.info.ddl.command_tag = "DROP";
				break;
			case OAT_POST_ALTER:
				auth_info.info.ddl.command_tag = "ALTER";
				auth_info.info.ddl.is_internal =
					arg ? ((ObjectAccessPostAlter *) arg)->is_internal : false;
				break;
			case OAT_TRUNCATE:
				auth_info.info.ddl.command_tag = "TRUNCATE";
				break;
			case OAT_NAMESPACE_SEARCH:
				auth_info.event_type = PG_AUTH_EVENT_OBJECT_ACCESS;
				auth_info.info.ddl.command_tag = "NAMESPACE_SEARCH";
				break;
			case OAT_FUNCTION_EXECUTE:
				auth_info.event_type = PG_AUTH_EVENT_OBJECT_ACCESS;
				auth_info.info.ddl.command_tag = "FUNCTION_EXECUTE";
				break;
		}

		/* Try to get object name */
		if (classId == RelationRelationId && OidIsValid(objectId))
		{
			auth_info.info.ddl.objectname = get_rel_name(objectId);
			auth_info.info.ddl.schemaname = get_namespace_name(
												get_rel_namespace(objectId));
		}
		else if (classId == NamespaceRelationId && OidIsValid(objectId))
		{
			auth_info.info.ddl.objectname = get_namespace_name(objectId);
		}
		else if (classId == ProcedureRelationId && OidIsValid(objectId))
		{
			HeapTuple	procTup;

			procTup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));
			if (HeapTupleIsValid(procTup))
			{
				Form_pg_proc procForm = (Form_pg_proc) GETSTRUCT(procTup);

				auth_info.info.ddl.objectname = NameStr(procForm->proname);
				auth_info.info.ddl.schemaname = get_namespace_name(procForm->pronamespace);
				ReleaseSysCache(procTup);
			}
		}

		result = call_external_authorization(&auth_info);

		/* Handle DENY result by raising an error */
		if (result == PG_AUTH_RESULT_DENY)
		{
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied by authorization policy"),
					 errdetail("External authorization service denied the operation.")));
		}
	}
}

/*
 * Executor permission check hook callback.
 *
 * Called for DML operations (SELECT, INSERT, UPDATE, DELETE)
 */
static bool
pg_authorization_exec_check_perms(List *rangeTable,
								  List *rteperminfos,
								  bool ereport_on_violation)
{
	ListCell   *l;
	bool		result = true;

	/* Chain to previous hook first */
	if (prev_executor_check_perms_hook &&
		!prev_executor_check_perms_hook(rangeTable, rteperminfos, ereport_on_violation))
		return false;

	/* Check if plugin is enabled */
	if (!pg_authorization_enabled)
		return true;

	/* Check if we have an external service configured */
	if (pg_authorization_url == NULL || pg_authorization_url[0] == '\0')
		return true;

	/* Check each relation in the query */
	foreach(l, rteperminfos)
	{
		RTEPermissionInfo *perminfo = lfirst_node(RTEPermissionInfo, l);
		AuthorizationInfo auth_info;
		AuthorizationResult auth_result;

		InitAuthorizationInfo(&auth_info, PG_AUTH_EVENT_DML, GetUserId());

		auth_info.info.dml.relid = perminfo->relid;
		auth_info.info.dml.relname = get_rel_name(perminfo->relid);
		auth_info.info.dml.schemaname = get_namespace_name(
										get_rel_namespace(perminfo->relid));
		auth_info.info.dml.required_perms = perminfo->requiredPerms;
		auth_info.info.dml.selected_cols = perminfo->selectedCols;
		auth_info.info.dml.inserted_cols = perminfo->insertedCols;
		auth_info.info.dml.updated_cols = perminfo->updatedCols;

		auth_result = call_external_authorization(&auth_info);

		if (auth_result == PG_AUTH_RESULT_DENY)
		{
			if (ereport_on_violation)
			{
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("permission denied for relation %s",
								auth_info.info.dml.relname),
						 errdetail("External authorization service denied the operation.")));
			}
			result = false;
		}
		else if (auth_result == PG_AUTH_RESULT_GRANT)
		{
			/* Grant overrides native checks - continue checking other relations */
		}
		/* PG_AUTH_RESULT_IGNORE lets native checks handle it */
	}

	return result;
}

/*
 * Process utility hook callback.
 *
 * Called for utility commands (DDL, VACUUM, etc.)
 */
static void
pg_authorization_utility(PlannedStmt *pstmt,
						 const char *queryString,
						 bool readOnlyTree,
						 ProcessUtilityContext context,
						 ParamListInfo params,
						 QueryEnvironment *queryEnv,
						 DestReceiver *dest,
						 QueryCompletion *qc)
{
	/* Check if plugin is enabled and URL is configured */
	if (pg_authorization_enabled &&
		pg_authorization_url != NULL &&
		pg_authorization_url[0] != '\0')
	{
		AuthorizationInfo auth_info;
		AuthorizationResult result;
		Node	   *parsetree = pstmt->utilityStmt;

		InitAuthorizationInfo(&auth_info, PG_AUTH_EVENT_UTILITY, GetUserId());

		auth_info.info.ddl.parse_tree = parsetree;
		auth_info.info.ddl.command_tag = CreateCommandName(parsetree);
		auth_info.query_string = queryString;

		result = call_external_authorization(&auth_info);

		if (result == PG_AUTH_RESULT_DENY)
		{
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied by authorization policy"),
					 errdetail("External authorization service denied the utility command.")));
		}
	}

	/* Chain to next hook or standard processing */
	if (prev_process_utility_hook)
		prev_process_utility_hook(pstmt, queryString, readOnlyTree,
								  context, params, queryEnv, dest, qc);
	else
		standard_ProcessUtility(pstmt, queryString, readOnlyTree,
								context, params, queryEnv, dest, qc);
}

/*
 * Module initialization function.
 */
void
_PG_init(void)
{
	/* Initialize libcurl */
	curl_global_init(CURL_GLOBAL_ALL);

	/* Define GUC variables */
	DefineCustomStringVariable("pg_authorization.url",
							   "URL of the external authorization service",
							   "When set, authorization requests are sent to this URL via HTTP POST. "
							   "The service should return JSON with a 'result' field (grant/deny/ignore).",
							   &pg_authorization_url,
							   "",
							   PGC_SIGHUP,
							   0,
							   NULL,
							   NULL,
							   NULL);

	DefineCustomIntVariable("pg_authorization.timeout",
							"Timeout for external authorization requests in milliseconds",
							NULL,
							&pg_authorization_timeout,
							5000,
							100,
							60000,
							PGC_SIGHUP,
							GUC_UNIT_MS,
							NULL,
							NULL,
							NULL);

	DefineCustomBoolVariable("pg_authorization.enabled",
							 "Enable or disable the authorization plugin",
							 NULL,
							 &pg_authorization_enabled,
							 true,
							 PGC_SIGHUP,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomBoolVariable("pg_authorization.log_decisions",
							 "Log authorization decisions",
							 "When enabled, all authorization decisions are logged.",
							 &pg_authorization_log_decisions,
							 false,
							 PGC_SIGHUP,
							 0,
							 NULL,
							 NULL,
							 NULL);

	MarkGUCPrefixReserved("pg_authorization");

	/* Install hooks */
	prev_object_access_hook = object_access_hook;
	object_access_hook = pg_authorization_object_access;

	prev_executor_check_perms_hook = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = pg_authorization_exec_check_perms;

	prev_process_utility_hook = ProcessUtility_hook;
	ProcessUtility_hook = pg_authorization_utility;

	prev_universal_auth_hook = universal_authorization_hook;
	universal_authorization_hook = pg_authorization_hook;

	ereport(LOG,
			(errmsg("pg_authorization: extension loaded")));
}

/*
 * SQL-callable function to check if the plugin is enabled.
 */
Datum
pg_authorization_is_enabled(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(pg_authorization_enabled);
}


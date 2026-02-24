/* -------------------------------------------------------------------------
 *
 * pg_cedar.c
 *
 * Embedded Cedar Authorization Engine for PostgreSQL
 *
 * This extension embeds the Cedar policy engine directly inside the
 * PostgreSQL backend process via libcedar C bindings.  No external
 * Cedar agent is required — authorization decisions are evaluated
 * in-process with microsecond latency.
 *
 * Features:
 * - Per-backend CedarEngine instance (one per connection)
 * - Policies, schemas, and entities stored in extension-managed tables
 * - Intercepts authorization via universal_authorization_hook
 * - Entity auto-sync via object_access_hook and ProcessUtility_hook
 * - Decision caching in shared memory
 * - Audit logging to cedar_audit_log table
 *
 * Copyright (c) 2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		contrib/pg_cedar/pg_cedar.c
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include <time.h>

#include "libcedar.h"

#include "access/htup_details.h"
#include "access/relation.h"
#include "access/table.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "commands/dbcommands.h"
#include "common/hashfn.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "nodes/nodes.h"
#include "nodes/parsenodes.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/authorization_hook.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/timestamp.h"

PG_MODULE_MAGIC;

/* SQL-callable functions */
PG_FUNCTION_INFO_V1(pg_cedar_is_enabled);
PG_FUNCTION_INFO_V1(pg_cedar_set_policies);
PG_FUNCTION_INFO_V1(pg_cedar_set_schema);
PG_FUNCTION_INFO_V1(pg_cedar_set_entities);
PG_FUNCTION_INFO_V1(pg_cedar_is_authorized);
PG_FUNCTION_INFO_V1(pg_cedar_validate);
PG_FUNCTION_INFO_V1(pg_cedar_explain_decision);
PG_FUNCTION_INFO_V1(pg_cedar_reload);
PG_FUNCTION_INFO_V1(pg_cedar_stats);
PG_FUNCTION_INFO_V1(pg_cedar_reset_stats);
PG_FUNCTION_INFO_V1(pg_cedar_cache_stats);
PG_FUNCTION_INFO_V1(pg_cedar_cache_reset);

/* --------------------------------------------------------------------------
 * GUC variables
 * --------------------------------------------------------------------------
 */
static bool cedar_enabled = true;
static char *cedar_namespace = NULL;
static bool cedar_log_decisions = false;
static bool cedar_audit_enabled = false;
static bool cedar_collect_stats = true;
static char *cedar_default_policy = NULL;

/* Caching GUCs */
static bool cedar_cache_enabled = true;
static int cedar_cache_size = 1024;
static int cedar_cache_ttl = 300; /* seconds */

/* --------------------------------------------------------------------------
 * Cache structures (shared memory)
 * --------------------------------------------------------------------------
 */
typedef struct AuthCacheKey {
  Oid roleid;
  Oid classid;
  Oid resource_oid;
  int32 subid;
  int32 action;
} AuthCacheKey;

typedef struct AuthCacheEntry {
  AuthCacheKey key;
  AuthorizationResult result;
  TimestampTz created_at;
  TimestampTz expires;
} AuthCacheEntry;

/* --------------------------------------------------------------------------
 * Statistics (shared memory)
 * --------------------------------------------------------------------------
 */
typedef struct pg_cedar_stats_t {
  long auth_requests;
  long auth_grants;
  long auth_denies;
  long auth_ignores;
  long auth_errors;
  double eval_total_us;
  TimestampTz last_cache_reset;
} pg_cedar_stats_t;

typedef struct pg_cedar_cache_stats_t {
  long hits;
  long misses;
  long evictions;
} pg_cedar_cache_stats_t;

static pg_cedar_stats_t *stats = NULL;
static pg_cedar_cache_stats_t *cache_stats = NULL;

/* --------------------------------------------------------------------------
 * Internal state
 * --------------------------------------------------------------------------
 */
static struct CedarEngine *cedar_engine = NULL;
static bool cedar_engine_loaded = false;
static HTAB *auth_cache = NULL;
static LWLock *auth_cache_lock = NULL;

/* Shared memory hooks */
static shmem_request_hook_type prev_shmem_request_hook = NULL;
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

/* Authorization hooks */
static object_access_hook_type prev_object_access_hook = NULL;
static ProcessUtility_hook_type prev_process_utility_hook = NULL;
static universal_authorization_hook_type prev_universal_auth_hook = NULL;

/* SPI guard: prevent re-entrant SPI calls from hooks during SPI */
static bool spi_in_progress = false;

/* --------------------------------------------------------------------------
 * Forward declarations
 * --------------------------------------------------------------------------
 */
void _PG_init(void);
void _PG_fini(void);

static AuthorizationResult
cedar_authorization_hook(AuthorizationInfo *auth_info);
static void cedar_object_access_hook(ObjectAccessType access, Oid classId,
                                     Oid objectId, int subId, void *arg);
static void
cedar_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                           bool readOnlyTree, ProcessUtilityContext context,
                           ParamListInfo params, QueryEnvironment *queryEnv,
                           DestReceiver *dest, QueryCompletion *qc);

static void reset_auth_cache(void);
static AuthorizationResult check_auth_cache(Oid roleid, Oid classid,
                                            Oid resource_oid, int32 subid,
                                            int32 action);
static void update_auth_cache(Oid roleid, Oid classid, Oid resource_oid,
                              int32 subid, int32 action,
                              AuthorizationResult result);

static bool ensure_cedar_engine(void);
static bool load_policies_from_catalog(void);
static bool load_schema_from_catalog(void);
static bool load_entities_from_catalog(void);

/* --------------------------------------------------------------------------
 * Shared Memory Management
 * --------------------------------------------------------------------------
 */
static size_t pg_cedar_shmem_size(void) {
  size_t size;

  size = MAXALIGN(sizeof(pg_cedar_stats_t));
  size = add_size(size, MAXALIGN(sizeof(pg_cedar_cache_stats_t)));
  size = add_size(size,
                  hash_estimate_size(cedar_cache_size, sizeof(AuthCacheEntry)));
  return size;
}

static void pg_cedar_shmem_request(void) {
  if (prev_shmem_request_hook)
    prev_shmem_request_hook();

  RequestAddinShmemSpace(pg_cedar_shmem_size());
  RequestNamedLWLockTranche("pg_cedar", 1);
}

static void pg_cedar_shmem_startup(void) {
  bool found;
  HASHCTL ctl;

  if (prev_shmem_startup_hook)
    prev_shmem_startup_hook();

  LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

  stats = (pg_cedar_stats_t *)ShmemInitStruct("pg_cedar_stats",
                                              sizeof(pg_cedar_stats_t), &found);
  if (!found)
    memset(stats, 0, sizeof(pg_cedar_stats_t));

  cache_stats = (pg_cedar_cache_stats_t *)ShmemInitStruct(
      "pg_cedar_cache_stats", sizeof(pg_cedar_cache_stats_t), &found);
  if (!found)
    memset(cache_stats, 0, sizeof(pg_cedar_cache_stats_t));

  memset(&ctl, 0, sizeof(ctl));
  ctl.keysize = sizeof(AuthCacheKey);
  ctl.entrysize = sizeof(AuthCacheEntry);
  auth_cache = ShmemInitHash("pg_cedar_cache", cedar_cache_size,
                             cedar_cache_size, &ctl, HASH_ELEM | HASH_BLOBS);

  auth_cache_lock = &(GetNamedLWLockTranche("pg_cedar"))[0].lock;

  LWLockRelease(AddinShmemInitLock);
}

/* --------------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------------
 */

/* Get current day as lowercase string */
static const char *get_current_day(void) {
  static const char *days[] = {"sun", "mon", "tue", "wed", "thu", "fri", "sat"};
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);

  return days[tm_info->tm_wday];
}

/* Get current date as YYYYMMDD integer */
static int get_current_date_int(void) {
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);

  return (tm_info->tm_year + 1900) * 10000 + (tm_info->tm_mon + 1) * 100 +
         tm_info->tm_mday;
}

/* Get client IP address */
static const char *get_client_ip(void) {
  if (MyProcPort && MyProcPort->remote_host) {
    if (strcmp(MyProcPort->remote_host, "[local]") == 0 ||
        strcmp(MyProcPort->remote_host, "unknown") == 0)
      return "127.0.0.1";
    return MyProcPort->remote_host;
  }
  return "127.0.0.1";
}

/* Map AclMode bit to Cedar action string */
static const char *get_cedar_action_for_bit(AclMode bit) {
  if (bit == ACL_SELECT)
    return "SELECT";
  if (bit == ACL_INSERT)
    return "INSERT";
  if (bit == ACL_UPDATE)
    return "UPDATE";
  if (bit == ACL_DELETE)
    return "DELETE";
  if (bit == ACL_TRUNCATE)
    return "TRUNCATE";
  if (bit == ACL_REFERENCES)
    return "REFERENCES";
  if (bit == ACL_TRIGGER)
    return "TRIGGER";
  if (bit == ACL_EXECUTE)
    return "EXECUTE";
  if (bit == ACL_USAGE)
    return "USAGE";
  if (bit == ACL_CREATE)
    return "CREATE";
  if (bit == ACL_CREATE_TEMP)
    return "CREATE_TEMP";
  if (bit == ACL_CONNECT)
    return "CONNECT";
  if (bit == ACL_SET)
    return "SET";
  if (bit == ACL_ALTER_SYSTEM)
    return "ALTER_SYSTEM";
  if (bit == ACL_MAINTAIN)
    return "MAINTAIN";
  return NULL;
}

/* JSON-escape a string */
static char *json_escape_string(const char *str) {
  StringInfoData buf;
  const char *p;

  if (str == NULL)
    return pstrdup("");

  initStringInfo(&buf);
  for (p = str; *p; p++) {
    switch (*p) {
    case '"':
      appendStringInfoString(&buf, "\\\"");
      break;
    case '\\':
      appendStringInfoString(&buf, "\\\\");
      break;
    case '\n':
      appendStringInfoString(&buf, "\\n");
      break;
    case '\r':
      appendStringInfoString(&buf, "\\r");
      break;
    case '\t':
      appendStringInfoString(&buf, "\\t");
      break;
    default:
      if ((unsigned char)*p < 0x20)
        appendStringInfo(&buf, "\\u%04x", (unsigned char)*p);
      else
        appendStringInfoChar(&buf, *p);
      break;
    }
  }
  return buf.data;
}

/* --------------------------------------------------------------------------
 * CedarEngine lifecycle
 * --------------------------------------------------------------------------
 */

/* Ensure the per-backend CedarEngine is initialized and loaded */
static bool ensure_cedar_engine(void) {
  if (cedar_engine == NULL) {
    cedar_engine = cedar_engine_new();
    if (cedar_engine == NULL) {
      ereport(WARNING, (errmsg("pg_cedar: failed to create Cedar engine")));
      return false;
    }
    cedar_engine_loaded = false;
  }

  if (!cedar_engine_loaded) {
    bool loaded_any = false;

    /* Load default policy from GUC if set */
    if (cedar_default_policy && cedar_default_policy[0] != '\0') {
      int rc = cedar_engine_set_policies(cedar_engine, cedar_default_policy);
      if (rc != 0) {
        const char *err = cedar_engine_last_error(cedar_engine);
        ereport(WARNING, (errmsg("pg_cedar: failed to load default policy: %s",
                                 err ? err : "unknown error")));
      } else {
        loaded_any = true;
      }
    }

    /*
     * Try to load from catalog tables via SPI.
     * This may fail early in startup when SPI is not yet available.
     */
    if (!spi_in_progress) {
      spi_in_progress = true;

      PG_TRY();
      {
        if (load_policies_from_catalog())
          loaded_any = true;
        load_schema_from_catalog();
        load_entities_from_catalog();
      }
      PG_CATCH();
      {
        /* Catalog tables may not exist yet (before CREATE EXTENSION) */
        FlushErrorState();
      }
      PG_END_TRY();

      spi_in_progress = false;
    }

    cedar_engine_loaded =
        loaded_any || (cedar_default_policy && cedar_default_policy[0] != '\0');
  }

  return (cedar_engine != NULL);
}

/* Load active policies from cedar_policies table */
static bool load_policies_from_catalog(void) {
  int ret;
  bool loaded = false;
  StringInfoData all_policies;

  ret = SPI_connect();
  if (ret != SPI_OK_CONNECT)
    return false;

  ret = SPI_execute(
      "SELECT policy_text FROM cedar_policies WHERE is_active = true "
      "ORDER BY id",
      true, 0);

  if (ret == SPI_OK_SELECT && SPI_processed > 0) {
    uint64 i;

    initStringInfo(&all_policies);
    for (i = 0; i < SPI_processed; i++) {
      char *ptext =
          SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1);
      if (ptext) {
        appendStringInfoString(&all_policies, ptext);
        appendStringInfoChar(&all_policies, '\n');
        pfree(ptext);
      }
    }

    if (all_policies.len > 0) {
      int rc = cedar_engine_set_policies(cedar_engine, all_policies.data);
      if (rc == 0)
        loaded = true;
      else {
        const char *err = cedar_engine_last_error(cedar_engine);
        ereport(WARNING, (errmsg("pg_cedar: policy load error: %s",
                                 err ? err : "unknown")));
      }
    }

    pfree(all_policies.data);
  }

  SPI_finish();
  return loaded;
}

/* Load active schema from cedar_schemas table */
static bool load_schema_from_catalog(void) {
  int ret;
  bool loaded = false;

  ret = SPI_connect();
  if (ret != SPI_OK_CONNECT)
    return false;

  ret = SPI_execute(
      "SELECT schema_json FROM cedar_schemas WHERE is_active = true "
      "ORDER BY id LIMIT 1",
      true, 0);

  if (ret == SPI_OK_SELECT && SPI_processed > 0) {
    char *schema_json =
        SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
    if (schema_json) {
      int rc = cedar_engine_set_schema_json(cedar_engine, schema_json);
      if (rc == 0)
        loaded = true;
      else {
        const char *err = cedar_engine_last_error(cedar_engine);
        ereport(WARNING, (errmsg("pg_cedar: schema load error: %s",
                                 err ? err : "unknown")));
      }
      pfree(schema_json);
    }
  }

  SPI_finish();
  return loaded;
}

/* Load active entities from cedar_entities table */
static bool load_entities_from_catalog(void) {
  int ret;
  bool loaded = false;

  ret = SPI_connect();
  if (ret != SPI_OK_CONNECT)
    return false;

  ret = SPI_execute(
      "SELECT entities_json FROM cedar_entities WHERE is_active = true "
      "ORDER BY id DESC LIMIT 1",
      true, 0);

  if (ret == SPI_OK_SELECT && SPI_processed > 0) {
    char *entities_json =
        SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
    if (entities_json) {
      int rc = cedar_engine_set_entities_json(cedar_engine, entities_json);
      if (rc == 0)
        loaded = true;
      else {
        const char *err = cedar_engine_last_error(cedar_engine);
        ereport(WARNING, (errmsg("pg_cedar: entities load error: %s",
                                 err ? err : "unknown")));
      }
      pfree(entities_json);
    }
  }

  SPI_finish();
  return loaded;
}

/* --------------------------------------------------------------------------
 * Core evaluation function (replaces HTTP call)
 * --------------------------------------------------------------------------
 */
static AuthorizationResult cedar_evaluate(const char *principal_type,
                                          const char *principal_id,
                                          const char *action,
                                          const char *resource_type,
                                          const char *resource_id) {
  StringInfoData principal_buf;
  StringInfoData action_buf;
  StringInfoData resource_buf;
  StringInfoData context_buf;
  enum CedarDecision decision;
  AuthorizationResult result;
  char *escaped_principal;
  char *escaped_resource;

  if (!ensure_cedar_engine())
    return PG_AUTH_RESULT_IGNORE;

  escaped_principal = json_escape_string(principal_id);
  escaped_resource = json_escape_string(resource_id);

  /* Build Cedar UID strings */
  initStringInfo(&principal_buf);
  initStringInfo(&action_buf);
  initStringInfo(&resource_buf);
  initStringInfo(&context_buf);

  if (cedar_namespace && cedar_namespace[0] != '\0') {
    appendStringInfo(&principal_buf, "%s::%s::\"%s\"", cedar_namespace,
                     principal_type, escaped_principal);
    appendStringInfo(&action_buf, "%s::Action::\"%s\"", cedar_namespace,
                     action);
    appendStringInfo(&resource_buf, "%s::%s::\"%s\"", cedar_namespace,
                     resource_type, escaped_resource);
  } else {
    appendStringInfo(&principal_buf, "%s::\"%s\"", principal_type,
                     escaped_principal);
    appendStringInfo(&action_buf, "Action::\"%s\"", action);
    appendStringInfo(&resource_buf, "%s::\"%s\"", resource_type,
                     escaped_resource);
  }

  pfree(escaped_principal);
  pfree(escaped_resource);

  /* Build context JSON */
  appendStringInfo(&context_buf,
                   "{\"day\":\"%s\",\"date\":%d,"
                   "\"ip\":{\"__extn\":{\"fn\":\"ip\",\"arg\":\"%s\"}}}",
                   get_current_day(), get_current_date_int(), get_client_ip());

  /* Evaluate */
  decision = cedar_engine_is_authorized(cedar_engine, principal_buf.data,
                                        action_buf.data, resource_buf.data,
                                        context_buf.data);

  switch (decision) {
  case Allow:
    result = PG_AUTH_RESULT_GRANT;
    if (cedar_collect_stats && stats)
      stats->auth_grants++;
    break;
  case Deny:
    result = PG_AUTH_RESULT_DENY;
    if (cedar_collect_stats && stats)
      stats->auth_denies++;
    break;
  default:
    result = PG_AUTH_RESULT_IGNORE;
    if (cedar_collect_stats && stats)
      stats->auth_errors++;
    break;
  }

  if (cedar_log_decisions) {
    ereport(LOG, (errmsg("pg_cedar: %s -> %s | %s on %s", principal_buf.data,
                         action_buf.data,
                         result == PG_AUTH_RESULT_GRANT  ? "ALLOW"
                         : result == PG_AUTH_RESULT_DENY ? "DENY"
                                                         : "IGNORE",
                         resource_buf.data)));
  }

  pfree(principal_buf.data);
  pfree(action_buf.data);
  pfree(resource_buf.data);
  pfree(context_buf.data);

  return result;
}

/* --------------------------------------------------------------------------
 * Authorization hook (same routing logic as pg_authorization)
 * --------------------------------------------------------------------------
 */
static AuthorizationResult
cedar_authorization_hook(AuthorizationInfo *auth_info) {
  AuthorizationResult result = PG_AUTH_RESULT_GRANT;
  AclMode required_perms = 0;
  bool check_perms_loop = false;
  char *resolved_rolename = NULL;
  const char *rolename = auth_info->rolename;
  const char *resource_type = NULL;
  char *resource_id_str = NULL;
  bool have_resource_id = false;
  bool have_resolved_rolename = false;
  Oid classid = InvalidOid;
  Oid resource_oid = InvalidOid;
  int32 subid = 0;

  if (prev_universal_auth_hook) {
    result = prev_universal_auth_hook(auth_info);
    if (result != PG_AUTH_RESULT_IGNORE)
      return result;
  }

  if (!cedar_enabled)
    return PG_AUTH_RESULT_IGNORE;

  /* Superusers bypass external authorization */
  if (superuser_arg(auth_info->roleid))
    return PG_AUTH_RESULT_IGNORE;

  /* Engine must be available */
  if (!ensure_cedar_engine() || !cedar_engine_loaded)
    return PG_AUTH_RESULT_IGNORE;

  if (cedar_collect_stats && stats)
    stats->auth_requests++;

  switch (auth_info->event_type) {
  case PG_AUTH_EVENT_DML:
    required_perms = auth_info->info.dml.required_perms;
    check_perms_loop = true;
    classid = RelationRelationId;
    resource_oid = auth_info->info.dml.relid;
    subid = 0;
    resource_type = "Table";
    break;

  case PG_AUTH_EVENT_DDL:
  case PG_AUTH_EVENT_UTILITY: {
    int32 action_key;
    AuthorizationResult cached;

    if (!auth_info->info.ddl.command_tag) {
      result = PG_AUTH_RESULT_IGNORE;
      goto cleanup;
    }

    check_perms_loop = false;
    classid = auth_info->info.ddl.classid;
    resource_oid = auth_info->info.ddl.objectid;
    subid = auth_info->info.ddl.subid;

    if (classid == RelationRelationId)
      resource_type = "Table";
    else if (classid == NamespaceRelationId)
      resource_type = "Schema";
    else if (classid == DatabaseRelationId)
      resource_type = "Database";
    else if (classid == AuthIdRelationId)
      resource_type = "User";
    else if (classid == ProcedureRelationId)
      resource_type = "Routine";
    else
      resource_type = "Object";

    action_key =
        (int32)hash_any((const unsigned char *)auth_info->info.ddl.command_tag,
                        (int)strlen(auth_info->info.ddl.command_tag));

    cached = check_auth_cache(auth_info->roleid, classid, resource_oid, subid,
                              action_key);
    if (cached != PG_AUTH_RESULT_IGNORE) {
      result = cached;
      goto cleanup;
    }

    /* Resolve rolename */
    if (rolename == NULL || rolename[0] == '\0') {
      HeapTuple roleTup =
          SearchSysCache1(AUTHOID, ObjectIdGetDatum(auth_info->roleid));
      if (HeapTupleIsValid(roleTup)) {
        Form_pg_authid roleForm = (Form_pg_authid)GETSTRUCT(roleTup);
        resolved_rolename = pstrdup(NameStr(roleForm->rolname));
        rolename = resolved_rolename;
        have_resolved_rolename = true;
        ReleaseSysCache(roleTup);
      } else
        rolename = "unknown";
    }

    /* Resolve resource name */
    if (auth_info->info.ddl.schemaname && auth_info->info.ddl.objectname)
      resource_id_str = psprintf("%s.%s", auth_info->info.ddl.schemaname,
                                 auth_info->info.ddl.objectname);
    else if (auth_info->info.ddl.objectname)
      resource_id_str = pstrdup(auth_info->info.ddl.objectname);
    else
      resource_id_str = psprintf("oid_%u", auth_info->info.ddl.objectid);
    have_resource_id = true;

    result = cedar_evaluate("User", rolename, auth_info->info.ddl.command_tag,
                            resource_type, resource_id_str);

    if (result != PG_AUTH_RESULT_IGNORE)
      update_auth_cache(auth_info->roleid, classid, resource_oid, subid,
                        action_key, result);

    goto cleanup;
  }

  case PG_AUTH_EVENT_ACL_CHECK: {
    required_perms = auth_info->info.ddl.required_perms;
    check_perms_loop = true;
    classid = auth_info->info.ddl.classid;
    resource_oid = auth_info->info.ddl.objectid;
    subid = auth_info->info.ddl.subid;

    if (classid == RelationRelationId)
      resource_type = (subid != 0) ? "Column" : "Table";
    else if (classid == NamespaceRelationId)
      resource_type = "Schema";
    else if (classid == TypeRelationId)
      resource_type = "Type";
    else if (classid == DatabaseRelationId)
      resource_type = "Database";
    else if (classid == ProcedureRelationId)
      resource_type = "Routine";
    else if (classid == AuthIdRelationId)
      resource_type = "User";
    else
      resource_type = "Object";
    break;
  }

  default:
    result = PG_AUTH_RESULT_IGNORE;
    goto cleanup;
  }

  /* Permission bit loop (DML and ACL_CHECK events) */
  if (check_perms_loop) {
    int i;

    if (required_perms == 0) {
      result = PG_AUTH_RESULT_GRANT;
      goto cleanup;
    }
    result = PG_AUTH_RESULT_DENY;

    for (i = 0; i < 32; i++) {
      AclMode bit = (1 << i);
      int32 action_key;
      AuthorizationResult cached;

      if ((required_perms & bit) == 0)
        continue;

      action_key = (int32)bit;
      cached = check_auth_cache(auth_info->roleid, classid, resource_oid, subid,
                                action_key);
      if (cached != PG_AUTH_RESULT_IGNORE) {
        if (cached != PG_AUTH_RESULT_GRANT) {
          result = cached;
          goto cleanup;
        }
        continue;
      }

      /* Resolve rolename on first cache miss */
      if (rolename == NULL || rolename[0] == '\0') {
        HeapTuple roleTup =
            SearchSysCache1(AUTHOID, ObjectIdGetDatum(auth_info->roleid));
        if (HeapTupleIsValid(roleTup)) {
          Form_pg_authid roleForm = (Form_pg_authid)GETSTRUCT(roleTup);
          resolved_rolename = pstrdup(NameStr(roleForm->rolname));
          rolename = resolved_rolename;
          have_resolved_rolename = true;
          ReleaseSysCache(roleTup);
        } else
          rolename = "unknown";
      }

      /* Resolve resource ID on first cache miss */
      if (!have_resource_id) {
        if (auth_info->event_type == PG_AUTH_EVENT_DML) {
          if (auth_info->info.dml.schemaname && auth_info->info.dml.relname)
            resource_id_str = psprintf("%s.%s", auth_info->info.dml.schemaname,
                                       auth_info->info.dml.relname);
          else if (auth_info->info.dml.relname)
            resource_id_str = pstrdup(auth_info->info.dml.relname);
          else
            resource_id_str = psprintf("oid_%u", auth_info->info.dml.relid);
        } else if (classid == RelationRelationId) {
          char *rel_name = get_rel_name(resource_oid);
          if (rel_name) {
            Oid ns_oid = get_rel_namespace(resource_oid);
            char *sch_name = get_namespace_name(ns_oid);

            if (subid != 0) {
              char *col_name = get_attname(resource_oid, subid, false);
              if (sch_name && col_name)
                resource_id_str =
                    psprintf("%s.%s.%s", sch_name, rel_name, col_name);
              else
                resource_id_str =
                    psprintf("oid_%u.att_%d", resource_oid, subid);
              if (col_name)
                pfree(col_name);
            } else {
              if (sch_name)
                resource_id_str = psprintf("%s.%s", sch_name, rel_name);
              else
                resource_id_str = pstrdup(rel_name);
            }

            pfree(rel_name);
            if (sch_name)
              pfree(sch_name);
          } else
            resource_id_str = psprintf("oid_%u", resource_oid);
        } else if (classid == NamespaceRelationId) {
          char *nsp_name = get_namespace_name(resource_oid);
          resource_id_str =
              nsp_name ? pstrdup(nsp_name) : psprintf("oid_%u", resource_oid);
          if (nsp_name)
            pfree(nsp_name);
        } else if (classid == TypeRelationId) {
          char *type_name = format_type_be(resource_oid);
          resource_id_str =
              type_name ? pstrdup(type_name) : psprintf("oid_%u", resource_oid);
          if (type_name)
            pfree(type_name);
        } else if (classid == DatabaseRelationId) {
          char *db_name = get_database_name(resource_oid);
          resource_id_str =
              db_name ? pstrdup(db_name) : psprintf("oid_%u", resource_oid);
          if (db_name)
            pfree(db_name);
        } else if (classid == ProcedureRelationId) {
          char *proc_name = get_func_name(resource_oid);
          resource_id_str =
              proc_name ? pstrdup(proc_name) : psprintf("oid_%u", resource_oid);
          if (proc_name)
            pfree(proc_name);
        } else {
          resource_id_str = psprintf("class_%u_oid_%u", classid, resource_oid);
        }
        have_resource_id = true;
      }

      {
        const char *action = get_cedar_action_for_bit(bit);
        if (action) {
          result = cedar_evaluate("User", rolename, action, resource_type,
                                  resource_id_str);
          if (result != PG_AUTH_RESULT_IGNORE)
            update_auth_cache(auth_info->roleid, classid, resource_oid, subid,
                              action_key, result);
          if (result != PG_AUTH_RESULT_GRANT)
            goto cleanup;
        }
      }
    }
    result = PG_AUTH_RESULT_GRANT;
  }

cleanup:
  if (have_resource_id && resource_id_str)
    pfree(resource_id_str);
  if (have_resolved_rolename && resolved_rolename)
    pfree(resolved_rolename);
  return result;
}

/* --------------------------------------------------------------------------
 * Object access hook (entity auto-sync into catalog)
 * --------------------------------------------------------------------------
 */
static void cedar_object_access_hook(ObjectAccessType access, Oid classId,
                                     Oid objectId, int subId, void *arg) {
  if (prev_object_access_hook)
    prev_object_access_hook(access, classId, objectId, subId, arg);

  /* Entity sync is implicit via the catalog — no action needed here. */
  /* The hook is kept for future entity auto-registration if needed. */
}

/* --------------------------------------------------------------------------
 * ProcessUtility hook
 * --------------------------------------------------------------------------
 */
static void
cedar_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                           bool readOnlyTree, ProcessUtilityContext context,
                           ParamListInfo params, QueryEnvironment *queryEnv,
                           DestReceiver *dest, QueryCompletion *qc) {
  if (prev_process_utility_hook)
    prev_process_utility_hook(pstmt, queryString, readOnlyTree, context, params,
                              queryEnv, dest, qc);
  else
    standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params,
                            queryEnv, dest, qc);
}

/* --------------------------------------------------------------------------
 * Cache Management
 * --------------------------------------------------------------------------
 */
static void reset_auth_cache(void) {
  if (stats)
    stats->last_cache_reset = GetCurrentTimestamp();
}

static AuthorizationResult check_auth_cache(Oid roleid, Oid classid,
                                            Oid resource_oid, int32 subid,
                                            int32 action) {
  AuthCacheKey key;
  AuthCacheEntry *entry;
  TimestampTz now;
  AuthorizationResult result = PG_AUTH_RESULT_IGNORE;

  if (!cedar_cache_enabled || !auth_cache || !auth_cache_lock || !stats)
    return PG_AUTH_RESULT_IGNORE;

  now = GetCurrentTimestamp();

  memset(&key, 0, sizeof(key));
  key.roleid = roleid;
  key.classid = classid;
  key.resource_oid = resource_oid;
  key.subid = subid;
  key.action = action;

  LWLockAcquire(auth_cache_lock, LW_SHARED);
  entry = (AuthCacheEntry *)hash_search(auth_cache, &key, HASH_FIND, NULL);
  if (entry != NULL) {
    if (now < entry->expires && entry->created_at >= stats->last_cache_reset) {
      if (cedar_collect_stats)
        cache_stats->hits++;
      result = entry->result;
    }
  }
  LWLockRelease(auth_cache_lock);

  /* Expired entry — try to remove */
  if (entry != NULL &&
      (now >= entry->expires || entry->created_at < stats->last_cache_reset)) {
    LWLockAcquire(auth_cache_lock, LW_EXCLUSIVE);
    hash_search(auth_cache, &key, HASH_REMOVE, NULL);
    LWLockRelease(auth_cache_lock);
  }

  if (result == PG_AUTH_RESULT_IGNORE && cedar_collect_stats)
    cache_stats->misses++;

  return result;
}

static void update_auth_cache(Oid roleid, Oid classid, Oid resource_oid,
                              int32 subid, int32 action,
                              AuthorizationResult result) {
  AuthCacheKey key;
  AuthCacheEntry *entry;
  bool found;
  TimestampTz now;

  if (!cedar_cache_enabled || !auth_cache || !auth_cache_lock)
    return;

  now = GetCurrentTimestamp();

  memset(&key, 0, sizeof(key));
  key.roleid = roleid;
  key.classid = classid;
  key.resource_oid = resource_oid;
  key.subid = subid;
  key.action = action;

  LWLockAcquire(auth_cache_lock, LW_EXCLUSIVE);

  /* Evict all if full */
  if (hash_get_num_entries(auth_cache) >= cedar_cache_size) {
    HASH_SEQ_STATUS status;
    AuthCacheEntry *iter_entry;

    if (cedar_collect_stats)
      cache_stats->evictions++;

    if (stats)
      stats->last_cache_reset = now;

    hash_seq_init(&status, auth_cache);
    while ((iter_entry = hash_seq_search(&status)) != NULL)
      hash_search(auth_cache, &iter_entry->key, HASH_REMOVE, NULL);
  }

  entry = (AuthCacheEntry *)hash_search(auth_cache, &key, HASH_ENTER, &found);
  if (entry) {
    entry->result = result;
    entry->created_at = now;
    entry->expires = TimestampTzPlusMilliseconds(now, cedar_cache_ttl * 1000);
  }

  LWLockRelease(auth_cache_lock);
}

/* --------------------------------------------------------------------------
 * Module init / fini
 * --------------------------------------------------------------------------
 */
void _PG_init(void) {
  if (!process_shared_preload_libraries_in_progress)
    ereport(ERROR,
            (errmsg("pg_cedar must be loaded via shared_preload_libraries")));

  /* Shared memory hooks */
  prev_shmem_request_hook = shmem_request_hook;
  shmem_request_hook = pg_cedar_shmem_request;
  prev_shmem_startup_hook = shmem_startup_hook;
  shmem_startup_hook = pg_cedar_shmem_startup;

  /* GUCs */
  DefineCustomBoolVariable(
      "pg_cedar.enabled", "Enable Cedar authorization checks", NULL,
      &cedar_enabled, true, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomStringVariable(
      "pg_cedar.namespace", "Namespace prefix for Cedar entities", NULL,
      &cedar_namespace, "", PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_cedar.log_decisions", "Log authorization decisions", NULL,
      &cedar_log_decisions, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_cedar.audit_enabled", "Write decisions to cedar_audit_log table",
      NULL, &cedar_audit_enabled, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_cedar.collect_stats", "Collect authorization statistics", NULL,
      &cedar_collect_stats, true, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomStringVariable(
      "pg_cedar.default_policy", "Default Cedar policy text (for quick setup)",
      NULL, &cedar_default_policy, "", PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_cedar.cache_enabled", "Enable authorization caching", NULL,
      &cedar_cache_enabled, true, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "pg_cedar.cache_size", "Maximum number of cache entries", NULL,
      &cedar_cache_size, 1024, 64, 100000, PGC_POSTMASTER, 0, NULL, NULL, NULL);

  DefineCustomIntVariable("pg_cedar.cache_ttl",
                          "TTL for cache entries in seconds", NULL,
                          &cedar_cache_ttl, 300, 1, 86400, PGC_SIGHUP,
                          GUC_UNIT_S, NULL, NULL, NULL);

  MarkGUCPrefixReserved("pg_cedar");

  /* Hook registration */
  prev_object_access_hook = object_access_hook;
  object_access_hook = cedar_object_access_hook;

  prev_process_utility_hook = ProcessUtility_hook;
  ProcessUtility_hook = cedar_process_utility_hook;

  prev_universal_auth_hook = universal_authorization_hook;
  universal_authorization_hook = cedar_authorization_hook;

  ereport(LOG, (errmsg("pg_cedar: embedded Cedar engine loaded")));
}

void _PG_fini(void) {
  if (cedar_engine) {
    cedar_engine_free(cedar_engine);
    cedar_engine = NULL;
  }
}

/* --------------------------------------------------------------------------
 * SQL Functions
 * --------------------------------------------------------------------------
 */

Datum pg_cedar_is_enabled(PG_FUNCTION_ARGS) { PG_RETURN_BOOL(cedar_enabled); }

Datum pg_cedar_set_policies(PG_FUNCTION_ARGS) {
  char *policy_name = text_to_cstring(PG_GETARG_TEXT_PP(0));
  char *policy_text = text_to_cstring(PG_GETARG_TEXT_PP(1));
  int ret;

  /* Upsert into cedar_policies via SPI */
  ret = SPI_connect();
  if (ret != SPI_OK_CONNECT) {
    pfree(policy_name);
    pfree(policy_text);
    ereport(ERROR, (errmsg("pg_cedar: SPI_connect failed")));
  }

  {
    Oid argtypes[2] = {TEXTOID, TEXTOID};
    Datum argvals[2];

    argvals[0] = CStringGetTextDatum(policy_name);
    argvals[1] = CStringGetTextDatum(policy_text);

    ret = SPI_execute_with_args(
        "INSERT INTO cedar_policies (name, policy_text) "
        "VALUES ($1, $2) "
        "ON CONFLICT (name) DO UPDATE SET policy_text = $2, "
        "created_at = now(), is_active = true",
        2, argtypes, argvals, NULL, false, 0);

    if (ret != SPI_OK_INSERT)
      ereport(WARNING,
              (errmsg("pg_cedar: failed to upsert policy '%s'", policy_name)));
  }

  SPI_finish();

  /* Reload the engine */
  cedar_engine_loaded = false;
  ensure_cedar_engine();

  /* Reset cache since policies changed */
  reset_auth_cache();

  pfree(policy_name);
  pfree(policy_text);

  PG_RETURN_BOOL(true);
}

Datum pg_cedar_set_schema(PG_FUNCTION_ARGS) {
  char *schema_name = text_to_cstring(PG_GETARG_TEXT_PP(0));
  char *schema_json = text_to_cstring(PG_GETARG_TEXT_PP(1));
  int ret;

  ret = SPI_connect();
  if (ret != SPI_OK_CONNECT) {
    pfree(schema_name);
    pfree(schema_json);
    ereport(ERROR, (errmsg("pg_cedar: SPI_connect failed")));
  }

  {
    Oid argtypes[2] = {TEXTOID, TEXTOID};
    Datum argvals[2];

    argvals[0] = CStringGetTextDatum(schema_name);
    argvals[1] = CStringGetTextDatum(schema_json);

    ret = SPI_execute_with_args(
        "INSERT INTO cedar_schemas (name, schema_json) "
        "VALUES ($1, $2) "
        "ON CONFLICT (name) DO UPDATE SET schema_json = $2, "
        "created_at = now(), is_active = true",
        2, argtypes, argvals, NULL, false, 0);

    if (ret != SPI_OK_INSERT)
      ereport(WARNING,
              (errmsg("pg_cedar: failed to upsert schema '%s'", schema_name)));
  }

  SPI_finish();

  cedar_engine_loaded = false;
  ensure_cedar_engine();
  reset_auth_cache();

  pfree(schema_name);
  pfree(schema_json);

  PG_RETURN_BOOL(true);
}

Datum pg_cedar_set_entities(PG_FUNCTION_ARGS) {
  char *entities_json = text_to_cstring(PG_GETARG_TEXT_PP(0));
  int ret;

  ret = SPI_connect();
  if (ret != SPI_OK_CONNECT) {
    pfree(entities_json);
    ereport(ERROR, (errmsg("pg_cedar: SPI_connect failed")));
  }

  {
    Oid argtypes[1] = {TEXTOID};
    Datum argvals[1];

    argvals[0] = CStringGetTextDatum(entities_json);

    /* Deactivate existing, insert new */
    SPI_execute("UPDATE cedar_entities SET is_active = false "
                "WHERE is_active = true",
                false, 0);

    ret = SPI_execute_with_args(
        "INSERT INTO cedar_entities (entities_json) VALUES ($1)", 1, argtypes,
        argvals, NULL, false, 0);

    if (ret != SPI_OK_INSERT)
      ereport(WARNING, (errmsg("pg_cedar: failed to insert entities")));
  }

  SPI_finish();

  cedar_engine_loaded = false;
  ensure_cedar_engine();
  reset_auth_cache();

  pfree(entities_json);

  PG_RETURN_BOOL(true);
}

Datum pg_cedar_is_authorized(PG_FUNCTION_ARGS) {
  char *principal;
  char *action;
  char *resource;
  const char *context_json = NULL;
  enum CedarDecision decision;
  const char *result_str;

  principal = text_to_cstring(PG_GETARG_TEXT_PP(0));
  action = text_to_cstring(PG_GETARG_TEXT_PP(1));
  resource = text_to_cstring(PG_GETARG_TEXT_PP(2));

  if (!PG_ARGISNULL(3))
    context_json = text_to_cstring(PG_GETARG_TEXT_PP(3));

  if (!ensure_cedar_engine()) {
    pfree(principal);
    pfree(action);
    pfree(resource);
    PG_RETURN_TEXT_P(cstring_to_text("Error"));
  }

  decision = cedar_engine_is_authorized(cedar_engine, principal, action,
                                        resource, context_json);

  switch (decision) {
  case Allow:
    result_str = "Allow";
    break;
  case Deny:
    result_str = "Deny";
    break;
  default:
    result_str = "Error";
    break;
  }

  pfree(principal);
  pfree(action);
  pfree(resource);

  PG_RETURN_TEXT_P(cstring_to_text(result_str));
}

Datum pg_cedar_validate(PG_FUNCTION_ARGS) {
  int rc;
  const char *err;

  if (!ensure_cedar_engine())
    PG_RETURN_TEXT_P(cstring_to_text("Error: engine not initialized"));

  rc = cedar_engine_validate(cedar_engine);
  if (rc == 0)
    PG_RETURN_TEXT_P(cstring_to_text("OK"));

  err = cedar_engine_last_error(cedar_engine);
  PG_RETURN_TEXT_P(cstring_to_text(err ? err : "validation failed"));
}

Datum pg_cedar_explain_decision(PG_FUNCTION_ARGS) {
  char *principal;
  char *action;
  char *resource;
  const char *context_json = NULL;
  const char *diag;

  principal = text_to_cstring(PG_GETARG_TEXT_PP(0));
  action = text_to_cstring(PG_GETARG_TEXT_PP(1));
  resource = text_to_cstring(PG_GETARG_TEXT_PP(2));

  if (!PG_ARGISNULL(3))
    context_json = text_to_cstring(PG_GETARG_TEXT_PP(3));

  if (!ensure_cedar_engine()) {
    pfree(principal);
    pfree(action);
    pfree(resource);
    PG_RETURN_TEXT_P(cstring_to_text("{\"error\":\"engine not initialized\"}"));
  }

  /* Evaluate to populate diagnostics */
  cedar_engine_is_authorized(cedar_engine, principal, action, resource,
                             context_json);

  diag = cedar_engine_get_diagnostics(cedar_engine);

  pfree(principal);
  pfree(action);
  pfree(resource);

  PG_RETURN_TEXT_P(cstring_to_text(diag ? diag : "{}"));
}

Datum pg_cedar_reload(PG_FUNCTION_ARGS) {
  cedar_engine_loaded = false;

  if (cedar_engine) {
    cedar_engine_free(cedar_engine);
    cedar_engine = NULL;
  }

  reset_auth_cache();

  PG_RETURN_BOOL(ensure_cedar_engine());
}

Datum pg_cedar_stats(PG_FUNCTION_ARGS) {
  TupleDesc tupdesc;
  Datum values[6];
  bool nulls[6] = {false};

  tupdesc = CreateTemplateTupleDesc(6);
  TupleDescInitEntry(tupdesc, 1, "auth_requests", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 2, "auth_grants", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 3, "auth_denies", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 4, "auth_ignores", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 5, "auth_errors", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 6, "eval_time_us", FLOAT8OID, -1, 0);
  tupdesc = BlessTupleDesc(tupdesc);

  if (stats) {
    values[0] = Int64GetDatum(stats->auth_requests);
    values[1] = Int64GetDatum(stats->auth_grants);
    values[2] = Int64GetDatum(stats->auth_denies);
    values[3] = Int64GetDatum(stats->auth_ignores);
    values[4] = Int64GetDatum(stats->auth_errors);
    values[5] = Float8GetDatum(stats->eval_total_us);
  } else {
    values[0] = Int64GetDatum(0);
    values[1] = Int64GetDatum(0);
    values[2] = Int64GetDatum(0);
    values[3] = Int64GetDatum(0);
    values[4] = Int64GetDatum(0);
    values[5] = Float8GetDatum(0.0);
  }

  PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

Datum pg_cedar_reset_stats(PG_FUNCTION_ARGS) {
  if (stats) {
    stats->auth_requests = 0;
    stats->auth_grants = 0;
    stats->auth_denies = 0;
    stats->auth_ignores = 0;
    stats->auth_errors = 0;
    stats->eval_total_us = 0;
  }
  PG_RETURN_VOID();
}

Datum pg_cedar_cache_stats(PG_FUNCTION_ARGS) {
  TupleDesc tupdesc;
  Datum values[4];
  bool nulls[4] = {false};

  tupdesc = CreateTemplateTupleDesc(4);
  TupleDescInitEntry(tupdesc, 1, "hits", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 2, "misses", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 3, "evictions", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 4, "entries", INT8OID, -1, 0);
  tupdesc = BlessTupleDesc(tupdesc);

  values[0] = Int64GetDatum(cache_stats ? cache_stats->hits : 0);
  values[1] = Int64GetDatum(cache_stats ? cache_stats->misses : 0);
  values[2] = Int64GetDatum(cache_stats ? cache_stats->evictions : 0);
  values[3] = Int64GetDatum(auth_cache ? hash_get_num_entries(auth_cache) : 0);

  PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

Datum pg_cedar_cache_reset(PG_FUNCTION_ARGS) {
  reset_auth_cache();
  if (cache_stats) {
    cache_stats->hits = 0;
    cache_stats->misses = 0;
    cache_stats->evictions = 0;
  }
  PG_RETURN_VOID();
}

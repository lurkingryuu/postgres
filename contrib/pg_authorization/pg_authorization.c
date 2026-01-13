/* -------------------------------------------------------------------------
 *
 * pg_authorization.c
 *
 * PostgreSQL External Authorization Plugin
 *
 * This extension externalizes PostgreSQL's authorization layer, allowing
 * authorization decisions to be delegated to external policy engines like
 * Cedar, OPA, or custom authorization services.
 *
 * Features:
 * - Intercepts all ACL permission checks via aclchk.c hooks
 * - Intercepts DDL operations via object_access_hook (for Entity Sync)
 * - Intercepts utility commands via ProcessUtility_hook (for Audit/Sync)
 * - Entity synchronization: syncs Users, Tables, Databases to Cedar Agent
 * - Cedar-compatible request format (principal/action/resource)
 * - Configurable via GUC variables
 * - Authorization caching to reduce network overhead
 * - Persistent CURL connections for improved latency
 *
 * Cedar Agent API Integration:
 * - Authorization: POST /v1/is_authorized
 * - Entity sync (create/update): PUT /v1/data/single/{entity_id}
 * - Entity sync (delete): DELETE /v1/data/single/{entity_id}
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
#include <time.h>

#include "access/htup_details.h"
#include "access/relation.h"
#include "access/table.h"
#include "catalog/objectaccess.h"
#include "utils/rel.h"
#include "nodes/parsenodes.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "commands/dbcommands.h"
#include "executor/executor.h"
#include "fmgr.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "libpq/libpq-be.h"
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
#include "utils/hsearch.h"
#include "utils/timestamp.h"

PG_MODULE_MAGIC;

/* SQL-callable functions */
PG_FUNCTION_INFO_V1(pg_authorization_is_enabled);
PG_FUNCTION_INFO_V1(pg_authorization_stats);
PG_FUNCTION_INFO_V1(pg_authorization_reset_stats);
PG_FUNCTION_INFO_V1(pg_authorization_sync_entity);
PG_FUNCTION_INFO_V1(pg_authorization_cache_stats);
PG_FUNCTION_INFO_V1(pg_authorization_cache_reset);

/* --------------------------------------------------------------------------
 * GUC variables
 * --------------------------------------------------------------------------
 */
static char *cedar_agent_url = NULL;     /* Base URL for Cedar Agent */
static char *cedar_namespace = NULL;     /* Namespace for Cedar entities */
static int cedar_request_timeout = 5000; /* Timeout in milliseconds */
static bool cedar_authorization_enabled = true;
static bool cedar_entity_sync_enabled = true;
static bool cedar_log_decisions = false;

/* Caching GUCs */
static bool cedar_cache_enabled = true;
static int cedar_cache_size = 1024;
static int cedar_cache_ttl = 300; /* seconds */

/* --------------------------------------------------------------------------
 * Statistics counters
 * --------------------------------------------------------------------------
 */
static volatile long stats_auth_requests = 0;
static volatile long stats_auth_grants = 0;
static volatile long stats_auth_denies = 0;
static volatile long stats_auth_ignores = 0;
static volatile long stats_auth_errors = 0;
static volatile long stats_sync_requests = 0;
static volatile long stats_sync_successes = 0;
static volatile long stats_sync_failures = 0;

/* Cache statistics */
static volatile long stats_cache_hits = 0;
static volatile long stats_cache_misses = 0;
static volatile long stats_cache_evictions = 0;

/* --------------------------------------------------------------------------
 * Internal state
 * --------------------------------------------------------------------------
 */
static CURL *persistent_curl = NULL;
static HTAB *auth_cache = NULL;

/* Cache structures */
typedef struct AuthCacheKey {
  char rolename[NAMEDATALEN];
  char action[64];
  char resource_type[64];
  char resource_id[256]; /* Sufficient for schema.table.column */
} AuthCacheKey;

typedef struct AuthCacheEntry {
  AuthCacheKey key;
  AuthorizationResult result;
  TimestampTz expires;
} AuthCacheEntry;

/* --------------------------------------------------------------------------
 * Saved hook entries (for chaining)
 * --------------------------------------------------------------------------
 */
static object_access_hook_type prev_object_access_hook = NULL;
static ProcessUtility_hook_type prev_process_utility_hook = NULL;
static universal_authorization_hook_type prev_universal_auth_hook = NULL;

/* --------------------------------------------------------------------------
 * Forward declarations
 * --------------------------------------------------------------------------
 */
void _PG_init(void);
void _PG_fini(void);

static void cedar_object_access_hook(ObjectAccessType access, Oid classId,
                                     Oid objectId, int subId, void *arg);

static void
cedar_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                           bool readOnlyTree, ProcessUtilityContext context,
                           ParamListInfo params, QueryEnvironment *queryEnv,
                           DestReceiver *dest, QueryCompletion *qc);

static AuthorizationResult
cedar_authorization_hook(AuthorizationInfo *auth_info);

static void init_auth_cache(void);
static void reset_auth_cache(void);
static AuthorizationResult check_auth_cache(const char *rolename, const char *action,
                                           const char *res_type, const char *res_id);
static void update_auth_cache(const char *rolename, const char *action,
                             const char *res_type, const char *res_id,
                             AuthorizationResult result);

/* --------------------------------------------------------------------------
 * Helper: JSON string escaping
 * --------------------------------------------------------------------------
 */
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
    case '\b':
      appendStringInfoString(&buf, "\\b");
      break;
    case '\f':
      appendStringInfoString(&buf, "\\f");
      break;
    default:
      if ((unsigned char)*p < 0x20) {
        /* Control character - escape as \uXXXX */
        appendStringInfo(&buf, "\\u%04x", (unsigned char)*p);
      } else {
        appendStringInfoChar(&buf, *p);
      }
      break;
    }
  }

  return buf.data;
}

/* --------------------------------------------------------------------------
 * Helper: Get current day as lowercase string (mon, tue, wed, etc.)
 * --------------------------------------------------------------------------
 */
static const char *get_current_day(void) {
  static const char *days[] = {"sun", "mon", "tue", "wed", "thu", "fri", "sat"};
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);

  return days[tm_info->tm_wday];
}

/* --------------------------------------------------------------------------
 * Helper: Get current date as YYYYMMDD integer
 * --------------------------------------------------------------------------
 */
static int get_current_date_int(void) {
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);

  return (tm_info->tm_year + 1900) * 10000 + (tm_info->tm_mon + 1) * 100 +
         tm_info->tm_mday;
}

/* --------------------------------------------------------------------------
 * Helper: Get current time as HHMMSS integer
 * --------------------------------------------------------------------------
 */
static int get_current_time_int(void) {
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);

  return tm_info->tm_hour * 10000 + tm_info->tm_min * 100 + tm_info->tm_sec;
}

/* --------------------------------------------------------------------------
 * Helper: Get client IP address
 * --------------------------------------------------------------------------
 */
static const char *get_client_ip(void) {
  if (MyProcPort && MyProcPort->remote_host) {
    if (strcmp(MyProcPort->remote_host, "[local]") == 0 || 
        strcmp(MyProcPort->remote_host, "unknown") == 0)
      return "127.0.0.1";
    return MyProcPort->remote_host;
  }
  return "127.0.0.1";
}

/* --------------------------------------------------------------------------
 * Helper: Map a single PostgreSQL AclMode bit to Cedar action string
 * --------------------------------------------------------------------------
 */
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

/* --------------------------------------------------------------------------
 * libcurl callback for response data
 * --------------------------------------------------------------------------
 */
static size_t
pg_auth_curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  StringInfo buf = (StringInfo)userp;

  appendBinaryStringInfo(buf, (char *)contents, realsize);
  return realsize;
}

/* --------------------------------------------------------------------------
 * Cedar Agent: Call /v1/is_authorized endpoint
 * --------------------------------------------------------------------------
 */
static AuthorizationResult cedar_call_is_authorized_internal(const char *principal_type,
                                                            const char *principal_id,
                                                            const char *action,
                                                            const char *resource_type,
                                                            const char *resource_id) {
  CURLcode res;
  StringInfoData request_body;
  StringInfoData response_body;
  StringInfoData url;
  struct curl_slist *headers = NULL;
  long response_code;
  AuthorizationResult result = PG_AUTH_RESULT_IGNORE;

  /* Use persistent handle if possible */
  if (persistent_curl == NULL) {
    persistent_curl = curl_easy_init();
    if (!persistent_curl) {
      ereport(WARNING, (errmsg("pg_authorization: failed to initialize curl")));
      stats_auth_errors++;
      return PG_AUTH_RESULT_IGNORE;
    }
  } else {
    /* Reset handle for new request but keep connections open */
    curl_easy_reset(persistent_curl);
  }

  initStringInfo(&request_body);
  initStringInfo(&response_body);
  initStringInfo(&url);

  /* Build URL */
  appendStringInfoString(&url, cedar_agent_url);
  if (url.len > 0 && url.data[url.len - 1] == '/')
    url.data[--url.len] = '\0';

  if (url.len >= 3 &&
      url.data[url.len - 3] == '/' &&
      url.data[url.len - 2] == 'v' &&
      url.data[url.len - 1] == '1')
    appendStringInfoString(&url, "/is_authorized");
  else
    appendStringInfoString(&url, "/v1/is_authorized");

  /* Build JSON request body */
  {
    char *escaped_principal = json_escape_string(principal_id);
    char *escaped_resource = json_escape_string(resource_id);
    char *ns_prefix = (cedar_namespace && cedar_namespace[0] != '\0') ? psprintf("%s::", cedar_namespace) : NULL;
    const char *ns_str = ns_prefix ? ns_prefix : "";

    appendStringInfoString(&request_body, "{");
    appendStringInfo(&request_body, "\"principal\":\"%s%s::\\\"%s\\\"\"",
                     ns_str, principal_type, escaped_principal);
    appendStringInfo(&request_body, ",\"action\":\"%sAction::\\\"%s\\\"\"",
                     ns_str, action);
    appendStringInfo(&request_body, ",\"resource\":\"%s%s::\\\"%s\\\"\"",
                     ns_str, resource_type, escaped_resource);
    appendStringInfo(
        &request_body,
        ",\"context\":{\"day\":\"%s\",\"date\":%d,\"time\":%d,\"ip\":{\"__extn\":{\"fn\":\"ip\",\"arg\":\"%s\"}}}",
        get_current_day(), get_current_date_int(), get_current_time_int(),
        get_client_ip());
    appendStringInfoString(&request_body, "}");

    pfree(escaped_principal);
    pfree(escaped_resource);
    if (ns_prefix) pfree(ns_prefix);
  }

  /* Setup curl request */
  curl_easy_setopt(persistent_curl, CURLOPT_URL, url.data);
  curl_easy_setopt(persistent_curl, CURLOPT_POST, 1L);
  curl_easy_setopt(persistent_curl, CURLOPT_POSTFIELDS, request_body.data);
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEFUNCTION, pg_auth_curl_write_cb);
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(persistent_curl, CURLOPT_TIMEOUT_MS, cedar_request_timeout);
  curl_easy_setopt(persistent_curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);
  curl_easy_setopt(persistent_curl, CURLOPT_TCP_KEEPALIVE, 1L);

  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(persistent_curl, CURLOPT_HTTPHEADER, headers);

  /* Perform the request */
  res = curl_easy_perform(persistent_curl);

  if (res != CURLE_OK) {
    ereport(LOG, (errmsg("pg_authorization: curl request failed: %s",
                             curl_easy_strerror(res))));
    stats_auth_errors++;
    result = PG_AUTH_RESULT_IGNORE;
  } else {
    curl_easy_getinfo(persistent_curl, CURLINFO_RESPONSE_CODE, &response_code);
    appendStringInfoChar(&response_body, '\0');

    if (response_code == 200) {
      if (strstr(response_body.data, "\"Allow\"") != NULL) {
        result = PG_AUTH_RESULT_GRANT;
        stats_auth_grants++;
      } else if (strstr(response_body.data, "\"Deny\"") != NULL) {
        result = PG_AUTH_RESULT_DENY;
        stats_auth_denies++;
      } else {
        result = PG_AUTH_RESULT_IGNORE;
        stats_auth_ignores++;
      }
    } else {
      ereport(WARNING, (errmsg("pg_authorization: Cedar Agent returned status %ld", response_code)));
      stats_auth_errors++;
      result = PG_AUTH_RESULT_IGNORE;
    }
  }

  curl_slist_free_all(headers);
  pfree(request_body.data);
  pfree(response_body.data);
  pfree(url.data);

  return result;
}

static AuthorizationResult cedar_call_is_authorized(const char *principal_type,
                                                    const char *principal_id,
                                                    const char *action,
                                                    const char *resource_type,
                                                    const char *resource_id) {
  AuthorizationResult result;

  /* Check if URL is configured */
  if (cedar_agent_url == NULL || cedar_agent_url[0] == '\0')
    return PG_AUTH_RESULT_IGNORE;

  /* Check cache first */
  result = check_auth_cache(principal_id, action, resource_type, resource_id);
  if (result != PG_AUTH_RESULT_IGNORE)
    return result;

  stats_auth_requests++;

  /* Cache miss - call agent */
  result = cedar_call_is_authorized_internal(principal_type, principal_id, action, resource_type, resource_id);

  /* Update cache */
  if (result != PG_AUTH_RESULT_IGNORE)
    update_auth_cache(principal_id, action, resource_type, resource_id, result);

  return result;
}

/* --------------------------------------------------------------------------
 * Cedar Agent: Sync entity to /v1/data/single endpoint (PUT)
 * --------------------------------------------------------------------------
 */
static bool cedar_sync_entity_upsert(const char *entity_type,
                                     const char *entity_id) {
  CURLcode res;
  StringInfoData request_body;
  StringInfoData response_body;
  StringInfoData url;
  struct curl_slist *headers = NULL;
  long response_code;
  char *url_escaped_id;
  char *json_escaped_id;
  bool success = false;
  bool has_v1;

  /* Check if sync is enabled and URL is configured */
  if (!cedar_entity_sync_enabled || cedar_agent_url == NULL ||
      cedar_agent_url[0] == '\0')
    return false;

  stats_sync_requests++;

  if (persistent_curl == NULL) {
    persistent_curl = curl_easy_init();
    if (!persistent_curl) return false;
  } else {
    curl_easy_reset(persistent_curl);
  }

  initStringInfo(&request_body);
  initStringInfo(&response_body);
  initStringInfo(&url);

  {
    char *ns_prefix = (cedar_namespace && cedar_namespace[0] != '\0') ? psprintf("%s::", cedar_namespace) : NULL;
    const char *ns_str = ns_prefix ? ns_prefix : "";
    char *full_uid;

    full_uid = psprintf("%s%s::\"%s\"", ns_str, entity_type, entity_id);

    appendStringInfoString(&url, cedar_agent_url);
    if (url.len > 0 && url.data[url.len - 1] == '/')
      url.data[--url.len] = '\0';

    has_v1 = (url.len >= 3 &&
              url.data[url.len - 3] == '/' &&
              url.data[url.len - 2] == 'v' &&
              url.data[url.len - 1] == '1');

    url_escaped_id = curl_easy_escape(persistent_curl, full_uid, (int)strlen(full_uid));
    if (has_v1)
      appendStringInfo(&url, "/data/single/%s", url_escaped_id ? url_escaped_id : full_uid);
    else
      appendStringInfo(&url, "/v1/data/single/%s", url_escaped_id ? url_escaped_id : full_uid);

    json_escaped_id = json_escape_string(entity_id);
    appendStringInfoString(&request_body, "[{");
    appendStringInfo(&request_body, "\"uid\":{\"type\":\"%s%s\",\"id\":\"%s\"}",
                     ns_str, entity_type, json_escaped_id);
    appendStringInfoString(&request_body, ",\"attrs\":{},\"parents\":[]}]");

    pfree(json_escaped_id);
    pfree(full_uid);
    if (ns_prefix) pfree(ns_prefix);
  }

  curl_easy_setopt(persistent_curl, CURLOPT_URL, url.data);
  curl_easy_setopt(persistent_curl, CURLOPT_CUSTOMREQUEST, "PUT");
  curl_easy_setopt(persistent_curl, CURLOPT_POSTFIELDS, request_body.data);
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEFUNCTION, pg_auth_curl_write_cb);
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(persistent_curl, CURLOPT_TIMEOUT_MS, cedar_request_timeout);
  curl_easy_setopt(persistent_curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);

  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(persistent_curl, CURLOPT_HTTPHEADER, headers);

  res = curl_easy_perform(persistent_curl);

  if (res != CURLE_OK) {
    ereport(WARNING, (errmsg("pg_authorization: entity sync failed: %s", curl_easy_strerror(res))));
    stats_sync_failures++;
  } else {
    curl_easy_getinfo(persistent_curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code >= 200 && response_code < 300) {
      stats_sync_successes++;
      success = true;
    } else if (response_code == 409) {
      stats_sync_successes++;
      success = true;
    } else {
      stats_sync_failures++;
    }
  }

  if (url_escaped_id) curl_free(url_escaped_id);
  curl_slist_free_all(headers);
  pfree(request_body.data);
  pfree(response_body.data);
  pfree(url.data);

  return success;
}

/* --------------------------------------------------------------------------
 * Cedar Agent: Delete entity from /v1/data/single endpoint (DELETE)
 * --------------------------------------------------------------------------
 */
static bool cedar_sync_entity_delete(const char *entity_type,
                                     const char *entity_id) {
  CURLcode res;
  StringInfoData response_body;
  StringInfoData url;
  struct curl_slist *headers = NULL;
  long response_code;
  char *url_escaped_id;
  bool success = false;
  bool has_v1;

  if (!cedar_entity_sync_enabled || cedar_agent_url == NULL ||
      cedar_agent_url[0] == '\0')
    return false;

  stats_sync_requests++;

  if (persistent_curl == NULL) {
    persistent_curl = curl_easy_init();
    if (!persistent_curl) return false;
  } else {
    curl_easy_reset(persistent_curl);
  }

  initStringInfo(&response_body);
  initStringInfo(&url);

  {
    char *ns_prefix = (cedar_namespace && cedar_namespace[0] != '\0') ? psprintf("%s::", cedar_namespace) : NULL;
    const char *ns_str = ns_prefix ? ns_prefix : "";
    char *full_uid;

    full_uid = psprintf("%s%s::\"%s\"", ns_str, entity_type, entity_id);

    appendStringInfoString(&url, cedar_agent_url);
    if (url.len > 0 && url.data[url.len - 1] == '/')
      url.data[--url.len] = '\0';

    has_v1 = (url.len >= 3 &&
              url.data[url.len - 3] == '/' &&
              url.data[url.len - 2] == 'v' &&
              url.data[url.len - 1] == '1');

    url_escaped_id = curl_easy_escape(persistent_curl, full_uid, (int)strlen(full_uid));
    if (has_v1)
      appendStringInfo(&url, "/data/single/%s", url_escaped_id ? url_escaped_id : full_uid);
    else
      appendStringInfo(&url, "/v1/data/single/%s", url_escaped_id ? url_escaped_id : full_uid);

    if (ns_prefix) pfree(ns_prefix);
    pfree(full_uid);
  }

  curl_easy_setopt(persistent_curl, CURLOPT_URL, url.data);
  curl_easy_setopt(persistent_curl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEFUNCTION, pg_auth_curl_write_cb);
  curl_easy_setopt(persistent_curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(persistent_curl, CURLOPT_TIMEOUT_MS, cedar_request_timeout);
  curl_easy_setopt(persistent_curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);

  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(persistent_curl, CURLOPT_HTTPHEADER, headers);

  res = curl_easy_perform(persistent_curl);

  if (res != CURLE_OK) {
    ereport(WARNING, (errmsg("pg_authorization: entity delete failed: %s", curl_easy_strerror(res))));
    stats_sync_failures++;
  } else {
    curl_easy_getinfo(persistent_curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code >= 200 && response_code < 300) {
      stats_sync_successes++;
      success = true;
    } else if (response_code == 404) {
      stats_sync_successes++;
      success = true;
    } else {
      stats_sync_failures++;
    }
  }

  if (url_escaped_id) curl_free(url_escaped_id);
  curl_slist_free_all(headers);
  pfree(response_body.data);
  pfree(url.data);

  return success;
}

/* --------------------------------------------------------------------------
 * Universal authorization hook callback
 * --------------------------------------------------------------------------
 */
static AuthorizationResult
cedar_authorization_hook(AuthorizationInfo *auth_info) {
  AuthorizationResult result = PG_AUTH_RESULT_GRANT;
  const char *resource_type;
  StringInfoData resource_id;
  AclMode required_perms = 0;
  bool check_perms_loop = false;

  if (prev_universal_auth_hook) {
    result = prev_universal_auth_hook(auth_info);
    if (result != PG_AUTH_RESULT_IGNORE)
      return result;
  }

  if (!cedar_authorization_enabled)
    return PG_AUTH_RESULT_IGNORE;

  if (cedar_agent_url == NULL || cedar_agent_url[0] == '\0')
    return PG_AUTH_RESULT_IGNORE;

  initStringInfo(&resource_id);

  switch (auth_info->event_type) {
  case PG_AUTH_EVENT_DML:
    required_perms = auth_info->info.dml.required_perms;
    check_perms_loop = true;
    resource_type = "Table";

    if (auth_info->info.dml.schemaname && auth_info->info.dml.relname)
      appendStringInfo(&resource_id, "%s.%s", auth_info->info.dml.schemaname, auth_info->info.dml.relname);
    else if (auth_info->info.dml.relname)
      appendStringInfoString(&resource_id, auth_info->info.dml.relname);
    else
      appendStringInfo(&resource_id, "oid_%u", auth_info->info.dml.relid);
    break;

  case PG_AUTH_EVENT_DDL:
  case PG_AUTH_EVENT_UTILITY:
    if (auth_info->info.ddl.command_tag) {
        check_perms_loop = false;
        if (auth_info->info.ddl.classid == RelationRelationId)
          resource_type = "Table";
        else if (auth_info->info.ddl.classid == NamespaceRelationId)
          resource_type = "Schema";
        else if (auth_info->info.ddl.classid == DatabaseRelationId)
          resource_type = "Database";
        else if (auth_info->info.ddl.classid == AuthIdRelationId)
          resource_type = "User";
        else if (auth_info->info.ddl.classid == ProcedureRelationId)
          resource_type = "Routine";
        else
          resource_type = "Object";

        if (auth_info->info.ddl.schemaname && auth_info->info.ddl.objectname)
          appendStringInfo(&resource_id, "%s.%s", auth_info->info.ddl.schemaname, auth_info->info.ddl.objectname);
        else if (auth_info->info.ddl.objectname)
          appendStringInfoString(&resource_id, auth_info->info.ddl.objectname);
        else
          appendStringInfo(&resource_id, "oid_%u", auth_info->info.ddl.objectid);
          
        result = cedar_call_is_authorized(
            "User", auth_info->rolename ? auth_info->rolename : "unknown", 
            auth_info->info.ddl.command_tag,
            resource_type, resource_id.data);
            
        pfree(resource_id.data);
        return result;
    }
    else {
        pfree(resource_id.data);
        return PG_AUTH_RESULT_IGNORE;
    }
    break;

  case PG_AUTH_EVENT_ACL_CHECK:
    {
        required_perms = auth_info->info.ddl.required_perms;
        check_perms_loop = true;

        if (auth_info->info.ddl.classid == RelationRelationId)
        {
            if (auth_info->info.ddl.subid != 0)
            {
                resource_type = "Column";
                char *rel_name = get_rel_name(auth_info->info.ddl.objectid);
                if (rel_name)
                {
                    Oid ns_oid = get_rel_namespace(auth_info->info.ddl.objectid);
                    char *sch_name = get_namespace_name(ns_oid);
                    char *col_name = get_attname(auth_info->info.ddl.objectid, auth_info->info.ddl.subid, false);

                    if (sch_name && col_name)
                        appendStringInfo(&resource_id, "%s.%s.%s", sch_name, rel_name, col_name);
                    else if (rel_name && col_name)
                        appendStringInfo(&resource_id, "%s.%s", rel_name, col_name);
                    else
                        appendStringInfo(&resource_id, "oid_%u.att_%d", auth_info->info.ddl.objectid, auth_info->info.ddl.subid);

                    if (col_name) pfree(col_name);
                    if (rel_name) pfree(rel_name);
                    if (sch_name) pfree(sch_name);
                }
                else
                    appendStringInfo(&resource_id, "oid_%u.att_%d", auth_info->info.ddl.objectid, auth_info->info.ddl.subid);
            }
            else
            {
                resource_type = "Table";
                char *rel_name = get_rel_name(auth_info->info.ddl.objectid);
                if (rel_name)
                {
                    Oid ns_oid = get_rel_namespace(auth_info->info.ddl.objectid);
                    char *sch_name = get_namespace_name(ns_oid);
                    if (sch_name)
                        appendStringInfo(&resource_id, "%s.%s", sch_name, rel_name);
                    else
                        appendStringInfoString(&resource_id, rel_name);
                    pfree(rel_name);
                    if (sch_name) pfree(sch_name);
                }
                else
                    appendStringInfo(&resource_id, "oid_%u", auth_info->info.ddl.objectid);
            }
        }
        else if (auth_info->info.ddl.classid == NamespaceRelationId)
        {
            resource_type = "Schema";
            char *nsp_name = get_namespace_name(auth_info->info.ddl.objectid);
            if (nsp_name) {
                appendStringInfoString(&resource_id, nsp_name);
                pfree(nsp_name);
            } else
                appendStringInfo(&resource_id, "oid_%u", auth_info->info.ddl.objectid);
        }
        else if (auth_info->info.ddl.classid == TypeRelationId)
        {
            resource_type = "Type";
            char *type_name = format_type_be(auth_info->info.ddl.objectid);
            if (type_name) {
                appendStringInfoString(&resource_id, type_name);
                pfree(type_name);
            } else
                appendStringInfo(&resource_id, "oid_%u", auth_info->info.ddl.objectid);
        }
        else if (auth_info->info.ddl.classid == DatabaseRelationId)
        {
            resource_type = "Database";
            char *db_name = get_database_name(auth_info->info.ddl.objectid);
            if (db_name) {
                appendStringInfoString(&resource_id, db_name);
                pfree(db_name);
            } else
                appendStringInfo(&resource_id, "oid_%u", auth_info->info.ddl.objectid);
        }
        else if (auth_info->info.ddl.classid == ProcedureRelationId)
        {
            resource_type = "Routine";
            char *proc_name = get_func_name(auth_info->info.ddl.objectid);
            if (proc_name) {
                appendStringInfoString(&resource_id, proc_name);
                pfree(proc_name);
            } else
                appendStringInfo(&resource_id, "oid_%u", auth_info->info.ddl.objectid);
        }
        else
        {
            resource_type = "Object";
            appendStringInfo(&resource_id, "class_%u_oid_%u", auth_info->info.ddl.classid, auth_info->info.ddl.objectid);
        }
    }
    break;

  default:
    pfree(resource_id.data);
    return PG_AUTH_RESULT_IGNORE;
  }

  if (check_perms_loop) {
      int i;
      if (required_perms == 0) {
          pfree(resource_id.data);
          return PG_AUTH_RESULT_GRANT;
      }
      result = PG_AUTH_RESULT_DENY;

      for (i = 0; i < 32; i++) {
          AclMode bit = (1 << i);
          if ((required_perms & bit) != 0) {
              const char *action = get_cedar_action_for_bit(bit);
              if (action) {
                  result = cedar_call_is_authorized(
                      "User", auth_info->rolename ? auth_info->rolename : "unknown", 
                      action,
                      resource_type, resource_id.data);
                  if (result != PG_AUTH_RESULT_GRANT) {
                      pfree(resource_id.data);
                      return result;
                  }
              }
          }
      }
      result = PG_AUTH_RESULT_GRANT;
  }

  pfree(resource_id.data);
  return result;
}

/* --------------------------------------------------------------------------
 * Object access hook callback
 * --------------------------------------------------------------------------
 */
static void cedar_object_access_hook(ObjectAccessType access, Oid classId,
                                     Oid objectId, int subId, void *arg) {
  const char *entity_type = NULL;
  char *entity_id = NULL;
  char *schema_name = NULL;

  if (prev_object_access_hook)
    prev_object_access_hook(access, classId, objectId, subId, arg);

  if (!cedar_authorization_enabled && !cedar_entity_sync_enabled)
    return;

  if (cedar_agent_url == NULL || cedar_agent_url[0] == '\0')
    return;

  if (cedar_entity_sync_enabled) {
    /* When an entity changes, we should invalidate our cache */
    reset_auth_cache();

    switch (classId) {
    case RelationRelationId:
      {
        char relkind = get_rel_relkind(objectId);
        if (relkind == '\0') {
          Relation rel = relation_open(objectId, NoLock);
          relkind = rel->rd_rel->relkind;
          relation_close(rel, NoLock);
        }
        if (relkind != RELKIND_RELATION && relkind != RELKIND_VIEW &&
            relkind != RELKIND_MATVIEW && relkind != RELKIND_PARTITIONED_TABLE)
          break;

        entity_type = "Table";
        Oid ns_oid = InvalidOid;
        char *rel_name = get_rel_name(objectId);
        if (rel_name) ns_oid = get_rel_namespace(objectId);
        else {
          Relation rel = relation_open(objectId, NoLock);
          rel_name = pstrdup(RelationGetRelationName(rel));
          ns_oid = RelationGetNamespace(rel);
          relation_close(rel, NoLock);
        }
        if (rel_name) {
          schema_name = get_namespace_name(ns_oid);
          entity_id = schema_name ? psprintf("%s.%s", schema_name, rel_name) : pstrdup(rel_name);
          pfree(rel_name);
        }
      }
      break;

    case NamespaceRelationId:
      {
        HeapTuple tup = SearchSysCache1(NAMESPACEOID, ObjectIdGetDatum(objectId));
        if (HeapTupleIsValid(tup)) {
          Form_pg_namespace nspForm = (Form_pg_namespace) GETSTRUCT(tup);
          entity_id = pstrdup(NameStr(nspForm->nspname));
          entity_type = "Schema";
          ReleaseSysCache(tup);
        }
      }
      break;

    case AuthIdRelationId:
      entity_type = "User";
      {
        HeapTuple roleTup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(objectId));
        if (HeapTupleIsValid(roleTup)) {
          Form_pg_authid roleForm = (Form_pg_authid)GETSTRUCT(roleTup);
          entity_id = pstrdup(NameStr(roleForm->rolname));
          ReleaseSysCache(roleTup);
        }
      }
      break;

    case DatabaseRelationId:
      entity_type = "Database";
      entity_id = get_database_name(objectId);
      break;

    case ProcedureRelationId:
      entity_type = "Routine";
      {
        HeapTuple procTup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));
        if (HeapTupleIsValid(procTup)) {
          Form_pg_proc procForm = (Form_pg_proc)GETSTRUCT(procTup);
          schema_name = get_namespace_name(procForm->pronamespace);
          entity_id = schema_name ? psprintf("%s.%s", schema_name, NameStr(procForm->proname)) : pstrdup(NameStr(procForm->proname));
          ReleaseSysCache(procTup);
        }
      }
      break;

    default: break;
    }

    if (entity_type && entity_id) {
      switch (access) {
      case OAT_POST_CREATE:
      case OAT_POST_ALTER:
        cedar_sync_entity_upsert(entity_type, entity_id);
        break;
      case OAT_DROP:
        cedar_sync_entity_delete(entity_type, entity_id);
        break;
      default: break;
      }
    }
    if (entity_id && entity_id != schema_name) pfree(entity_id);
    if (schema_name) pfree(schema_name);
  }
}

/* --------------------------------------------------------------------------
 * Process utility hook callback
 * --------------------------------------------------------------------------
 */
static void
cedar_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                           bool readOnlyTree, ProcessUtilityContext context,
                           ParamListInfo params, QueryEnvironment *queryEnv,
                           DestReceiver *dest, QueryCompletion *qc) {
  if (prev_process_utility_hook)
    prev_process_utility_hook(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
  else
    standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);

  if (cedar_entity_sync_enabled && cedar_agent_url != NULL && cedar_agent_url[0] != '\0' &&
      pstmt != NULL && pstmt->utilityStmt != NULL) {
    Node *parsetree = (Node *) pstmt->utilityStmt;
    if (IsA(parsetree, CreateRoleStmt)) {
      CreateRoleStmt *stmt = (CreateRoleStmt *) parsetree;
      if (stmt->role && stmt->role[0] != '\0') cedar_sync_entity_upsert("User", stmt->role);
    } else if (IsA(parsetree, CreateSchemaStmt)) {
      CreateSchemaStmt *stmt = (CreateSchemaStmt *) parsetree;
      if (stmt->schemaname && stmt->schemaname[0] != '\0') cedar_sync_entity_upsert("Schema", stmt->schemaname);
    }
    /* Any utility command might change permissions, so reset cache */
    reset_auth_cache();
  }
}

/* --------------------------------------------------------------------------
 * Authorization Cache Management
 * --------------------------------------------------------------------------
 */
static void init_auth_cache(void) {
  HASHCTL ctl;
  memset(&ctl, 0, sizeof(ctl));
  ctl.keysize = sizeof(AuthCacheKey);
  ctl.entrysize = sizeof(AuthCacheEntry);
  auth_cache = hash_create("Cedar Authorization Cache", cedar_cache_size, &ctl, HASH_ELEM | HASH_BLOBS);
}

static void reset_auth_cache(void) {
  if (auth_cache == NULL) return;
  hash_destroy(auth_cache);
  init_auth_cache();
}

static AuthorizationResult check_auth_cache(const char *rolename, const char *action,
                                           const char *res_type, const char *res_id) {
  AuthCacheKey key;
  AuthCacheEntry *entry;
  TimestampTz now = GetCurrentTimestamp();

  if (!cedar_cache_enabled || auth_cache == NULL) return PG_AUTH_RESULT_IGNORE;

  memset(&key, 0, sizeof(key));
  strncpy(key.rolename, rolename ? rolename : "unknown", NAMEDATALEN - 1);
  strncpy(key.action, action, 63);
  strncpy(key.resource_type, res_type, 63);
  strncpy(key.resource_id, res_id, 255);

  entry = (AuthCacheEntry *) hash_search(auth_cache, &key, HASH_FIND, NULL);
  if (entry != NULL) {
    if (now < entry->expires) {
      stats_cache_hits++;
      return entry->result;
    }
    /* Expired */
    hash_search(auth_cache, &key, HASH_REMOVE, NULL);
  }

  stats_cache_misses++;
  return PG_AUTH_RESULT_IGNORE;
}

static void update_auth_cache(const char *rolename, const char *action,
                             const char *res_type, const char *res_id,
                             AuthorizationResult result) {
  AuthCacheKey key;
  AuthCacheEntry *entry;
  bool found;

  if (!cedar_cache_enabled) return;
  if (auth_cache == NULL) init_auth_cache();

  /* Basic eviction: if cache is full, reset it (simplest way for now) */
  if (hash_get_num_entries(auth_cache) >= cedar_cache_size) {
    stats_cache_evictions++;
    reset_auth_cache();
  }

  memset(&key, 0, sizeof(key));
  strncpy(key.rolename, rolename ? rolename : "unknown", NAMEDATALEN - 1);
  strncpy(key.action, action, 63);
  strncpy(key.resource_type, res_type, 63);
  strncpy(key.resource_id, res_id, 255);

  entry = (AuthCacheEntry *) hash_search(auth_cache, &key, HASH_ENTER, &found);
  entry->result = result;
  entry->expires = TimestampTzPlusMilliseconds(GetCurrentTimestamp(), cedar_cache_ttl * 1000);
}

/* --------------------------------------------------------------------------
 * Module initialization function
 * --------------------------------------------------------------------------
 */
void _PG_init(void) {
  curl_global_init(CURL_GLOBAL_ALL);

  DefineCustomStringVariable(
      "pg_authorization.cedar_agent_url", "Base URL of the Cedar Agent service",
      NULL, &cedar_agent_url, "", PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomIntVariable("pg_authorization.timeout",
                          "Timeout for Cedar Agent requests in milliseconds",
                          NULL, &cedar_request_timeout, 5000, 100, 60000,
                          PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);

  DefineCustomStringVariable(
      "pg_authorization.namespace", "Namespace for Cedar authorization",
      NULL, &cedar_namespace, "", PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable("pg_authorization.enabled",
                           "Enable Cedar authorization checks", NULL,
                           &cedar_authorization_enabled, true, PGC_SIGHUP, 0,
                           NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_authorization.entity_sync_enabled",
      "Enable entity synchronization to Cedar Agent", NULL,
      &cedar_entity_sync_enabled, true, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_authorization.log_decisions",
      "Log authorization decisions", NULL,
      &cedar_log_decisions, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

  /* Cache GUCs */
  DefineCustomBoolVariable(
      "pg_authorization.cache_enabled", "Enable authorization caching", NULL,
      &cedar_cache_enabled, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "pg_authorization.cache_size", "Maximum number of entries in auth cache", NULL,
      &cedar_cache_size, 1024, 64, 100000, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "pg_authorization.cache_ttl", "TTL for cache entries in seconds", NULL,
      &cedar_cache_ttl, 300, 1, 86400, PGC_SIGHUP, GUC_UNIT_S, NULL, NULL, NULL);

  MarkGUCPrefixReserved("pg_authorization");

  prev_object_access_hook = object_access_hook;
  object_access_hook = cedar_object_access_hook;

  prev_process_utility_hook = ProcessUtility_hook;
  ProcessUtility_hook = cedar_process_utility_hook;

  prev_universal_auth_hook = universal_authorization_hook;
  universal_authorization_hook = cedar_authorization_hook;

  init_auth_cache();

  ereport(LOG, (errmsg("pg_authorization: extension loaded")));
}

void _PG_fini(void) {
  if (persistent_curl) {
    curl_easy_cleanup(persistent_curl);
    persistent_curl = NULL;
  }
  curl_global_cleanup();
}

/* --------------------------------------------------------------------------
 * SQL Functions
 * --------------------------------------------------------------------------
 */
Datum pg_authorization_is_enabled(PG_FUNCTION_ARGS) { PG_RETURN_BOOL(cedar_authorization_enabled); }

Datum pg_authorization_stats(PG_FUNCTION_ARGS) {
  TupleDesc tupdesc = CreateTemplateTupleDesc(8);
  Datum values[8];
  bool nulls[8] = {false};
  TupleDescInitEntry(tupdesc, 1, "auth_requests", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 2, "auth_grants", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 3, "auth_denies", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 4, "auth_ignores", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 5, "auth_errors", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 6, "sync_requests", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 7, "sync_successes", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 8, "sync_failures", INT8OID, -1, 0);
  tupdesc = BlessTupleDesc(tupdesc);
  values[0] = Int64GetDatum(stats_auth_requests);
  values[1] = Int64GetDatum(stats_auth_grants);
  values[2] = Int64GetDatum(stats_auth_denies);
  values[3] = Int64GetDatum(stats_auth_ignores);
  values[4] = Int64GetDatum(stats_auth_errors);
  values[5] = Int64GetDatum(stats_sync_requests);
  values[6] = Int64GetDatum(stats_sync_successes);
  values[7] = Int64GetDatum(stats_sync_failures);
  PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

Datum pg_authorization_reset_stats(PG_FUNCTION_ARGS) {
  stats_auth_requests = stats_auth_grants = stats_auth_denies = stats_auth_ignores = stats_auth_errors = 0;
  stats_sync_requests = stats_sync_successes = stats_sync_failures = 0;
  PG_RETURN_VOID();
}

Datum pg_authorization_sync_entity(PG_FUNCTION_ARGS) {
  char *type = text_to_cstring(PG_GETARG_TEXT_PP(0));
  char *id = text_to_cstring(PG_GETARG_TEXT_PP(1));
  bool res = cedar_sync_entity_upsert(type, id);
  pfree(type); pfree(id);
  PG_RETURN_BOOL(res);
}

Datum pg_authorization_cache_stats(PG_FUNCTION_ARGS) {
  TupleDesc tupdesc = CreateTemplateTupleDesc(4);
  Datum values[4];
  bool nulls[4] = {false};
  TupleDescInitEntry(tupdesc, 1, "hits", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 2, "misses", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 3, "evictions", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, 4, "entries", INT8OID, -1, 0);
  tupdesc = BlessTupleDesc(tupdesc);
  values[0] = Int64GetDatum(stats_cache_hits);
  values[1] = Int64GetDatum(stats_cache_misses);
  values[2] = Int64GetDatum(stats_cache_evictions);
  values[3] = Int64GetDatum(auth_cache ? hash_get_num_entries(auth_cache) : 0);
  PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

Datum pg_authorization_cache_reset(PG_FUNCTION_ARGS) {
  reset_auth_cache();
  stats_cache_hits = stats_cache_misses = stats_cache_evictions = 0;
  PG_RETURN_VOID();
}

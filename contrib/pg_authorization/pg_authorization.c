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
 * - Intercepts all DML permission checks (SELECT, INSERT, UPDATE, DELETE)
 * - Intercepts DDL operations via object_access_hook
 * - Intercepts utility commands via ProcessUtility_hook
 * - Entity synchronization: syncs Users, Tables, Databases to Cedar Agent
 * - Cedar-compatible request format (principal/action/resource)
 * - Configurable via GUC variables
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
#include "catalog/objectaccess.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "commands/dbcommands.h"
#include "executor/executor.h"
#include "fmgr.h"
#include "funcapi.h"
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
PG_FUNCTION_INFO_V1(pg_authorization_stats);
PG_FUNCTION_INFO_V1(pg_authorization_reset_stats);
PG_FUNCTION_INFO_V1(pg_authorization_sync_entity);

/* --------------------------------------------------------------------------
 * GUC variables
 * --------------------------------------------------------------------------
 */
static char *cedar_agent_url = NULL;     /* Base URL for Cedar Agent */
static int cedar_request_timeout = 5000; /* Timeout in milliseconds */
static bool cedar_authorization_enabled = true;
static bool cedar_entity_sync_enabled = true;
static bool cedar_log_decisions = false;

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

/* --------------------------------------------------------------------------
 * Saved hook entries (for chaining)
 * --------------------------------------------------------------------------
 */
static object_access_hook_type prev_object_access_hook = NULL;
static ExecutorCheckPerms_hook_type prev_executor_check_perms_hook = NULL;
static ProcessUtility_hook_type prev_process_utility_hook = NULL;
static universal_authorization_hook_type prev_universal_auth_hook = NULL;

/* --------------------------------------------------------------------------
 * Forward declarations
 * --------------------------------------------------------------------------
 */
void _PG_init(void);

static void cedar_object_access_hook(ObjectAccessType access, Oid classId,
                                     Oid objectId, int subId, void *arg);

static bool cedar_executor_check_perms(List *rangeTable, List *rteperminfos,
                                       bool ereport_on_violation);

static void
cedar_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                           bool readOnlyTree, ProcessUtilityContext context,
                           ParamListInfo params, QueryEnvironment *queryEnv,
                           DestReceiver *dest, QueryCompletion *qc);

static AuthorizationResult
cedar_authorization_hook(AuthorizationInfo *auth_info);

/* --------------------------------------------------------------------------
 * Helper: JSON string escaping
 *
 * Escapes special characters for JSON string values.
 * Returns a palloc'd string that must be pfree'd by caller.
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
 * Helper: Build Cedar entity ID
 *
 * Formats entity IDs in Cedar format: Type::"id"
 * --------------------------------------------------------------------------
 */
static void build_cedar_entity_id(StringInfo buf, const char *entity_type,
                                  const char *entity_id) {
  char *escaped_id = json_escape_string(entity_id);

  appendStringInfo(buf, "%s::\"%s\"", entity_type, escaped_id);
  pfree(escaped_id);
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
 * Helper: Map PostgreSQL AclMode to Cedar action string
 * --------------------------------------------------------------------------
 */
static const char *aclmode_to_cedar_action(AclMode mode) {
  if (mode & ACL_SELECT)
    return "Select";
  if (mode & ACL_INSERT)
    return "Insert";
  if (mode & ACL_UPDATE)
    return "Update";
  if (mode & ACL_DELETE)
    return "Delete";
  if (mode & ACL_TRUNCATE)
    return "Truncate";
  if (mode & ACL_REFERENCES)
    return "References";
  if (mode & ACL_TRIGGER)
    return "Trigger";
  if (mode & ACL_EXECUTE)
    return "Execute";
  if (mode & ACL_USAGE)
    return "Usage";
  if (mode & ACL_CREATE)
    return "Create";
  if (mode & ACL_CREATE_TEMP)
    return "CreateTemp";
  if (mode & ACL_CONNECT)
    return "Connect";
  if (mode & ACL_SET)
    return "Set";
  if (mode & ACL_ALTER_SYSTEM)
    return "AlterSystem";
  if (mode & ACL_MAINTAIN)
    return "Maintain";

  return "Unknown";
}

/* --------------------------------------------------------------------------
 * libcurl callback for response data
 *
 * Note: the name deliberately does NOT match libcurl's public typedef
 * "curl_write_callback" to avoid symbol clashes with curl headers.
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
 *
 * Sends authorization request in Cedar format:
 * {
 *   "principal": "User::\"username\"",
 *   "action": "Action::\"Select\"",
 *   "resource": "Table::\"schema.table\"",
 *   "context": { "day": "mon", "date": 20250101, "time": 120000 }
 * }
 *
 * Returns: PG_AUTH_RESULT_GRANT, PG_AUTH_RESULT_DENY, or PG_AUTH_RESULT_IGNORE
 * --------------------------------------------------------------------------
 */
static AuthorizationResult cedar_call_is_authorized(const char *principal_type,
                                                    const char *principal_id,
                                                    const char *action,
                                                    const char *resource_type,
                                                    const char *resource_id) {
  CURL *curl;
  CURLcode res;
  StringInfoData request_body;
  StringInfoData response_body;
  StringInfoData url;
  struct curl_slist *headers = NULL;
  long response_code;
  AuthorizationResult result = PG_AUTH_RESULT_IGNORE;

  /* Check if URL is configured */
  if (cedar_agent_url == NULL || cedar_agent_url[0] == '\0')
    return PG_AUTH_RESULT_IGNORE;

  stats_auth_requests++;

  curl = curl_easy_init();
  if (!curl) {
    ereport(WARNING, (errmsg("pg_authorization: failed to initialize curl")));
    stats_auth_errors++;
    return PG_AUTH_RESULT_IGNORE;
  }

  initStringInfo(&request_body);
  initStringInfo(&response_body);
  initStringInfo(&url);

  /* Build URL: base_url/v1/is_authorized */
  appendStringInfoString(&url, cedar_agent_url);
  if (url.len > 0 && url.data[url.len - 1] == '/')
    url.data[--url.len] = '\0';
  appendStringInfoString(&url, "/v1/is_authorized");

  /* Build JSON request body in Cedar format */
  {
    char *escaped_principal = json_escape_string(principal_id);
    char *escaped_resource = json_escape_string(resource_id);

    appendStringInfoString(&request_body, "{");

    /* Principal: User::"username" */
    appendStringInfo(&request_body, "\"principal\":\"%s::\\\"%s\\\"\"",
                     principal_type, escaped_principal);

    /* Action: Action::"Select" */
    appendStringInfo(&request_body, ",\"action\":\"Action::\\\"%s\\\"\"",
                     action);

    /* Resource: Table::"schema.tablename" */
    appendStringInfo(&request_body, ",\"resource\":\"%s::\\\"%s\\\"\"",
                     resource_type, escaped_resource);

    /* Context with time information */
    appendStringInfo(
        &request_body, ",\"context\":{\"day\":\"%s\",\"date\":%d,\"time\":%d}",
        get_current_day(), get_current_date_int(), get_current_time_int());

    appendStringInfoString(&request_body, "}");

    pfree(escaped_principal);
    pfree(escaped_resource);
  }

  /* Setup curl request */
  curl_easy_setopt(curl, CURLOPT_URL, url.data);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body.data);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pg_auth_curl_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, cedar_request_timeout);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);

  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  if (cedar_log_decisions) {
    ereport(LOG, (errmsg("pg_authorization: sending request to %s", url.data),
                  errdetail("Request body: %s", request_body.data)));
  }

  /* Perform the request */
  res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    ereport(WARNING, (errmsg("pg_authorization: curl request failed: %s",
                             curl_easy_strerror(res))));
    stats_auth_errors++;
    result = PG_AUTH_RESULT_IGNORE;
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if (cedar_log_decisions) {
      ereport(LOG,
              (errmsg("pg_authorization: response code %ld", response_code),
               errdetail("Response body: %s", response_body.data)));
    }

    if (response_code == 200) {
      /*
       * Parse Cedar Agent response. Expected format:
       * {"decision":"Allow"} or {"decision":"Deny"}
       */
      if (strstr(response_body.data, "\"Allow\"") != NULL) {
        result = PG_AUTH_RESULT_GRANT;
        stats_auth_grants++;
      } else if (strstr(response_body.data, "\"Deny\"") != NULL) {
        result = PG_AUTH_RESULT_DENY;
        stats_auth_denies++;
      } else {
        /* Unknown response - treat as IGNORE */
        result = PG_AUTH_RESULT_IGNORE;
        stats_auth_ignores++;
      }
    } else {
      ereport(WARNING,
              (errmsg("pg_authorization: Cedar Agent returned status %ld",
                      response_code)));
      stats_auth_errors++;
      result = PG_AUTH_RESULT_IGNORE;
    }
  }

  /* Cleanup */
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  pfree(request_body.data);
  pfree(response_body.data);
  pfree(url.data);

  return result;
}

/* --------------------------------------------------------------------------
 * Cedar Agent: Sync entity to /v1/data/single endpoint (PUT)
 *
 * Creates or updates an entity in Cedar Agent's data store.
 * Request body format:
 * [{"uid":{"type":"Table","id":"public.mytable"},"attrs":{},"parents":[]}]
 * --------------------------------------------------------------------------
 */
static bool cedar_sync_entity_upsert(const char *entity_type,
                                     const char *entity_id,
                                     const char *parent_type,
                                     const char *parent_id) {
  CURL *curl;
  CURLcode res;
  StringInfoData request_body;
  StringInfoData response_body;
  StringInfoData url;
  StringInfoData entity_uid;
  struct curl_slist *headers = NULL;
  long response_code;
  char *escaped_entity_id;
  char *url_escaped_uid;
  bool success = false;

  /* Check if sync is enabled and URL is configured */
  if (!cedar_entity_sync_enabled || cedar_agent_url == NULL ||
      cedar_agent_url[0] == '\0')
    return false;

  stats_sync_requests++;

  curl = curl_easy_init();
  if (!curl) {
    ereport(
        WARNING,
        (errmsg(
            "pg_authorization: failed to initialize curl for entity sync")));
    stats_sync_failures++;
    return false;
  }

  initStringInfo(&request_body);
  initStringInfo(&response_body);
  initStringInfo(&url);
  initStringInfo(&entity_uid);

  /* Build entity UID for URL: Type::"id" */
  build_cedar_entity_id(&entity_uid, entity_type, entity_id);

  /* URL-encode the entity UID */
  url_escaped_uid = curl_easy_escape(curl, entity_uid.data, entity_uid.len);

  /* Build URL: base_url/v1/data/single/Type::"id" */
  appendStringInfoString(&url, cedar_agent_url);
  if (url.len > 0 && url.data[url.len - 1] == '/')
    url.data[--url.len] = '\0';
  appendStringInfo(&url, "/v1/data/single/%s",
                   url_escaped_uid ? url_escaped_uid : entity_uid.data);

  /* Build JSON request body */
  escaped_entity_id = json_escape_string(entity_id);

  appendStringInfoString(&request_body, "[{");
  appendStringInfo(&request_body, "\"uid\":{\"type\":\"%s\",\"id\":\"%s\"}",
                   entity_type, escaped_entity_id);
  appendStringInfoString(&request_body, ",\"attrs\":{}");

  /* Add parent relationship if specified */
  if (parent_type && parent_id) {
    char *escaped_parent_id = json_escape_string(parent_id);

    appendStringInfo(&request_body,
                     ",\"parents\":[{\"type\":\"%s\",\"id\":\"%s\"}]",
                     parent_type, escaped_parent_id);
    pfree(escaped_parent_id);
  } else {
    appendStringInfoString(&request_body, ",\"parents\":[]");
  }

  appendStringInfoString(&request_body, "}]");

  pfree(escaped_entity_id);

  /* Setup curl request */
  curl_easy_setopt(curl, CURLOPT_URL, url.data);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body.data);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pg_auth_curl_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, cedar_request_timeout);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);

  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  if (cedar_log_decisions) {
    ereport(LOG, (errmsg("pg_authorization: syncing entity %s to %s",
                         entity_uid.data, url.data),
                  errdetail("Request body: %s", request_body.data)));
  }

  /* Perform the request */
  res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    ereport(WARNING, (errmsg("pg_authorization: entity sync failed: %s",
                             curl_easy_strerror(res))));
    stats_sync_failures++;
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if (response_code >= 200 && response_code < 300) {
      if (cedar_log_decisions)
        ereport(LOG, (errmsg("pg_authorization: entity sync succeeded for %s",
                             entity_uid.data)));
      stats_sync_successes++;
      success = true;
    } else {
      ereport(WARNING,
              (errmsg("pg_authorization: entity sync returned HTTP %ld",
                      response_code),
               errdetail("Response: %s", response_body.data)));
      stats_sync_failures++;
    }
  }

  /* Cleanup */
  if (url_escaped_uid)
    curl_free(url_escaped_uid);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  pfree(request_body.data);
  pfree(response_body.data);
  pfree(url.data);
  pfree(entity_uid.data);

  return success;
}

/* --------------------------------------------------------------------------
 * Cedar Agent: Delete entity from /v1/data/single endpoint (DELETE)
 * --------------------------------------------------------------------------
 */
static bool cedar_sync_entity_delete(const char *entity_type,
                                     const char *entity_id) {
  CURL *curl;
  CURLcode res;
  StringInfoData response_body;
  StringInfoData url;
  StringInfoData entity_uid;
  struct curl_slist *headers = NULL;
  long response_code;
  char *url_escaped_uid;
  bool success = false;

  /* Check if sync is enabled and URL is configured */
  if (!cedar_entity_sync_enabled || cedar_agent_url == NULL ||
      cedar_agent_url[0] == '\0')
    return false;

  stats_sync_requests++;

  curl = curl_easy_init();
  if (!curl) {
    ereport(
        WARNING,
        (errmsg(
            "pg_authorization: failed to initialize curl for entity delete")));
    stats_sync_failures++;
    return false;
  }

  initStringInfo(&response_body);
  initStringInfo(&url);
  initStringInfo(&entity_uid);

  /* Build entity UID for URL: Type::"id" */
  build_cedar_entity_id(&entity_uid, entity_type, entity_id);

  /* URL-encode the entity UID */
  url_escaped_uid = curl_easy_escape(curl, entity_uid.data, entity_uid.len);

  /* Build URL: base_url/v1/data/single/Type::"id" */
  appendStringInfoString(&url, cedar_agent_url);
  if (url.len > 0 && url.data[url.len - 1] == '/')
    url.data[--url.len] = '\0';
  appendStringInfo(&url, "/v1/data/single/%s",
                   url_escaped_uid ? url_escaped_uid : entity_uid.data);

  /* Setup curl request */
  curl_easy_setopt(curl, CURLOPT_URL, url.data);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pg_auth_curl_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, cedar_request_timeout);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1000);

  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  if (cedar_log_decisions) {
    ereport(LOG, (errmsg("pg_authorization: deleting entity %s from %s",
                         entity_uid.data, url.data)));
  }

  /* Perform the request */
  res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    ereport(WARNING, (errmsg("pg_authorization: entity delete failed: %s",
                             curl_easy_strerror(res))));
    stats_sync_failures++;
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if (response_code >= 200 && response_code < 300) {
      if (cedar_log_decisions)
        ereport(LOG, (errmsg("pg_authorization: entity delete succeeded for %s",
                             entity_uid.data)));
      stats_sync_successes++;
      success = true;
    } else {
      /* 404 is OK for delete - entity may not exist */
      if (response_code == 404) {
        if (cedar_log_decisions)
          ereport(
              LOG,
              (errmsg("pg_authorization: entity %s not found (already deleted)",
                      entity_uid.data)));
        stats_sync_successes++;
        success = true;
      } else {
        ereport(WARNING,
                (errmsg("pg_authorization: entity delete returned HTTP %ld",
                        response_code)));
        stats_sync_failures++;
      }
    }
  }

  /* Cleanup */
  if (url_escaped_uid)
    curl_free(url_escaped_uid);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  pfree(response_body.data);
  pfree(url.data);
  pfree(entity_uid.data);

  return success;
}

/* --------------------------------------------------------------------------
 * Universal authorization hook callback
 *
 * This is called for ACL checks from the core authorization system.
 * --------------------------------------------------------------------------
 */
static AuthorizationResult
cedar_authorization_hook(AuthorizationInfo *auth_info) {
  AuthorizationResult result;
  const char *action;
  const char *resource_type;
  StringInfoData resource_id;

  /* Chain to previous hook if any */
  if (prev_universal_auth_hook) {
    result = prev_universal_auth_hook(auth_info);
    if (result != PG_AUTH_RESULT_IGNORE)
      return result;
  }

  /* Check if plugin is enabled */
  if (!cedar_authorization_enabled)
    return PG_AUTH_RESULT_IGNORE;

  /* Check if URL is configured */
  if (cedar_agent_url == NULL || cedar_agent_url[0] == '\0')
    return PG_AUTH_RESULT_IGNORE;

  initStringInfo(&resource_id);

  /* Build Cedar request based on event type */
  switch (auth_info->event_type) {
  case PG_AUTH_EVENT_DML:
    action = aclmode_to_cedar_action(auth_info->info.dml.required_perms);
    resource_type = "Table";

    if (auth_info->info.dml.schemaname && auth_info->info.dml.relname)
      appendStringInfo(&resource_id, "%s.%s", auth_info->info.dml.schemaname,
                       auth_info->info.dml.relname);
    else if (auth_info->info.dml.relname)
      appendStringInfoString(&resource_id, auth_info->info.dml.relname);
    else
      appendStringInfo(&resource_id, "oid_%u", auth_info->info.dml.relid);
    break;

  case PG_AUTH_EVENT_DDL:
  case PG_AUTH_EVENT_UTILITY:
    action = auth_info->info.ddl.command_tag ? auth_info->info.ddl.command_tag
                                             : "Unknown";

    /* Determine resource type based on class ID */
    if (auth_info->info.ddl.classid == RelationRelationId)
      resource_type = "Table";
    else if (auth_info->info.ddl.classid == NamespaceRelationId)
      resource_type = "Schema";
    else if (auth_info->info.ddl.classid == DatabaseRelationId)
      resource_type = "Database";
    else if (auth_info->info.ddl.classid == AuthIdRelationId)
      resource_type = "User";
    else if (auth_info->info.ddl.classid == ProcedureRelationId)
      resource_type = "Function";
    else
      resource_type = "Object";

    if (auth_info->info.ddl.schemaname && auth_info->info.ddl.objectname)
      appendStringInfo(&resource_id, "%s.%s", auth_info->info.ddl.schemaname,
                       auth_info->info.ddl.objectname);
    else if (auth_info->info.ddl.objectname)
      appendStringInfoString(&resource_id, auth_info->info.ddl.objectname);
    else
      appendStringInfo(&resource_id, "oid_%u", auth_info->info.ddl.objectid);
    break;

  case PG_AUTH_EVENT_ACL_CHECK:
    action = "AclCheck";
    resource_type = "Object";
    appendStringInfo(&resource_id, "class_%u_oid_%u",
                     auth_info->info.ddl.classid, auth_info->info.ddl.objectid);
    break;

  default:
    pfree(resource_id.data);
    return PG_AUTH_RESULT_IGNORE;
  }

  /* Call Cedar Agent */
  result = cedar_call_is_authorized(
      "User", auth_info->rolename ? auth_info->rolename : "unknown", action,
      resource_type, resource_id.data);

  if (cedar_log_decisions) {
    ereport(LOG, (errmsg("pg_authorization: event=%s, user=%s, action=%s, "
                         "resource=%s::%s, result=%s",
                         GetAuthorizationEventTypeName(auth_info->event_type),
                         auth_info->rolename ? auth_info->rolename : "unknown",
                         action, resource_type, resource_id.data,
                         GetAuthorizationResultName(result))));
  }

  pfree(resource_id.data);

  return result;
}

/* --------------------------------------------------------------------------
 * Object access hook callback
 *
 * Called for DDL operations (CREATE, ALTER, DROP, etc.)
 * Also handles entity synchronization to Cedar Agent.
 * --------------------------------------------------------------------------
 */
static void cedar_object_access_hook(ObjectAccessType access, Oid classId,
                                     Oid objectId, int subId, void *arg) {
  const char *entity_type = NULL;
  const char *parent_type = NULL;
  char *entity_id = NULL;
  char *parent_id = NULL;
  char *schema_name = NULL;

  /* Chain to previous hook first */
  if (prev_object_access_hook)
    prev_object_access_hook(access, classId, objectId, subId, arg);

  /* Check if plugin is enabled */
  if (!cedar_authorization_enabled && !cedar_entity_sync_enabled)
    return;

  /* Check if URL is configured */
  if (cedar_agent_url == NULL || cedar_agent_url[0] == '\0')
    return;

  /*
   * Handle entity synchronization for CREATE, ALTER, DROP
   */
  if (cedar_entity_sync_enabled) {
    switch (classId) {
    case RelationRelationId:
      /* Table/Relation */
      entity_type = "Table";
      {
        char *rel_name = get_rel_name(objectId);
        Oid namespace_oid = get_rel_namespace(objectId);

        if (rel_name) {
          schema_name = get_namespace_name(namespace_oid);
          if (schema_name) {
            entity_id = psprintf("%s.%s", schema_name, rel_name);
            parent_type = "Schema";
            parent_id = schema_name;
          } else {
            entity_id = pstrdup(rel_name);
          }
          pfree(rel_name);
        }
      }
      break;

    case NamespaceRelationId:
      /* Schema */
      entity_type = "Schema";
      entity_id = get_namespace_name(objectId);
      parent_type = "Database";
      parent_id = get_database_name(MyDatabaseId);
      break;

    case AuthIdRelationId:
      /* User/Role */
      entity_type = "User";
      {
        HeapTuple roleTup;

        roleTup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(objectId));
        if (HeapTupleIsValid(roleTup)) {
          Form_pg_authid roleForm = (Form_pg_authid)GETSTRUCT(roleTup);

          entity_id = pstrdup(NameStr(roleForm->rolname));
          ReleaseSysCache(roleTup);
        }
      }
      break;

    case DatabaseRelationId:
      /* Database */
      entity_type = "Database";
      entity_id = get_database_name(objectId);
      break;

    case ProcedureRelationId:
      /* Function/Procedure */
      entity_type = "Function";
      {
        HeapTuple procTup;

        procTup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));
        if (HeapTupleIsValid(procTup)) {
          Form_pg_proc procForm = (Form_pg_proc)GETSTRUCT(procTup);

          schema_name = get_namespace_name(procForm->pronamespace);
          if (schema_name) {
            entity_id =
                psprintf("%s.%s", schema_name, NameStr(procForm->proname));
            parent_type = "Schema";
            parent_id = schema_name;
          } else {
            entity_id = pstrdup(NameStr(procForm->proname));
          }
          ReleaseSysCache(procTup);
        }
      }
      break;

    default:
      /* Other object types - skip sync */
      break;
    }

    /* Perform entity sync if we identified the entity */
    if (entity_type && entity_id) {
      switch (access) {
      case OAT_POST_CREATE:
      case OAT_POST_ALTER:
        cedar_sync_entity_upsert(entity_type, entity_id, parent_type,
                                 parent_id);
        break;

      case OAT_DROP:
        cedar_sync_entity_delete(entity_type, entity_id);
        break;

      default:
        /* Other access types don't need sync */
        break;
      }
    }

    /* Cleanup */
    if (entity_id && entity_id != schema_name)
      pfree(entity_id);
    if (schema_name)
      pfree(schema_name);
    if (parent_id && parent_id != schema_name)
      pfree(parent_id);
  }

  /*
   * Handle authorization check for DDL operations
   */
  if (cedar_authorization_enabled) {
    AuthorizationInfo auth_info;
    AuthorizationResult result;

    InitAuthorizationInfo(&auth_info, PG_AUTH_EVENT_DDL, GetUserId());

    auth_info.info.ddl.classid = classId;
    auth_info.info.ddl.objectid = objectId;
    auth_info.info.ddl.subid = subId;

    /* Set command tag based on access type */
    switch (access) {
    case OAT_POST_CREATE:
      auth_info.info.ddl.command_tag = "Create";
      auth_info.info.ddl.is_internal =
          arg ? ((ObjectAccessPostCreate *)arg)->is_internal : false;
      break;
    case OAT_DROP:
      auth_info.info.ddl.command_tag = "Drop";
      break;
    case OAT_POST_ALTER:
      auth_info.info.ddl.command_tag = "Alter";
      auth_info.info.ddl.is_internal =
          arg ? ((ObjectAccessPostAlter *)arg)->is_internal : false;
      break;
    case OAT_TRUNCATE:
      auth_info.info.ddl.command_tag = "Truncate";
      break;
    case OAT_NAMESPACE_SEARCH:
      auth_info.event_type = PG_AUTH_EVENT_OBJECT_ACCESS;
      auth_info.info.ddl.command_tag = "NamespaceSearch";
      break;
    case OAT_FUNCTION_EXECUTE:
      auth_info.event_type = PG_AUTH_EVENT_OBJECT_ACCESS;
      auth_info.info.ddl.command_tag = "Execute";
      break;
    }

    /* Try to get object name */
    if (classId == RelationRelationId && OidIsValid(objectId)) {
      auth_info.info.ddl.objectname = get_rel_name(objectId);
      auth_info.info.ddl.schemaname =
          get_namespace_name(get_rel_namespace(objectId));
    } else if (classId == NamespaceRelationId && OidIsValid(objectId)) {
      auth_info.info.ddl.objectname = get_namespace_name(objectId);
    } else if (classId == ProcedureRelationId && OidIsValid(objectId)) {
      HeapTuple procTup;

      procTup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));
      if (HeapTupleIsValid(procTup)) {
        Form_pg_proc procForm = (Form_pg_proc)GETSTRUCT(procTup);

        auth_info.info.ddl.objectname = pstrdup(NameStr(procForm->proname));
        auth_info.info.ddl.schemaname =
            get_namespace_name(procForm->pronamespace);
        ReleaseSysCache(procTup);
      }
    }

    result = cedar_authorization_hook(&auth_info);

    /* Handle DENY result by raising an error */
    if (result == PG_AUTH_RESULT_DENY) {
      ereport(
          ERROR,
          (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
           errmsg("permission denied by Cedar authorization policy"),
           errdetail(
               "The external authorization service denied this operation.")));
    }
  }
}

/* --------------------------------------------------------------------------
 * Executor permission check hook callback
 *
 * Called for DML operations (SELECT, INSERT, UPDATE, DELETE)
 * --------------------------------------------------------------------------
 */
static bool cedar_executor_check_perms(List *rangeTable, List *rteperminfos,
                                       bool ereport_on_violation) {
  ListCell *l;
  bool result = true;

  /* Chain to previous hook first */
  if (prev_executor_check_perms_hook &&
      !prev_executor_check_perms_hook(rangeTable, rteperminfos,
                                      ereport_on_violation))
    return false;

  /* Check if plugin is enabled */
  if (!cedar_authorization_enabled)
    return true;

  /* Check if URL is configured */
  if (cedar_agent_url == NULL || cedar_agent_url[0] == '\0')
    return true;

  /* Check each relation in the query */
  foreach (l, rteperminfos) {
    RTEPermissionInfo *perminfo = lfirst_node(RTEPermissionInfo, l);
    const char *rel_name;
    const char *schema_name;
    StringInfoData resource_id;
    AuthorizationResult auth_result;
    AclMode remaining_perms;

    rel_name = get_rel_name(perminfo->relid);
    schema_name = get_namespace_name(get_rel_namespace(perminfo->relid));

    initStringInfo(&resource_id);
    if (schema_name && rel_name)
      appendStringInfo(&resource_id, "%s.%s", schema_name, rel_name);
    else if (rel_name)
      appendStringInfoString(&resource_id, rel_name);
    else
      appendStringInfo(&resource_id, "oid_%u", perminfo->relid);

    /*
     * Check each required permission separately since Cedar handles
     * one action per request
     */
    remaining_perms = perminfo->requiredPerms;

    while (remaining_perms != 0) {
      AclMode check_perm;
      const char *action;

      /* Extract one permission at a time */
      check_perm = remaining_perms & -remaining_perms; /* lowest set bit */
      remaining_perms &= ~check_perm;

      action = aclmode_to_cedar_action(check_perm);

      auth_result = cedar_call_is_authorized(
          "User", GetUserNameFromId(GetUserId(), false), action, "Table",
          resource_id.data);

      if (auth_result == PG_AUTH_RESULT_DENY) {
        if (ereport_on_violation) {
          ereport(ERROR,
                  (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                   errmsg("permission denied for relation %s",
                          rel_name ? rel_name : "(unknown)"),
                   errdetail("Cedar authorization policy denied %s access.",
                             action)));
        }
        result = false;
        break;
      } else if (auth_result == PG_AUTH_RESULT_GRANT) {
        /* Explicitly granted - continue checking other permissions */
      }
      /* PG_AUTH_RESULT_IGNORE lets native checks handle it */
    }

    pfree(resource_id.data);

    if (!result)
      break;
  }

  return result;
}

/* --------------------------------------------------------------------------
 * Process utility hook callback
 *
 * Called for utility commands (DDL, VACUUM, etc.)
 * --------------------------------------------------------------------------
 */
static void
cedar_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                           bool readOnlyTree, ProcessUtilityContext context,
                           ParamListInfo params, QueryEnvironment *queryEnv,
                           DestReceiver *dest, QueryCompletion *qc) {
  /* Check if plugin is enabled and URL is configured */
  if (cedar_authorization_enabled && cedar_agent_url != NULL &&
      cedar_agent_url[0] != '\0') {
    AuthorizationInfo auth_info;
    AuthorizationResult result;
    Node *parsetree = pstmt->utilityStmt;

    InitAuthorizationInfo(&auth_info, PG_AUTH_EVENT_UTILITY, GetUserId());

    auth_info.info.ddl.parse_tree = parsetree;
    auth_info.info.ddl.command_tag = CreateCommandName(parsetree);
    auth_info.query_string = queryString;

    result = cedar_authorization_hook(&auth_info);

    if (result == PG_AUTH_RESULT_DENY) {
      ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                      errmsg("permission denied by Cedar authorization policy"),
                      errdetail("The external authorization service denied "
                                "this utility command.")));
    }
  }

  /* Chain to next hook or standard processing */
  if (prev_process_utility_hook)
    prev_process_utility_hook(pstmt, queryString, readOnlyTree, context, params,
                              queryEnv, dest, qc);
  else
    standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params,
                            queryEnv, dest, qc);
}

/* --------------------------------------------------------------------------
 * Module initialization function
 * --------------------------------------------------------------------------
 */
void _PG_init(void) {
  /* Initialize libcurl */
  curl_global_init(CURL_GLOBAL_ALL);

  /* Define GUC variables */
  DefineCustomStringVariable(
      "pg_authorization.cedar_agent_url", "Base URL of the Cedar Agent service",
      "When set, authorization requests are sent to this Cedar Agent. "
      "Example: http://localhost:8180",
      &cedar_agent_url, "", PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomIntVariable("pg_authorization.timeout",
                          "Timeout for Cedar Agent requests in milliseconds",
                          NULL, &cedar_request_timeout, 5000, 100, 60000,
                          PGC_SIGHUP, GUC_UNIT_MS, NULL, NULL, NULL);

  DefineCustomBoolVariable("pg_authorization.enabled",
                           "Enable or disable Cedar authorization checks", NULL,
                           &cedar_authorization_enabled, true, PGC_SIGHUP, 0,
                           NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_authorization.entity_sync_enabled",
      "Enable or disable entity synchronization to Cedar Agent",
      "When enabled, CREATE/ALTER/DROP operations sync entities to Cedar.",
      &cedar_entity_sync_enabled, true, PGC_SIGHUP, 0, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pg_authorization.log_decisions",
      "Log authorization decisions and Cedar Agent requests",
      "When enabled, all authorization decisions are logged.",
      &cedar_log_decisions, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

  MarkGUCPrefixReserved("pg_authorization");

  /* Install hooks */
  prev_object_access_hook = object_access_hook;
  object_access_hook = cedar_object_access_hook;

  prev_executor_check_perms_hook = ExecutorCheckPerms_hook;
  ExecutorCheckPerms_hook = cedar_executor_check_perms;

  prev_process_utility_hook = ProcessUtility_hook;
  ProcessUtility_hook = cedar_process_utility_hook;

  prev_universal_auth_hook = universal_authorization_hook;
  universal_authorization_hook = cedar_authorization_hook;

  ereport(LOG, (errmsg("pg_authorization: extension loaded"),
                errdetail("Cedar authorization and entity sync enabled.")));
}

/* --------------------------------------------------------------------------
 * SQL-callable function: Check if the plugin is enabled
 * --------------------------------------------------------------------------
 */
Datum pg_authorization_is_enabled(PG_FUNCTION_ARGS) {
  PG_RETURN_BOOL(cedar_authorization_enabled);
}

/* --------------------------------------------------------------------------
 * SQL-callable function: Get authorization statistics
 *
 * Returns a single row with all statistics counters.
 * --------------------------------------------------------------------------
 */
Datum pg_authorization_stats(PG_FUNCTION_ARGS) {
  TupleDesc tupdesc;
  Datum values[8];
  bool nulls[8];
  HeapTuple tuple;

  /* Build tuple descriptor */
  tupdesc = CreateTemplateTupleDesc(8);
  TupleDescInitEntry(tupdesc, (AttrNumber)1, "auth_requests", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, (AttrNumber)2, "auth_grants", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, (AttrNumber)3, "auth_denies", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, (AttrNumber)4, "auth_ignores", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, (AttrNumber)5, "auth_errors", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, (AttrNumber)6, "sync_requests", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, (AttrNumber)7, "sync_successes", INT8OID, -1, 0);
  TupleDescInitEntry(tupdesc, (AttrNumber)8, "sync_failures", INT8OID, -1, 0);

  tupdesc = BlessTupleDesc(tupdesc);

  /* Fill in values */
  memset(nulls, 0, sizeof(nulls));
  values[0] = Int64GetDatum(stats_auth_requests);
  values[1] = Int64GetDatum(stats_auth_grants);
  values[2] = Int64GetDatum(stats_auth_denies);
  values[3] = Int64GetDatum(stats_auth_ignores);
  values[4] = Int64GetDatum(stats_auth_errors);
  values[5] = Int64GetDatum(stats_sync_requests);
  values[6] = Int64GetDatum(stats_sync_successes);
  values[7] = Int64GetDatum(stats_sync_failures);

  tuple = heap_form_tuple(tupdesc, values, nulls);

  PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

/* --------------------------------------------------------------------------
 * SQL-callable function: Reset authorization statistics
 * --------------------------------------------------------------------------
 */
Datum pg_authorization_reset_stats(PG_FUNCTION_ARGS) {
  stats_auth_requests = 0;
  stats_auth_grants = 0;
  stats_auth_denies = 0;
  stats_auth_ignores = 0;
  stats_auth_errors = 0;
  stats_sync_requests = 0;
  stats_sync_successes = 0;
  stats_sync_failures = 0;

  PG_RETURN_VOID();
}

/* --------------------------------------------------------------------------
 * SQL-callable function: Manually sync an entity to Cedar Agent
 *
 * Usage: SELECT pg_authorization_sync_entity('Table', 'public.mytable');
 * --------------------------------------------------------------------------
 */
Datum pg_authorization_sync_entity(PG_FUNCTION_ARGS) {
  text *entity_type_text = PG_GETARG_TEXT_PP(0);
  text *entity_id_text = PG_GETARG_TEXT_PP(1);
  char *entity_type = text_to_cstring(entity_type_text);
  char *entity_id = text_to_cstring(entity_id_text);
  bool success;

  success = cedar_sync_entity_upsert(entity_type, entity_id, NULL, NULL);

  pfree(entity_type);
  pfree(entity_id);

  PG_RETURN_BOOL(success);
}

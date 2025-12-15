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
  if (MyProcPort && MyProcPort->remote_host)
    return MyProcPort->remote_host;
  return "unknown";
}

/* --------------------------------------------------------------------------
 * Helper: Map a single PostgreSQL AclMode bit to Cedar action string
 * --------------------------------------------------------------------------
 */
static const char *get_cedar_action_for_bit(AclMode bit) {
  if (bit == ACL_SELECT)
    return "Select";
  if (bit == ACL_INSERT)
    return "Insert";
  if (bit == ACL_UPDATE)
    return "Update";
  if (bit == ACL_DELETE)
    return "Delete";
  if (bit == ACL_TRUNCATE)
    return "Truncate";
  if (bit == ACL_REFERENCES)
    return "References";
  if (bit == ACL_TRIGGER)
    return "Trigger";
  if (bit == ACL_EXECUTE)
    return "Execute";
  if (bit == ACL_USAGE)
    return "Usage";
  if (bit == ACL_CREATE)
    return "Create";
  if (bit == ACL_CREATE_TEMP)
    return "CreateTemp";
  if (bit == ACL_CONNECT)
    return "Connect";
  if (bit == ACL_SET)
    return "Set";
  if (bit == ACL_ALTER_SYSTEM)
    return "AlterSystem";
  if (bit == ACL_MAINTAIN)
    return "Maintain";
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

  /*
   * Build URL: <base>[/v1]/is_authorized
   *
   * This matches the MySQL cedar_authorization + ddl_audit behavior where
   * the base may be either http://host:port or http://host:port/v1.
   */
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

    /* Context with time and IP information */
    appendStringInfo(
        &request_body,
        ",\"context\":{\"day\":\"%s\",\"date\":%d,\"time\":%d,\"ip\":{\"__extn\":{\"fn\":\"ip\",\"arg\":\"%s\"}}}",
        get_current_day(), get_current_date_int(), get_current_time_int(),
        get_client_ip());

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
 * --------------------------------------------------------------------------
 */
static bool cedar_sync_entity_upsert(const char *entity_type,
                                     const char *entity_id) {
  CURL *curl;
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

  /*
   * Build URL: <base>[/v1]/data/single/<urlencoded id>
   *
   * This matches the MySQL ddl_audit plugin behavior where the base may
   * be either http://host:port or http://host:port/v1.
   */
  appendStringInfoString(&url, cedar_agent_url);
  if (url.len > 0 && url.data[url.len - 1] == '/')
    url.data[--url.len] = '\0';

  has_v1 = (url.len >= 3 &&
            url.data[url.len - 3] == '/' &&
            url.data[url.len - 2] == 'v' &&
            url.data[url.len - 1] == '1');

  url_escaped_id = curl_easy_escape(curl, entity_id, (int)strlen(entity_id));
  if (has_v1)
    appendStringInfo(&url, "/data/single/%s",
                     url_escaped_id ? url_escaped_id : entity_id);
  else
    appendStringInfo(&url, "/v1/data/single/%s",
                     url_escaped_id ? url_escaped_id : entity_id);

  /* Build JSON request body: array with single entity */
  json_escaped_id = json_escape_string(entity_id);

  appendStringInfoString(&request_body, "[{");
  appendStringInfo(&request_body, "\"uid\":{\"type\":\"%s\",\"id\":\"%s\"}",
                   entity_type, json_escaped_id);
  /* Parents are empty to match MySQL implementation */
  appendStringInfoString(&request_body, ",\"attrs\":{},\"parents\":[]}]");

  pfree(json_escaped_id);

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
    ereport(LOG, (errmsg("pg_authorization: syncing entity %s:\"%s\" to %s",
                         entity_type, entity_id, url.data),
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
        ereport(LOG,
                (errmsg("pg_authorization: entity sync succeeded for %s:\"%s\"",
                        entity_type, entity_id)));
      stats_sync_successes++;
      success = true;
    } else if (response_code == 409) {
      /*
       * Conflict - entity already exists. Treat this as success for
       * idempotency, matching the MySQL ddl_audit plugin.
       */
      if (cedar_log_decisions)
        ereport(LOG,
                (errmsg("pg_authorization: entity %s:\"%s\" already exists "
                        "(HTTP 409), treating as success",
                        entity_type, entity_id)));
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
  if (url_escaped_id)
    curl_free(url_escaped_id);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
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
  CURL *curl;
  CURLcode res;
  StringInfoData response_body;
  StringInfoData url;
  struct curl_slist *headers = NULL;
  long response_code;
  char *url_escaped_id;
  bool success = false;
  bool has_v1;

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

  /*
   * Build URL: <base>[/v1]/data/single/<urlencoded id>
   *
   * This matches the MySQL ddl_audit plugin behavior where the base may
   * be either http://host:port or http://host:port/v1.
   */
  appendStringInfoString(&url, cedar_agent_url);
  if (url.len > 0 && url.data[url.len - 1] == '/')
    url.data[--url.len] = '\0';

  has_v1 = (url.len >= 3 &&
            url.data[url.len - 3] == '/' &&
            url.data[url.len - 2] == 'v' &&
            url.data[url.len - 1] == '1');

  url_escaped_id = curl_easy_escape(curl, entity_id, (int)strlen(entity_id));
  if (has_v1)
    appendStringInfo(&url, "/data/single/%s",
                     url_escaped_id ? url_escaped_id : entity_id);
  else
    appendStringInfo(&url, "/v1/data/single/%s",
                     url_escaped_id ? url_escaped_id : entity_id);

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
    ereport(LOG, (errmsg("pg_authorization: deleting entity %s:\"%s\" from %s",
                         entity_type, entity_id, url.data)));
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
        ereport(LOG,
                (errmsg("pg_authorization: entity delete succeeded for %s:\"%s\"",
                        entity_type, entity_id)));
      stats_sync_successes++;
      success = true;
    } else {
      ereport(WARNING,
              (errmsg("pg_authorization: entity delete returned HTTP %ld",
                      response_code),
               errdetail("Response: %s", response_body.data)));
      stats_sync_failures++;
    }
  }

  /* Cleanup */
  if (url_escaped_id)
    curl_free(url_escaped_id);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  pfree(response_body.data);
  pfree(url.data);

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
  AuthorizationResult result = PG_AUTH_RESULT_GRANT;
  const char *resource_type;
  StringInfoData resource_id;
  AclMode required_perms = 0;
  bool check_perms_loop = false;

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
    /* Legacy path if passed explicitly */
    required_perms = auth_info->info.dml.required_perms;
    check_perms_loop = true;
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
    /* Only handle if command_tag is set */
    if (auth_info->info.ddl.command_tag) {
        check_perms_loop = false; /* Single action */
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
          resource_type = "Routine"; /* Using Routine to match MySQL */
        else
          resource_type = "Object";

        if (auth_info->info.ddl.schemaname && auth_info->info.ddl.objectname)
          appendStringInfo(&resource_id, "%s.%s", auth_info->info.ddl.schemaname,
                           auth_info->info.ddl.objectname);
        else if (auth_info->info.ddl.objectname)
          appendStringInfoString(&resource_id, auth_info->info.ddl.objectname);
        else
          appendStringInfo(&resource_id, "oid_%u", auth_info->info.ddl.objectid);
          
        /* Perform single check */
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
    /* 
     * This event is triggered by the native authorization system (aclchk.c)
     * when a native check fails.
     */
    {
        char   *rel_name;
        char   *schema_name;
        char   *nsp_name;
        char   *db_name;
        char   *proc_name;

        required_perms = auth_info->info.ddl.required_perms;
        check_perms_loop = true;

        /* Determine resource type and fetch names if possible */
        if (auth_info->info.ddl.classid == RelationRelationId)
        {
            resource_type = "Table";
            /* Try to fetch name */
            rel_name = get_rel_name(auth_info->info.ddl.objectid);
            if (rel_name)
            {
                Oid namespace_oid = get_rel_namespace(auth_info->info.ddl.objectid);

                schema_name = get_namespace_name(namespace_oid);

                if (schema_name)
                    appendStringInfo(&resource_id, "%s.%s", schema_name, rel_name);
                else
                    appendStringInfoString(&resource_id, rel_name);

                pfree(rel_name);
                if (schema_name)
                    pfree(schema_name);
            }
            else
            {
                appendStringInfo(&resource_id, "oid_%u",
                                 auth_info->info.ddl.objectid);
            }
        }
        else if (auth_info->info.ddl.classid == NamespaceRelationId)
        {
            resource_type = "Schema";
            nsp_name = get_namespace_name(auth_info->info.ddl.objectid);
            if (nsp_name)
            {
                appendStringInfoString(&resource_id, nsp_name);
                pfree(nsp_name);
            }
            else
            {
                appendStringInfo(&resource_id, "oid_%u",
                                 auth_info->info.ddl.objectid);
            }
        }
        else if (auth_info->info.ddl.classid == DatabaseRelationId)
        {
            resource_type = "Database";
            db_name = get_database_name(auth_info->info.ddl.objectid);
            if (db_name)
            {
                appendStringInfoString(&resource_id, db_name);
                pfree(db_name);
            }
            else
            {
                appendStringInfo(&resource_id, "oid_%u",
                                 auth_info->info.ddl.objectid);
            }
        }
        else if (auth_info->info.ddl.classid == ProcedureRelationId)
        {
            resource_type = "Routine"; /* Using Routine to match MySQL */
            /* Simplified helper for function name lookup */
            proc_name = get_func_name(auth_info->info.ddl.objectid);
            if (proc_name)
            {
                appendStringInfoString(&resource_id, proc_name);
                pfree(proc_name);
            }
            else
            {
                appendStringInfo(&resource_id, "oid_%u",
                                 auth_info->info.ddl.objectid);
            }
        }
        else
        {
            resource_type = "Object";
            appendStringInfo(&resource_id, "class_%u_oid_%u",
                             auth_info->info.ddl.classid,
                             auth_info->info.ddl.objectid);
        }
    }
    break;

  default:
    pfree(resource_id.data);
    return PG_AUTH_RESULT_IGNORE;
  }

  /* 
   * Iterate over all required permissions and check each one.
   * If ANY permission is denied or errors, we return that result.
   * ALL permissions must be granted to return GRANT.
   */
  if (check_perms_loop) {
      int i;
      
      /* If no permissions required (shouldn't happen), assume GRANT */
      if (required_perms == 0) {
          pfree(resource_id.data);
          return PG_AUTH_RESULT_GRANT;
      }

      for (i = 0; i < 32; i++) {
          AclMode bit = (1 << i);
          if ((required_perms & bit) != 0) {
              const char *action = get_cedar_action_for_bit(bit);
              if (action) {
                  result = cedar_call_is_authorized(
                      "User", auth_info->rolename ? auth_info->rolename : "unknown", 
                      action,
                      resource_type, resource_id.data);
                      
                  if (cedar_log_decisions) {
                    ereport(LOG, (errmsg("pg_authorization: event=%s, user=%s, action=%s, "
                                         "resource=%s::%s, result=%s",
                                         GetAuthorizationEventTypeName(auth_info->event_type),
                                         auth_info->rolename ? auth_info->rolename : "unknown",
                                         action, resource_type, resource_id.data,
                                         GetAuthorizationResultName(result))));
                  }

                  if (result != PG_AUTH_RESULT_GRANT) {
                      /* Deny or Ignore/Error -> stop and return this result */
                      pfree(resource_id.data);
                      return result;
                  }
              }
          }
      }
      /* If we get here, all checked permissions were granted */
      result = PG_AUTH_RESULT_GRANT;
  }

  pfree(resource_id.data);

  return result;
}

/* --------------------------------------------------------------------------
 * Object access hook callback
 *
 * Called for DDL operations (CREATE, ALTER, DROP, etc.)
 * ONLY handles entity synchronization to Cedar Agent.
 * Authorization is handled via universal_authorization_hook in aclchk.c.
 * --------------------------------------------------------------------------
 */
static void cedar_object_access_hook(ObjectAccessType access, Oid classId,
                                     Oid objectId, int subId, void *arg) {
  const char *entity_type = NULL;
  char *entity_id = NULL;
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
        Oid namespace_oid = InvalidOid;

        if (rel_name) {
          namespace_oid = get_rel_namespace(objectId);
        } else {
          /*
           * If syscache lookup fails (e.g. during OAT_POST_CREATE),
           * try opening the relation directly.
           */
          Relation rel = relation_open(objectId, NoLock);
          rel_name = pstrdup(RelationGetRelationName(rel));
          namespace_oid = RelationGetNamespace(rel);
          relation_close(rel, NoLock);
        }

        if (rel_name) {
          schema_name = get_namespace_name(namespace_oid);
          if (schema_name) {
            entity_id = psprintf("%s.%s", schema_name, rel_name);
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
      entity_type = "Routine"; /* Using Routine to match MySQL */
      {
        HeapTuple procTup;

        procTup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));
        if (HeapTupleIsValid(procTup)) {
          Form_pg_proc procForm = (Form_pg_proc)GETSTRUCT(procTup);

          schema_name = get_namespace_name(procForm->pronamespace);
          if (schema_name) {
            entity_id =
                psprintf("%s.%s", schema_name, NameStr(procForm->proname));
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
        cedar_sync_entity_upsert(entity_type, entity_id);
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
  }
}

/* --------------------------------------------------------------------------
 * Executor permission check hook callback
 * --------------------------------------------------------------------------
 */
static bool cedar_executor_check_perms(List *rangeTable, List *rteperminfos,
                                       bool ereport_on_violation) {
  /* 
   * We do not enforce authorization here anymore because we have injected
   * the universal authorization hook into aclchk.c.
   * Native authorization checks will call our hook if they fail.
   * This hook is just a pass-through to ensure we don't block.
   */

  if (prev_executor_check_perms_hook)
    return prev_executor_check_perms_hook(rangeTable, rteperminfos,
                                          ereport_on_violation);
  
  return true;
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
  /*
   * We do not enforce authorization here anymore because most utility commands
   * perform ACL checks which are intercepted by our hook in aclchk.c.
   * Enforcing here would be redundant and might block valid operations
   * (e.g. if native check passes but we check Cedar prematurely).
   */

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
 * --------------------------------------------------------------------------
 */
Datum pg_authorization_sync_entity(PG_FUNCTION_ARGS) {
  text *entity_type_text = PG_GETARG_TEXT_PP(0);
  text *entity_id_text = PG_GETARG_TEXT_PP(1);
  char *entity_type = text_to_cstring(entity_type_text);
  char *entity_id = text_to_cstring(entity_id_text);
  bool success;

  success = cedar_sync_entity_upsert(entity_type, entity_id);

  pfree(entity_type);
  pfree(entity_id);

  PG_RETURN_BOOL(success);
}

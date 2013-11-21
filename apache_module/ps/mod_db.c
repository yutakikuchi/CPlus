#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "apr_hash.h"
#include "apr_tables.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "util_script.h"
#include "http_log.h"
#include "mysql/mysql.h"
#include "stdio.h"
#include "stdlib.h"

module AP_MODULE_DECLARE_DATA db_module;

typedef struct {
    int port;
    char *host;
    char *user;
    char *pass;
    char *name;
    char *table_name;
} db_env;

/* parse parameter */
static apr_hash_t *parse_parameter(request_rec *r) {
    char *str = apr_pstrdup(r->pool, r->args);
    if( str == NULL ) {
        return NULL;
    }
    
    apr_hash_t *hash = NULL;
    const char *del = "&";
    char *items, *last, *st;
    hash = apr_hash_make(r->pool);

    // set hash
    for ( items = apr_strtok(str, del, &last); items != NULL; items = apr_strtok(NULL, del, &last) ){
        st = strchr(items, '=');
        if (st) {
            *st++ = '\0';
            ap_unescape_url(items);
            ap_unescape_url(st);
        } else {
            st = "";
            ap_unescape_url(items);
        }
        apr_hash_set( hash, items, APR_HASH_KEY_STRING, st );
    }
    return hash;
}

/* get parameter */
static char *get_parameter(request_rec *r, apr_hash_t *hash, char *find_key) {
    apr_hash_index_t *hash_index;
    char *key, *val;
    hash_index = apr_hash_first(r->pool, hash);
    while (hash_index) {
        apr_hash_this(hash_index, (const void **)&key, NULL, (void **)&val);
        if( strcmp(key, find_key) == 0 ) {
            return (char*)val;
        }
        hash_index = apr_hash_next(hash_index);
    }
    return NULL;
}

static int getDBContents(request_rec *r, int id) {
    // connect
    MYSQL *conn;
    conn = mysql_init(NULL);
    db_env *db = ap_get_module_config(r->per_dir_config, &db_module);
    int rid;
    MYSQL_TIME ts;

    if (!mysql_real_connect(conn, db->host, db->user, db->pass, db->name, db->port, NULL, 0)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Mysql Connection Error : %s", mysql_error(conn));
        mysql_close(conn);	
        return DECLINED;
    }

    // issue query
    char query[100];
    sprintf(query, "SELECT id, created_at FROM %s.%s where id = ?", db->name, db->table_name);

    // stmt
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Mysql Prepare Error : %s", mysql_stmt_error(stmt));
        mysql_close(conn);	
        return DECLINED;
    }

    // bind
    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(id));

    bind[0].buffer = &id;
    bind[0].buffer_type = MYSQL_TYPE_LONG;
    bind[0].buffer_length = sizeof(id);
    bind[0].is_null = 0;

    // bind_param
    if (mysql_stmt_bind_param(stmt,bind) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Mysql Bind Param Error : %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        mysql_close(conn);
        return DECLINED;
    }

    // execute
    if (mysql_stmt_execute(stmt) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Mysql Execute Error : %s", mysql_stmt_error(stmt));
        mysql_close(conn);	
        return DECLINED; 		
    }  

    // bind_result
    MYSQL_BIND result[2];
    memset(result, 0, sizeof(result));

    result[0].buffer = &rid;
    result[0].buffer_type = MYSQL_TYPE_LONG;
    result[0].buffer_length = sizeof(rid);
    result[0].is_null = 0;

    result[1].buffer = &ts;
    result[1].buffer_type = MYSQL_TYPE_DATETIME;
    result[1].buffer_length = sizeof(ts);
    result[1].is_null = 0;

    // bind_result
    if (mysql_stmt_bind_result(stmt,result) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Mysql Bind Result Error : %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        mysql_close(conn);
        return DECLINED;
    }

    // store_result
    if (mysql_stmt_store_result(stmt) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Mysql Store Result Error : %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        mysql_close(conn);
        return DECLINED;
    }

    // stmt_fetch
    while (!mysql_stmt_fetch(stmt)) {
        ap_rprintf(r, "id = [%d]\n", rid);
        char str[30];
        sprintf(str, "%04d-%02d-%02d %02d:%02d:%02d", ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second);
        ap_rprintf(r, "datetime = [%s]\n", str);
    }

    // close
    mysql_stmt_close(stmt);
    mysql_close(conn);
    return OK;
}

/* The db handler */
static int db_handler(request_rec *r) {
    apr_hash_t *hash = parse_parameter(r);
    if( hash == NULL ) {
        r->status = HTTP_BAD_REQUEST;
        return DECLINED;
    }
    char *id = get_parameter(r, hash, "id");
    if( id == NULL ) {
        r->status = HTTP_BAD_REQUEST;
        return DECLINED;
    }
    getDBContents(r, atoi(id));
    return OK;
}

/* make db dir */
static void *make_db_dir(apr_pool_t *p, char *d)
{
    db_env *db;
    db = (db_env *) apr_pcalloc(p, sizeof(db_env));
    return db;
}

/*
 * Set the value for the 'DBHost' attribute.
 */
static const char *set_db_host(cmd_parms *cmd, void *mconfig, const char *name)
{
    db_env *db;
    db = (db_env *) mconfig;
    db->host = ap_getword_conf(cmd->pool, &name);
    return NULL;
}

/*
 * Set the value for the 'DBUser' attribute.
 */
static const char *set_db_user(cmd_parms *cmd, void *mconfig, const char *user)
{
    db_env *db;
    db = (db_env *) mconfig;
    db->user = ap_getword_conf(cmd->pool, &user);
    return NULL;
}

/*
 * Set the value for the 'DBPass' attribute.
 */
static const char *set_db_pass(cmd_parms *cmd, void *mconfig, const char *pass)
{
    db_env *db;
    db = (db_env *) mconfig;
    db->pass = ap_getword_conf(cmd->pool, &pass);
    return NULL;
}

/*
 * Set the value for the 'DBPort' attribute.
 */
static const char *set_db_port(cmd_parms *cmd, void *mconfig, const char *port)
{
    db_env *db;
    db = (db_env *) mconfig;
    db->port = *(int *)ap_getword_conf(cmd->pool, &port);
    return NULL;
}

/*
 * Set the value for the 'DBName' attribute.
 */
static const char *set_db_name(cmd_parms *cmd, void *mconfig, const char *name)
{
    db_env *db;
    db = (db_env *) mconfig;
    db->name = ap_getword_conf(cmd->pool, &name);
    return NULL;
}

/*
 * Set the value for the 'DBTable' attribute.
 */
static const char *set_db_table(cmd_parms *cmd, void *mconfig, const char *table)
{
    db_env *db;
    db = (db_env *) mconfig;
    db->table_name = ap_getword_conf(cmd->pool, &table);
    return NULL;
}

static const command_rec db_conf_cmds[] = {
    AP_INIT_TAKE1("DBHost", set_db_host, NULL, OR_FILEINFO, "db hostname"),
    AP_INIT_TAKE1("DBPort", set_db_port, NULL, OR_FILEINFO, "db port"),
    AP_INIT_TAKE1("DBUser", set_db_user, NULL, OR_FILEINFO, "db username"),
    AP_INIT_TAKE1("DBPass", set_db_pass, NULL, OR_FILEINFO, "db password"),
    AP_INIT_TAKE1("DBName", set_db_name, NULL, OR_FILEINFO, "db name"),
    AP_INIT_TAKE1("DBTableName", set_db_table, NULL, OR_FILEINFO, "db tablename"),
    {NULL}
};

static void db_register_hooks(apr_pool_t *p)
{
    // ap_hook_post_redb_request(check_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(db_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA db_module = {
    STANDARD20_MODULE_STUFF, 
    make_db_dir,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    db_conf_cmds,          /* table of config file commands       */
    db_register_hooks      /* register hooks                  */
};

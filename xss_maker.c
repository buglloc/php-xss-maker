/*
  +----------------------------------------------------------------------+
  | Author: Andrew Krasichkov buglloc@yandex.ru                          |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_xss_maker.h"
#include "ext/standard/php_smart_str.h"
#include "ext/pcre/php_pcre.h"

// Forward declaration
static int array_make_xss(HashTable *data);
static int xm_trigger_enabled(char *var_name TSRMLS_DC);

/* {{{ xm_overload_t_ xm_ovld[] */
static struct xm_overload_t_ xm_ovld[] = {
    [XM_MYSQL_FETCH_ARRAY] = {
        .orig_func_name = "mysql_fetch_array",
        .ovld_func_name = "xm_mysql_fetch_array",
        .original_handler = NULL
    },
    [XM_MYSQL_FETCH_ASSOC] = {
        .orig_func_name = "mysql_fetch_assoc",
        .ovld_func_name = "xm_mysql_fetch_assoc",
        .original_handler = NULL
    },
    [XM_MYSQLI_FETCH_ASSOC] = {
        .orig_func_name = "mysqli_fetch_assoc",
        .ovld_func_name = "xm_mysqli_fetch_assoc",
        .original_handler = NULL
    },
    {NULL, NULL, NULL}
};
/* }}} */

ZEND_DECLARE_MODULE_GLOBALS(xss_maker)

/* {{{ arginfo */

ZEND_BEGIN_ARG_INFO_EX(arginfo_xss_maker_enable, 0, 0, 0)
    ZEND_ARG_INFO(0, enable)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_xss_maker_enabled, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_xss_maker_inited, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_xm_mysql_fetch_assoc, 0, 0, 1)
    ZEND_ARG_INFO(0, result)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_xm_mysql_fetch_array, 0, 0, 1)
    ZEND_ARG_INFO(0, result)
    ZEND_ARG_INFO(0, result_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_xm_mysqli_fetch_array, 0, 0, 1)
#ifdef MYSQLI_USE_FULL_TYPED_ARGINFO_0
    ZEND_ARG_OBJ_INFO(0, result, mysqli_result, 0)
#else
    ZEND_ARG_INFO(0, result)
#endif
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ xss_maker_functions[]
 *
 * Every user visible function must have an entry in xss_maker_functions[].
 */
const zend_function_entry xss_maker_functions[] = {
    PHP_FE(xss_maker_enable,          arginfo_xss_maker_enable)
    PHP_FE(xss_maker_enabled,         arginfo_xss_maker_enabled)
    PHP_FE(xss_maker_inited,          arginfo_xss_maker_inited)
    PHP_FE(xm_mysql_fetch_array,      arginfo_xm_mysql_fetch_array)
    PHP_FE(xm_mysql_fetch_assoc,      arginfo_xm_mysql_fetch_assoc)
    PHP_FE(xm_mysqli_fetch_assoc,     arginfo_xm_mysqli_fetch_array)
    PHP_FE_END
};
/* }}} */

/* {{{ xss_maker_module_entry
 */
zend_module_entry xss_maker_module_entry = {
    STANDARD_MODULE_HEADER,
    "XSS Maker",
    xss_maker_functions,
    PHP_MINIT(xss_maker), /* PHP_MINIT */
    NULL, /* PHP_MSHUTDOWN */
    PHP_RINIT(xss_maker), /* PHP_RINIT */
    NULL, /* PHP_RSHUTDOWN */
    PHP_MINFO(xss_maker),
    XSS_MAKER_VERSION,
    PHP_MODULE_GLOBALS(xss_maker),
    PHP_GINIT(xss_maker),
    NULL, /* PHP_GSHUTDOWN */
    NULL,
    STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

#ifdef COMPILE_DL_XSS_MAKER
ZEND_GET_MODULE(xss_maker)
#endif

/* {{{ PHP_INI
 */
PHP_INI_BEGIN()
    STD_PHP_INI_BOOLEAN("xssmaker.autostart", "1", PHP_INI_SYSTEM, OnUpdateLong, autostart, zend_xss_maker_globals, xss_maker_globals)
    STD_PHP_INI_BOOLEAN("xssmaker.use_autostart_trigger", "0", PHP_INI_SYSTEM, OnUpdateLong, use_autostart_trigger, zend_xss_maker_globals, xss_maker_globals)
    STD_PHP_INI_ENTRY("xssmaker.autostart_trigger", "_XSS_MAKER", PHP_INI_SYSTEM, OnUpdateString, autostart_trigger, zend_xss_maker_globals, xss_maker_globals)
    STD_PHP_INI_ENTRY("xssmaker.marker", "#_xss$#i", PHP_INI_ALL, OnUpdateString, marker, zend_xss_maker_globals, xss_maker_globals)
    STD_PHP_INI_ENTRY("xssmaker.xss", "'\"><h1>$n|$v</h1>", PHP_INI_ALL, OnUpdateString, xss, zend_xss_maker_globals, xss_maker_globals)
PHP_INI_END()
/* }}} */

/* {{{ module global initialize handler */
PHP_GINIT_FUNCTION(xss_maker)
{
    xss_maker_globals->autostart = 0;
    xss_maker_globals->use_autostart_trigger = 0;
    xss_maker_globals->autostart_trigger = NULL;
    xss_maker_globals->enabled = 0;
    xss_maker_globals->marker = NULL;
    xss_maker_globals->xss = NULL;
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(xss_maker)
{
    REGISTER_INI_ENTRIES();
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(xss_maker)
{
    zend_function *func, *orig;
    struct xm_overload_t_ *p;

    if (XMG(autostart))
        XMG(enabled) = 1;
    else if (XMG(use_autostart_trigger))
        XMG(enabled) = xm_trigger_enabled(XMG(autostart_trigger) TSRMLS_CC);


    if (XM_FIND_FUNCTION("xss_maker_inited", &orig) != SUCCESS || XM_FIND_FUNCTION("xss_maker_loaded", &func) == SUCCESS)
        return SUCCESS;

    zend_hash_add(EG(function_table), "xss_maker_loaded", strlen("xss_maker_loaded")+1, orig, sizeof(zend_function), NULL);
    p = &(xm_ovld[0]);
    while (p->orig_func_name != NULL) {
        if (XM_FIND_FUNCTION(p->ovld_func_name, &func) != SUCCESS) {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "XSS Maker couldn't find function replace %s.", p->ovld_func_name);
            return FAILURE;
        }

        if (XM_FIND_FUNCTION(p->orig_func_name, &orig) == SUCCESS) {
            p->original_handler = orig->internal_function.handler;
            if (XM_REPLACE_FUNCTION(p->orig_func_name, func) != SUCCESS) {
                php_error_docref(NULL TSRMLS_CC, E_ERROR, "XSS Maker couldn't replace function %s.", p->orig_func_name);
                return FAILURE;
            }
        }

        p++;
    }
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(xss_maker)
{
    php_info_print_table_start();
    php_info_print_table_row(2, "XSS Maker enabled", XMG(enabled) ? "enabled": "disabled");
    php_info_print_table_row(2, "Version", XSS_MAKER_VERSION);
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}
/* }}} */


/* {{{ proto string xss_maker_inited()
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(xss_maker_enable)
{
    zend_bool enable = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &enable) == FAILURE) {
        RETURN_NULL();
    }

    XMG(enabled) = enable;
    if (enable)
        RETURN_TRUE;
    RETURN_FALSE;
}
/* }}} */

/* {{{ proto string xss_maker_inited()
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(xss_maker_enabled)
{
    if (XMG(enabled))
        RETURN_TRUE;
    RETURN_FALSE;
}
/* }}} */

/* {{{ proto string xss_maker_inited()
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(xss_maker_inited)
{
    RETURN_TRUE;
}
/* }}} */

/* {{{ proto array mysql_fetch_array(resource result [, int result_type])
   Fetch a result row as an array (associative, numeric or both) */
PHP_FUNCTION(xm_mysql_fetch_array)
{
    ((xm_ovld[XM_MYSQL_FETCH_ARRAY]).original_handler)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

    if (Z_TYPE_P(return_value) == IS_ARRAY && zend_hash_num_elements(Z_ARRVAL_P(return_value))) {
        array_make_xss(Z_ARRVAL_P(return_value));
    }
}
/* }}} */


/* {{{ proto array mysql_fetch_assoc(resource result)
   Fetch a result row as an associative array */
PHP_FUNCTION(xm_mysql_fetch_assoc)
{
    ((xm_ovld[XM_MYSQL_FETCH_ASSOC]).original_handler)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

    if (Z_TYPE_P(return_value) == IS_ARRAY && zend_hash_num_elements(Z_ARRVAL_P(return_value))) {
        array_make_xss(Z_ARRVAL_P(return_value));
    }
}
/* }}} */

/* {{{ proto mixed mysqli_fetch_assoc (object result)
   Fetch a result row as an associative array */
PHP_FUNCTION(xm_mysqli_fetch_assoc)
{
    ((xm_ovld[XM_MYSQLI_FETCH_ASSOC]).original_handler)(INTERNAL_FUNCTION_PARAM_PASSTHRU);

    if (Z_TYPE_P(return_value) == IS_ARRAY && zend_hash_num_elements(Z_ARRVAL_P(return_value))) {
        array_make_xss(Z_ARRVAL_P(return_value));
    }
}
/* }}} */

static int xm_trigger_enabled(char *var_name TSRMLS_DC)
{
    zval **value;

    if (
        (
            (
                PG(http_globals)[TRACK_VARS_GET] &&
                zend_hash_find(PG(http_globals)[TRACK_VARS_GET]->value.ht, var_name, strlen(var_name) + 1, (void **) &value) == SUCCESS
            ) || (
                PG(http_globals)[TRACK_VARS_POST] &&
                zend_hash_find(PG(http_globals)[TRACK_VARS_POST]->value.ht, var_name, strlen(var_name) + 1, (void **) &value) == SUCCESS
            ) || (
                PG(http_globals)[TRACK_VARS_COOKIE] &&
                zend_hash_find(PG(http_globals)[TRACK_VARS_COOKIE]->value.ht, var_name, strlen(var_name) + 1, (void **) &value) == SUCCESS
            )
        ) && (
            strcmp(Z_STRVAL_PP(value), "y") == 0
        )
    ) {
        return 1;
    }

    return 0;
}

static int place_xss(char *name, int name_len, char *value, int value_len, smart_str *result)
{
    int i = 0;
    char *xss = XMG(xss);
    int xss_len = strlen(xss);

    for (i = 0; i < xss_len - 1; i++) {
        if (xss[i] == '$') {
            if (xss[i + 1] == 'n') {
                smart_str_appendl(result, name, name_len);
                i++;
            } else if (xss[i + 1] == 'v') {
                smart_str_appendl(result, value, value_len);
                i++;
            } else {
                smart_str_appendc(result, xss[i]);
            }
        } else {
            smart_str_appendc(result, xss[i]);
        }
    }
    smart_str_appendc(result, xss[xss_len - 1]);

    return 1;
}

static int array_make_xss(HashTable *data)
{
    ulong i;
    ulong type;
    char *key;
    uint key_length;
    zval **value;
    zval *xss;
    smart_str tmp;
    pcre_cache_entry *pcre;
    zval *pcre_ret;
    char *marker;
    int marker_len;

    if (!XMG(enabled))
        return SUCCESS;

    if (data->nApplyCount > 0) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "recursion detected");
        return FAILURE;
    }

    // Recurtion protection
    data->nApplyCount++;

    marker = XMG(marker);
    marker_len = strlen(marker);
    if ((pcre = pcre_get_compiled_regex_cache(marker, marker_len TSRMLS_CC)) == NULL) {
         php_error_docref(NULL TSRMLS_CC, E_WARNING, "Can't compile regexp: \"%s\"", marker);
        return FAILURE;
    }


    MAKE_STD_ZVAL(pcre_ret);
    zend_hash_internal_pointer_reset(data);
    while (zend_hash_get_current_data(data, (void **)&value) == SUCCESS) {
        if (
            Z_TYPE_P(*value) == IS_STRING
            && zend_hash_get_current_key_ex(data, &key, &key_length, &i, 0, NULL) == HASH_KEY_IS_STRING
            ) {

            php_pcre_match_impl(pcre, Z_STRVAL_P(*value), Z_STRLEN_P(*value), pcre_ret, NULL, 0, 0, 0, 0 TSRMLS_CC);
            if (Z_LVAL_P(pcre_ret) > 0) {
                smart_str_0(&tmp);
                if (place_xss(key, key_length - 1, Z_STRVAL_P(*value), Z_STRLEN_P(*value), &tmp)) {
                    MAKE_STD_ZVAL(xss);
                    ZVAL_STRINGL(xss, tmp.c, tmp.len, 1);
                    zend_hash_update(data, key, key_length, &xss, sizeof(zval *), NULL);
                }
                smart_str_free(&tmp);
            }
        }
        zend_hash_move_forward(data);
    }

    FREE_ZVAL(pcre_ret);
    data->nApplyCount--;
    return SUCCESS;
}

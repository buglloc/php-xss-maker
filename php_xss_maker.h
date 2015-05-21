/*
  +----------------------------------------------------------------------+
  | Author: Andrew Krasichkov buglloc@yandex.ru                          |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_XSS_MAKER_H
#define PHP_XSS_MAKER_H

extern zend_module_entry xss_maker_module_entry;
#define phpext_xss_maker_ptr &xss_maker_module_entry

#ifdef PHP_WIN32
#   define PHP_TEST_HELPERS_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#   define PHP_TEST_HELPERS_API __attribute__ ((visibility("default")))
#else
#   define PHP_TEST_HELPERS_API
#endif

ZEND_BEGIN_MODULE_GLOBALS(xss_maker)
    long enabled;
    long autostart;
    long use_autostart_trigger;
    char *autostart_trigger;
    char *marker;
    char *xss;
ZEND_END_MODULE_GLOBALS(xss_maker)

#ifdef ZTS
#define XMG(v) TSRMG(xss_maker_globals_id, zend_xss_maker_globals *, v)
#else
#define XMG(v) (xss_maker_globals.v)
#endif

#define XSS_MAKER_VERSION "0.1.1-dev"
#define XM_FIND_FUNCTION(name, func) zend_hash_find(EG(function_table), name, strlen(name)+1, (void **)(func))
#define XM_REPLACE_FUNCTION(name, func) zend_hash_update(EG(function_table), name, strlen(name)+1, func, sizeof(zend_function), NULL)

#define XM_MYSQL_FETCH_ARRAY      0
#define XM_MYSQL_FETCH_ASSOC      1
#define XM_MYSQLI_FETCH_ASSOC     2

#define XM_UTF8_ENCODING          "UTF-8"
#define XM_UTF8_MARKER            "#[\\xD0\\xD1][\\x80-\\xBF]#"
#define XM_NATIONAL_MARKER        "#[\\xC0-\\xFF]#"

PHP_MINIT_FUNCTION(xss_maker);
PHP_RINIT_FUNCTION(xss_maker);
PHP_MINFO_FUNCTION(xss_maker);
PHP_GINIT_FUNCTION(xss_maker);
PHP_FUNCTION(xss_maker_enable);
PHP_FUNCTION(xss_maker_enabled);
PHP_FUNCTION(xss_maker_inited);
PHP_FUNCTION(xm_mysql_fetch_row);
PHP_FUNCTION(xm_mysql_fetch_array);
PHP_FUNCTION(xm_mysql_fetch_assoc);
PHP_FUNCTION(xm_mysqli_fetch_assoc);
struct xm_overload_t_ {
    char *orig_func_name;
    char *ovld_func_name;
    void (*original_handler)(INTERNAL_FUNCTION_PARAMETERS);
};

#endif  /* PHP_XSS_MAKER_H */

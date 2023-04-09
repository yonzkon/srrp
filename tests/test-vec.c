#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>
#include "vec.h"
#include "str.h"

static void test_vec_base(void **status)
{
    str_t *str1 = str_new("Cio-stream");
    str_t *str2 = str_new("Srrp-router");
    str_t *str3 = str_new("Websocket-proxy");

    vec_t *v = vec_new(sizeof(str_t *), 3);
    vpush(v, &str1);
    vpush(v, &str2);
    vpush(v, &str3);

    str_t *tmp;

    vpop(v, &tmp);
    assert_true(tmp == str3);
    vpop(v, &tmp);
    assert_true(tmp == str2);
    vpop(v, &tmp);
    assert_true(tmp == str1);

    vec_free(v);

    str_free(str1);
    str_free(str2);
    str_free(str3);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_vec_base),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

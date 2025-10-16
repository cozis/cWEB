#include <stddef.h>

#define CWEB_IMPLEMENTATION
#include "../cweb.h"

#define USERNAME_LIMIT 64

bool valid_name(CWEB_String str)
{
    return str.len >= 3 && str.len < 100;
}

bool valid_email(CWEB_String str)
{
    (void) str;
    return true;
}

bool valid_pass(CWEB_String str)
{
    return str.len >= 8 && str.len < 1000;
}

bool valid_post_title(CWEB_String str)
{
    (void) str;
    return true;
}

bool valid_post_content(CWEB_String str)
{
    (void) str;
    return true;
}

bool valid_link(CWEB_String str)
{
    (void) str;
    return true;
}

bool valid_comment_content(CWEB_String str)
{
    (void) str;
    return true;
}

// TODO: check for the correct methods at each endpoint

static int user_exists(CWEB *cweb, CWEB_String name, CWEB_String pass)
{
    CWEB_QueryResult res = cweb_database_select(cweb, "SELECT id, hash FROM Users WHERE username=?", name);

    int64_t user_id;
    CWEB_PasswordHash hash;
    int ret = cweb_next_query_row(&res, &user_id, &hash);
    if (ret < 0) {
        printf("here %s:%d\n", __FILE__, __LINE__); // TODO: remove
        cweb_free_query_result(&res);
        return -1;
    }
    if (ret == 0) {
        printf("here %s:%d\n", __FILE__, __LINE__); // TODO: remove
        cweb_free_query_result(&res);
        return 0;
    }

    ret = cweb_check_password(pass, hash);
    if (ret < 0) {
        printf("here %s:%d\n", __FILE__, __LINE__); // TODO: remove
        cweb_free_query_result(&res);
        return -1;
    }
    if (ret > 0) {
        printf("here %s:%d\n", __FILE__, __LINE__); // TODO: remove
        cweb_free_query_result(&res);
        return 0;
    }

    return user_id;
}

static void endpoint_api_login(CWEB *cweb, CWEB_Request *req)
{
    if (cweb_get_user_id(req) != -1) {
        cweb_respond_redirect(req, CWEB_STR("/index"));
        return;
    }

    CWEB_String name = cweb_get_param_s(req, CWEB_STR("username"));
    CWEB_String pass = cweb_get_param_s(req, CWEB_STR("password"));
    if (!valid_name(name) || !valid_pass(pass)) {
        cweb_respond_basic(req, 400, CWEB_STR("Invalid credentials"));
        return;
    }

    int ret = user_exists(cweb, name, pass);
    if (ret < 0) {
        cweb_respond_basic(req, 500, CWEB_STR("Internal error"));
        return;
    }
    if (ret == 0) {
        cweb_respond_basic(req, 400, CWEB_STR("Invalid credentials"));
        return;
    }
    if (cweb_set_user_id(req, ret) < 0) {
        cweb_respond_basic(req, 500, CWEB_STR("Internal error"));
        return;
    }

    cweb_respond_redirect(req, CWEB_STR("/index"));
}

static void endpoint_api_signup(CWEB *cweb, CWEB_Request *req)
{
    if (cweb_get_user_id(req) != -1) {
        cweb_respond_redirect(req, CWEB_STR("/index"));
        return;
    }

    CWEB_String name  = cweb_get_param_s(req, CWEB_STR("username"));
    CWEB_String email = cweb_get_param_s(req, CWEB_STR("email"));
    CWEB_String pass1 = cweb_get_param_s(req, CWEB_STR("password1"));
    CWEB_String pass2 = cweb_get_param_s(req, CWEB_STR("password2"));

    if (!valid_name(name) || !valid_email(email) || !valid_pass(pass1)) {
        cweb_respond_basic(req, 400, CWEB_STR("Invalid credentials"));
        return;
    }

    if (!cweb_streq(pass1, pass2)) {
        cweb_respond_basic(req, 400, CWEB_STR("The password was repeated incorrectly"));
        return;
    }

    CWEB_PasswordHash hash;
    int ret = cweb_hash_password(pass1, 12, &hash);
    if (ret) {
        cweb_respond_basic(req, 500, CWEB_STR("Internal error"));
        return;
    }

    int64_t insert_id = cweb_database_insert(cweb, "INSERT INTO Users(username, email, hash) VALUES (?, ?, ?)", name, email, hash);
    if (insert_id < 0) {
        // TODO: What if the user exists?
        cweb_respond_basic(req, 500, CWEB_STR("Internal error"));
        return;
    }
    if (cweb_set_user_id(req, insert_id) < 0) {
        cweb_respond_basic(req, 500, CWEB_STR("Internal error"));
        return;
    }

    cweb_respond_redirect(req, CWEB_STR("/index"));
}

static void endpoint_api_logout(CWEB *cweb, CWEB_Request *req)
{
    (void) cweb;

    cweb_set_user_id(req, -1);
    cweb_respond_redirect(req, CWEB_STR("/index"));
}

static void endpoint_api_post(CWEB *cweb, CWEB_Request *req)
{
    int user_id = cweb_get_user_id(req);
    if (user_id == -1) {
        cweb_respond_redirect(req, CWEB_STR("/index"));
        return;
    }

    CWEB_String title   = cweb_get_param_s(req, CWEB_STR("title"));
    CWEB_String link    = cweb_get_param_s(req, CWEB_STR("link"));
    CWEB_String content = cweb_get_param_s(req, CWEB_STR("content"));
    CWEB_String csrf    = cweb_get_param_s(req, CWEB_STR("csrf"));

    if (!cweb_streq(cweb_get_csrf(req), csrf)) {
        cweb_respond_basic(req, 400, CWEB_STR("Invalid request"));
        return;
    }
    if (!valid_post_title(title)) {
        cweb_respond_basic(req, 400, CWEB_STR("Invalid title"));
        return;
    }
    if (!valid_link(link)) {
        cweb_respond_basic(req, 400, CWEB_STR("Invalid link"));
        return;
    }
    if (!valid_post_content(content)) {
        cweb_respond_basic(req, 400, CWEB_STR("Invalid content"));
        return;
    }

    bool is_link = false;
    if (link.len > 0) {
        is_link = true;
        content = link;
    }

    int64_t insert_id = cweb_database_insert(cweb,
        "INSERT INTO Posts(author, title, is_link, content) VALUES (?, ?, ?, ?)",
        user_id, title, is_link, content);

    if (insert_id < 0) {
        cweb_respond_basic(req, 500, CWEB_STR("Internal error"));
        return;
    }
    int post_id = (int) insert_id;

    CWEB_String target = cweb_format(req, "/post?id={}", post_id);
    cweb_respond_redirect(req, target);
}

static void endpoint_api_comment(CWEB *cweb, CWEB_Request *req)
{
    int user_id = cweb_get_user_id(req);
    if (user_id == -1) {
        cweb_respond_basic(req, 400, CWEB_STR("You are not logged in"));
        return;
    }

    int parent_post     = cweb_get_param_i(req, CWEB_STR("parent_post"));
    int parent_comment  = cweb_get_param_i(req, CWEB_STR("parent_comment"));
    CWEB_String content = cweb_get_param_s(req, CWEB_STR("content"));
    CWEB_String csrf2   = cweb_get_param_s(req, CWEB_STR("csrf"));

    if (!cweb_streq(cweb_get_csrf(req), csrf2)) {
        cweb_respond_basic(req, 400, CWEB_STR("Invalid request"));
        return;
    }

    content = cweb_trim(content);
    if (!valid_comment_content(content)) {
        cweb_respond_basic(req, 400, CWEB_STR("Invalid content"));
        return;
    }

    int64_t insert_id;
    if (parent_comment == -1) insert_id = cweb_database_insert(cweb, "INSERT INTO Comments(author, content, parent_post) VALUES (?, ?, ?)",                    user_id, content, parent_post);
    else                      insert_id = cweb_database_insert(cweb, "INSERT INTO Comments(author, content, parent_post, parent_comment) VALUES (?, ?, ?, ?)", user_id, content, parent_post, parent_comment);
    if (insert_id < 0) {
        cweb_respond_basic(req, 500, CWEB_STR("Internal error"));
        return;
    }

    CWEB_String target = cweb_format(req, "/post?id={}", parent_post);
    cweb_respond_redirect(req, target);
}

static void endpoint_index(CWEB *cweb, CWEB_Request *req)
{
    (void) cweb;

    cweb_respond_template(req, 200, CWEB_STR("demo/pages/index.wl"));
}

static void endpoint_write(CWEB *cweb, CWEB_Request *req)
{
    (void) cweb;

    if (cweb_get_user_id(req) == -1) {
        cweb_respond_redirect(req, CWEB_STR("/index"));
        return;
    }

    cweb_respond_template(req, 200, CWEB_STR("demo/pages/write.wl"));
}

static void endpoint_login(CWEB *cweb, CWEB_Request *req)
{
    (void) cweb;

    if (cweb_get_user_id(req) != -1) {
        cweb_respond_redirect(req, CWEB_STR("/index"));
        return;
    }

    cweb_respond_template(req, 200, CWEB_STR("demo/pages/login.wl"));
}

static void endpoint_signup(CWEB *cweb, CWEB_Request *req)
{
    (void) cweb;

    if (cweb_get_user_id(req) != -1) {
        cweb_respond_redirect(req, CWEB_STR("/index"));
        return;
    }

    cweb_respond_template(req, 200, CWEB_STR("demo/pages/signup.wl"));
}

static void endpoint_post(CWEB *cweb, CWEB_Request *req)
{
    int post_id = cweb_get_param_i(req, CWEB_STR("id"));
    if (post_id < 0) {
        cweb_respond_template(req, 404, CWEB_STR("demo/pages/notfound.wl"));
        return;
    }

    CWEB_QueryResult res = cweb_database_select(cweb, "SELECT COUNT(*) FROM Posts WHERE id=?", post_id);

    int num;
    if (cweb_next_query_row(&res, &num) != 1) {
        cweb_respond_basic(req, 500, CWEB_STR(""));
        cweb_free_query_result(&res);
        return;
    }
    cweb_free_query_result(&res);

    if (num < 0) {
        cweb_respond_basic(req, 500, CWEB_STR(""));
        return;
    }

    if (num == 0) {
        cweb_respond_template(req, 404, CWEB_STR("demo/pages/notfound.wl"));
        return;
    }

    cweb_respond_template(req, 200, CWEB_STR("demo/pages/post.wl"), post_id);
}

static void endpoint_fallback(CWEB *cweb, CWEB_Request *req)
{
    (void) cweb;

    cweb_respond_template(req, 404, CWEB_STR("demo/pages/notfound.wl"));
}

int main(void)
{
    CWEB_String addr          = CWEB_STR("127.0.0.1");
    uint16_t    port          = 8080;
    CWEB_String database_file = CWEB_STR(":memory:");
    CWEB_String schema_file   = CWEB_STR("demo/schema.sql");

    if (cweb_global_init() < 0)
        return -1;

    uint16_t    secure_port = 0;
    CWEB_String cert_key;
    CWEB_String private_key;
#ifdef HTTPS_ENABLED
    secure_port = 8443;
    cert_key    = CWEB_STR("test_cert_file.pem");
    private_key = CWEB_STR("test_private_key.pem");
    int ret = cweb_create_test_certificate(
        CWEB_STR("C"),
        CWEB_STR("O"),
        CWEB_STR("CN"),
        cert_key,
        private_key
    );
    if (ret < 0) return -1;
#endif

    CWEB *cweb = cweb_init(addr, port, secure_port, cert_key, private_key);
    if (cweb == NULL) {
        cweb_global_free();
        return -1;
    }

    if (cweb_enable_database(cweb, database_file, schema_file) < 0) {
        cweb_free(cweb);
        cweb_global_free();
        return -1;
    }

    cweb_trace_sql(cweb, true);
    cweb_enable_template_cache(cweb, false);

    for (;;) {

        CWEB_Request *req = cweb_wait(cweb);
        if (req == NULL) break;

        if (0) {}
        else if (cweb_match_endpoint(req, CWEB_STR("/api/login")))   endpoint_api_login(cweb, req);
        else if (cweb_match_endpoint(req, CWEB_STR("/api/signup")))  endpoint_api_signup(cweb, req);
        else if (cweb_match_endpoint(req, CWEB_STR("/api/logout")))  endpoint_api_logout(cweb, req);
        else if (cweb_match_endpoint(req, CWEB_STR("/api/post")))    endpoint_api_post(cweb, req);
        else if (cweb_match_endpoint(req, CWEB_STR("/api/comment"))) endpoint_api_comment(cweb, req);
        else if (cweb_match_endpoint(req, CWEB_STR("/index")))       endpoint_index(cweb, req);
        else if (cweb_match_endpoint(req, CWEB_STR("/write")))       endpoint_write(cweb, req);
        else if (cweb_match_endpoint(req, CWEB_STR("/login")))       endpoint_login(cweb, req);
        else if (cweb_match_endpoint(req, CWEB_STR("/signup")))      endpoint_signup(cweb, req);
        else if (cweb_match_endpoint(req, CWEB_STR("/post")))        endpoint_post(cweb, req);
        else endpoint_fallback(cweb, req);
    }

    cweb_free(cweb);
    cweb_global_free();
    return 0;
}

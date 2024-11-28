/* Simple HTTP Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "protocol_examples_utils.h"
#include "esp_tls_crypto.h"
#include <esp_http_server.h>
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_tls.h"

#if !CONFIG_IDF_TARGET_LINUX
#include <esp_wifi.h>
#include <esp_system.h>
#include "nvs_flash.h"
#include "esp_eth.h"
#endif // !CONFIG_IDF_TARGET_LINUX

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_netif_net_stack.h"

#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"

#define EXAMPLE_HTTP_QUERY_KEY_MAX_LEN (64)

/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 */

static const char *TAG = "example";

uint64_t fw_len = 0;
bool is_ota = false;

#define BUFFSIZE 1024
uint64_t binary_file_length = 0;
/*deal with all receive packet*/
bool image_header_was_checked = false;
esp_ota_handle_t update_handle = 0;
const esp_partition_t *update_partition = NULL;

const esp_partition_t *configured = esp_ota_get_boot_partition();
const esp_partition_t *running = esp_ota_get_running_partition();

void ota_write2(char *ota_write_data, size_t len, bool final);

static void __attribute__((noreturn)) task_fatal_error(void)
{
    ESP_LOGE(TAG, "Exiting task due to fatal error...");
    (void)vTaskDelete(NULL);

    while (1)
    {
        ;
    }
}

static void infinite_loop(void)
{
    int i = 0;
    ESP_LOGI(TAG, "When a new firmware is available on the server, press the "
                  "reset button to download it");
    while (1)
    {
        ESP_LOGI(TAG, "Waiting for a new firmware ... %d", ++i);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

#if CONFIG_EXAMPLE_BASIC_AUTH

typedef struct
{
    char *username;
    char *password;
} basic_auth_info_t;

#define HTTPD_401 "401 UNAUTHORIZED" /*!< HTTP Response 401 */

static char *http_auth_basic(const char *username, const char *password)
{
    size_t out;
    char *user_info = NULL;
    char *digest = NULL;
    size_t n = 0;
    int rc = asprintf(&user_info, "%s:%s", username, password);
    if (rc < 0)
    {
        ESP_LOGE(TAG, "asprintf() returned: %d", rc);
        return NULL;
    }

    if (!user_info)
    {
        ESP_LOGE(TAG, "No enough memory for user information");
        return NULL;
    }
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info,
                             strlen(user_info));

    /* 6: The length of the "Basic " string
     * n: Number of bytes for a base64 encode format
     * 1: Number of bytes for a reserved which be used to fill zero
     */
    digest = calloc(1, 6 + n + 1);
    if (digest)
    {
        strcpy(digest, "Basic ");
        esp_crypto_base64_encode((unsigned char *)digest + 6, n, &out,
                                 (const unsigned char *)user_info,
                                 strlen(user_info));
    }
    free(user_info);
    return digest;
}

/* An HTTP GET handler */
static esp_err_t basic_auth_get_handler(httpd_req_t *req)
{
    char *buf = NULL;
    size_t buf_len = 0;
    basic_auth_info_t *basic_auth_info = req->user_ctx;

    buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1)
    {
        buf = calloc(1, buf_len);
        if (!buf)
        {
            ESP_LOGE(TAG, "No enough memory for basic authorization");
            return ESP_ERR_NO_MEM;
        }

        if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) ==
            ESP_OK)
        {
            ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
        }
        else
        {
            ESP_LOGE(TAG, "No auth value received");
        }

        char *auth_credentials = http_auth_basic(basic_auth_info->username,
                                                 basic_auth_info->password);
        if (!auth_credentials)
        {
            ESP_LOGE(TAG,
                     "No enough memory for basic authorization credentials");
            free(buf);
            return ESP_ERR_NO_MEM;
        }

        if (strncmp(auth_credentials, buf, buf_len))
        {
            ESP_LOGE(TAG, "Not authenticated");
            httpd_resp_set_status(req, HTTPD_401);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            httpd_resp_set_hdr(req, "WWW-Authenticate",
                               "Basic realm=\"Hello\"");
            httpd_resp_send(req, NULL, 0);
        }
        else
        {
            ESP_LOGI(TAG, "Authenticated!");
            char *basic_auth_resp = NULL;
            httpd_resp_set_status(req, HTTPD_200);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            int rc = asprintf(&basic_auth_resp,
                              "{\"authenticated\": true,\"user\": \"%s\"}",
                              basic_auth_info->username);
            if (rc < 0)
            {
                ESP_LOGE(TAG, "asprintf() returned: %d", rc);
                free(auth_credentials);
                return ESP_FAIL;
            }
            if (!basic_auth_resp)
            {
                ESP_LOGE(TAG,
                         "No enough memory for basic authorization response");
                free(auth_credentials);
                free(buf);
                return ESP_ERR_NO_MEM;
            }
            httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
            free(basic_auth_resp);
        }
        free(auth_credentials);
        free(buf);
    }
    else
    {
        ESP_LOGE(TAG, "No auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
    }

    return ESP_OK;
}

static httpd_uri_t basic_auth = {
    .uri = "/basic_auth",
    .method = HTTP_GET,
    .handler = basic_auth_get_handler,
};

static void httpd_register_basic_auth(httpd_handle_t server)
{
    basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
    if (basic_auth_info)
    {
        basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
        basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

        basic_auth.user_ctx = basic_auth_info;
        httpd_register_uri_handler(server, &basic_auth);
    }
}
#endif

/* An HTTP GET handler */
static esp_err_t hello_get_handler(httpd_req_t *req)
{
    char *buf;
    size_t buf_len;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1)
    {
        buf = (char *)malloc(buf_len);
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(TAG, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
    if (buf_len > 1)
    {
        buf = (char *)malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) ==
            ESP_OK)
        {
            ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
    if (buf_len > 1)
    {
        buf = (char *)malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) ==
            ESP_OK)
        {
            ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
        }
        free(buf);
    }

    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1)
    {
        buf = (char *)malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            char param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN],
                dec_param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN] = {0};
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "query1", param, sizeof(param)) ==
                ESP_OK)
            {
                ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
                example_uri_decode(
                    dec_param, param,
                    strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "query3", param, sizeof(param)) ==
                ESP_OK)
            {
                ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
                example_uri_decode(
                    dec_param, param,
                    strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "query2", param, sizeof(param)) ==
                ESP_OK)
            {
                ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
                example_uri_decode(
                    dec_param, param,
                    strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
        }
        free(buf);
    }

    /* Set some custom headers */
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char *resp_str = (const char *)req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0)
    {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t hello = {.uri = "/hello",
                                  .method = HTTP_GET,
                                  .handler = hello_get_handler,
                                  /* Let's pass response string in user
                                   * context to demonstrate it's usage */
                                  .user_ctx = (void *)"Hello World!"};

void ota_write(uint8_t *data, size_t len, bool final)
{
    // Upload handler chunks in data
    // Reset progress size on first frame
    uint32_t _current_progress_size = 0;
    uint32_t mode = 1;

    // Write chunked data to the free sketch space
    if (len)
    {
        size_t ret = Update.write(data, len);
        if (ret != len)
        {
            ESP_LOGE(TAG, "Write error len: %d", ret);
        }
        _current_progress_size += len;
        // Progress update callback
    }

    if (final)
        Update.end(true);

    // if (final)
    // { // if the final flag is set then this is the last frame of data
    //     if (!Update.end(true))
    //     { // true to set the size to the current progress
    //         // Save error to string
    //         String str;
    //         Update.printError(str);
    //         printf(str);
    //     }
    // }
    // else
    // {
    //     return;
    // }
}

/* An HTTP POST handler */
static esp_err_t update_post_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, remaining = req->content_len;
    // fw_len += req->content_len;

    ESP_LOGI(TAG, "remaining = %d", remaining);

    while (remaining > 0)
    {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                                  MIN(remaining, sizeof(buf)))) <= 0)
        {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT)
            {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        // httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        // ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        // ESP_LOGI(TAG, "len: %d", ret);
        // ESP_LOGI(TAG, "data: %.*s", ret, buf);
        // ESP_LOGI(TAG, "====================================");

        // ESP_LOGI(TAG, "=========== FIRMWARE UPDATE ==========");
        // ESP_LOGI(TAG, "======================================");
        if (remaining <= 0)
        {
            httpd_resp_send(req, NULL, 0);
            ota_write2(buf, ret, true);
        }
        else
            ota_write2(buf, ret, false);
    }

    // is_ota = true;

    // End response
    // httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t update = {.uri = "/update",
                                 .method = HTTP_POST,
                                 .handler = update_post_handler,
                                 .user_ctx = NULL};

/* This handler allows the custom error handling functionality to be
 * tested from client side. For that, when a PUT request 0 is sent to
 * URI /ctrl, the /hello and /update URIs are unregistered and following
 * custom error handler http_404_error_handler() is registered.
 * Afterwards, when /hello or /update is requested, this custom error
 * handler is invoked which, after sending an error message to client,
 * either closes the underlying socket (when requested URI is /update)
 * or keeps it open (when requested URI is /hello). This allows the
 * client to infer if the custom error handler is functioning as expected
 * by observing the socket state.
 */
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/hello", req->uri) == 0)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND,
                            "/hello URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    }
    else if (strcmp("/update", req->uri) == 0)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND,
                            "/update URI is not available");
        /* Return ESP_FAIL to close underlying socket */
        return ESP_FAIL;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

/* An HTTP PUT handler. This demonstrates realtime
 * registration and deregistration of URI handlers
 */
static esp_err_t ctrl_put_handler(httpd_req_t *req)
{
    char buf;
    int ret;

    if ((ret = httpd_req_recv(req, &buf, 1)) <= 0)
    {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT)
        {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

    if (buf == '0')
    {
        /* URI handlers can be unregistered using the uri string */
        ESP_LOGI(TAG, "Unregistering /hello and /update URIs");
        httpd_unregister_uri(req->handle, "/hello");
        httpd_unregister_uri(req->handle, "/update");
        /* Register the custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND,
                                   http_404_error_handler);
    }
    else
    {
        ESP_LOGI(TAG, "Registering /hello and /update URIs");
        httpd_register_uri_handler(req->handle, &hello);
        httpd_register_uri_handler(req->handle, &update);
        /* Unregister custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
    }

    /* Respond with empty body */
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t ctrl = {.uri = "/ctrl",
                                 .method = HTTP_PUT,
                                 .handler = ctrl_put_handler,
                                 .user_ctx = NULL};

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 8192;
#if CONFIG_IDF_TARGET_LINUX
    // Setting port as 8001 when building for Linux. Port 80 can be used only by
    // a priviliged user in linux. So when a unpriviliged user tries to run the
    // application, it throws bind error and the server is not started. Port
    // 8001 can be used by an unpriviliged user as well. So the application will
    // not throw bind error and the server will be started.
    config.server_port = 8001;
#endif // !CONFIG_IDF_TARGET_LINUX
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK)
    {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &hello);
        httpd_register_uri_handler(server, &update);
        httpd_register_uri_handler(server, &ctrl);
#if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
#endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

#if !CONFIG_IDF_TARGET_LINUX
static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_stop(server);
}

static void disconnect_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server)
    {
        ESP_LOGI(TAG, "Stopping webserver");
        if (stop_webserver(*server) == ESP_OK)
        {
            *server = NULL;
        }
        else
        {
            ESP_LOGE(TAG, "Failed to stop http server");
        }
    }
}

static void connect_handler(void *arg, esp_event_base_t event_base,
                            int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server == NULL)
    {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}
#endif // !CONFIG_IDF_TARGET_LINUX

#if CONFIG_ESP_WIFI_AUTH_OPEN
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_OPEN
#elif CONFIG_ESP_WIFI_AUTH_WEP
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WEP
#elif CONFIG_ESP_WIFI_AUTH_WPA_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA2_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA_WPA2_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_WPA2_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA3_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA3_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA2_WPA3_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_WPA3_PSK
#elif CONFIG_ESP_WIFI_AUTH_WAPI_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WAPI_PSK
#endif

/* AP Configuration */
#define EXAMPLE_ESP_WIFI_AP_SSID "ap-test"
#define EXAMPLE_ESP_WIFI_AP_PASSWD "lpca2138"
#define EXAMPLE_ESP_WIFI_CHANNEL 1
#define EXAMPLE_MAX_STA_CONN 1

/* The event group allows multiple bits for each event, but we only care about
 * two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

/*DHCP server option*/
#define DHCPS_OFFER_DNS 0x02

static const char *TAG_AP = "WiFi SoftAP";

static int s_retry_num = 0;

/* FreeRTOS event group to signal when we are connected/disconnected */
static EventGroupHandle_t s_wifi_event_group;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED)
    {
        wifi_event_ap_staconnected_t *event =
            (wifi_event_ap_staconnected_t *)event_data;
        ESP_LOGI(TAG_AP, "Station " MACSTR " joined, AID=%d",
                 MAC2STR(event->mac), event->aid);
    }
    else if (event_base == WIFI_EVENT &&
             event_id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        wifi_event_ap_stadisconnected_t *event =
            (wifi_event_ap_stadisconnected_t *)event_data;
        ESP_LOGI(TAG_AP, "Station " MACSTR " left, AID=%d", MAC2STR(event->mac),
                 event->aid);
    }
}

/* Initialize soft AP */
esp_netif_t *wifi_init_softap(void)
{
    esp_netif_t *esp_netif_ap = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    char ssid[] = EXAMPLE_ESP_WIFI_AP_SSID;
    char pswd[] = EXAMPLE_ESP_WIFI_AP_PASSWD;

    wifi_config_t wifi_ap_config = {};
    memcpy(wifi_ap_config.ap.ssid, ssid, sizeof(ssid));
    wifi_ap_config.ap.ssid_len = strlen(EXAMPLE_ESP_WIFI_AP_SSID);
    wifi_ap_config.ap.channel = EXAMPLE_ESP_WIFI_CHANNEL;
    memcpy(wifi_ap_config.ap.password, pswd, sizeof(pswd));
    wifi_ap_config.ap.max_connection = EXAMPLE_MAX_STA_CONN;
    wifi_ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_ap_config.ap.pmf_cfg.required = false;

    if (strlen(EXAMPLE_ESP_WIFI_AP_PASSWD) == 0)
        wifi_ap_config.ap.authmode = WIFI_AUTH_OPEN;

    /* Register Event handler */
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG_AP,
             "wifi_init_softap finished. SSID:%s password:%s channel:%d",
             EXAMPLE_ESP_WIFI_AP_SSID, EXAMPLE_ESP_WIFI_AP_PASSWD,
             EXAMPLE_ESP_WIFI_CHANNEL);

    return esp_netif_ap;
}

void setup()
{
    static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_wifi_event_group = xEventGroupCreate();

    ESP_LOGI(TAG_AP, "ESP_WIFI_MODE_AP");
    esp_netif_t *esp_netif_ap = wifi_init_softap();

    Update.begin(UPDATE_SIZE_UNKNOWN);
    server = start_webserver();

    if (configured != running)
    {
        ESP_LOGW(TAG,
                 "Configured OTA boot partition at offset 0x%08" PRIx32
                 ", but running from offset 0x%08" PRIx32,
                 configured->address, running->address);
        ESP_LOGW(TAG, "(This can happen if either the OTA boot data or "
                      "preferred boot image become corrupted somehow.)");
    }
    ESP_LOGI(TAG,
             "Running partition type %d subtype %d (offset 0x%08" PRIx32 ")",
             running->type, running->subtype, running->address);

    update_partition = esp_ota_get_next_update_partition(NULL);
    assert(update_partition != NULL);
    ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%" PRIx32,
             update_partition->subtype, update_partition->address);
}

void loop()
{
    vTaskDelay(20);
}

void ota_write2(char *ota_write_data, size_t len, bool final)
{
    esp_err_t err;

    if (image_header_was_checked == false)
    {
        esp_app_desc_t new_app_info;
        // check current version with downloading
        memcpy(&new_app_info,
               &ota_write_data[sizeof(esp_image_header_t) +
                               sizeof(esp_image_segment_header_t)],
               sizeof(esp_app_desc_t));
        ESP_LOGI(TAG, "New firmware version: %s", new_app_info.version);

        esp_app_desc_t running_app_info;
        if (esp_ota_get_partition_description(running, &running_app_info) ==
            ESP_OK)
        {
            ESP_LOGI(TAG, "Running firmware version: %s",
                     running_app_info.version);
        }

        const esp_partition_t *last_invalid_app =
            esp_ota_get_last_invalid_partition();
        esp_app_desc_t invalid_app_info;
        if (esp_ota_get_partition_description(last_invalid_app,
                                              &invalid_app_info) == ESP_OK)
        {
            ESP_LOGI(TAG, "Last invalid firmware version: %s",
                     invalid_app_info.version);
        }

        // check current version with last invalid partition
        if (last_invalid_app != NULL)
        {
            if (memcmp(invalid_app_info.version, new_app_info.version,
                       sizeof(new_app_info.version)) == 0)
            {
                ESP_LOGW(TAG, "New version is the same as invalid version.");
                ESP_LOGW(TAG,
                         "Previously, there was an attempt to launch "
                         "the firmware with %s version, but it failed.",
                         invalid_app_info.version);
                ESP_LOGW(TAG, "The firmware has been rolled back "
                              "to the previous version.");

                infinite_loop();
            }
        }
#ifndef CONFIG_EXAMPLE_SKIP_VERSION_CHECK
        if (memcmp(new_app_info.version, running_app_info.version,
                   sizeof(new_app_info.version)) == 0)
        {
            ESP_LOGW(TAG, "Current running version is the same as a "
                          "new. We will not continue the update.");
            infinite_loop();
        }
#endif

        image_header_was_checked = true;

        err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES,
                            &update_handle);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
            esp_ota_abort(update_handle);
            task_fatal_error();
        }
        ESP_LOGI(TAG, "esp_ota_begin succeeded");
    }
    err = esp_ota_write(update_handle, (const void *)ota_write_data, len);
    if (err != ESP_OK)
    {
        esp_ota_abort(update_handle);
        task_fatal_error();
    }
    binary_file_length += len;
    ESP_LOGI(TAG, "Written image length %"PRIu64, binary_file_length);

    if (final == true)
    {
        err = esp_ota_end(update_handle);
        if (err != ESP_OK)
        {
            if (err == ESP_ERR_OTA_VALIDATE_FAILED)
            {
                ESP_LOGE(TAG, "Image validation failed, image is corrupted");
            }
            else
            {
                ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
            }
            task_fatal_error();
        }

        err = esp_ota_set_boot_partition(update_partition);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!",
                    esp_err_to_name(err));
            task_fatal_error();
        }
        ESP_LOGI(TAG, "Prepare to restart system!");
        esp_restart();
        return;
    }
    else
        return;
}
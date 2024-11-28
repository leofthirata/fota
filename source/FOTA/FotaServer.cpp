/******************************************************************************
 * Copyright © 2008 - 2024, F&K Group. All rights reserved.
 *
 * No part of this software may be reproduced, distributed, or transmitted in
 * any form or by any means without the prior written permission of the F&K Group
 * company.
 *
 * For permission requests, contact the company through the e-mail address
 * leonardo.hirata@fkgroup.com.br with subject "Software Licence Request".
 ******************************************************************************/

/*******************************************************************************
 * F&K Group FOTA Webserver
 *
 * FotaServer class declaration.
 *
 * @author Leonardo Hirata
 * @copyright F&K Group
 ******************************************************************************/

#include <cstring>
#include <cstdlib>
#include <cstring>

#include "esp_log.h"

#include "FOTA/FotaServer.hpp"

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

namespace FOTA
{

static const char *m_tag = "Fota";
static size_t bin_size = 0;
static bool is_fota_ok = false;
static bool can_send_err = false;

void update_task(void *args);
void cancel_task(void *args);

static QueueHandle_t xUpdateQueue;

static TaskHandle_t m_cancel_task = NULL;

esp_err_t _http_404_error_handler(httpd_req_t *req, httpd_err_code_t err);
esp_err_t _http_update_post_handler(httpd_req_t *req);
esp_err_t _hello_get_handler(httpd_req_t *req);
esp_err_t _cancel_get_handler(httpd_req_t *req);

void _wifi_event_handler(void *arg, esp_event_base_t event_base,
                         int32_t event_id, void *event_data);
void _ip_event_handler(void *arg, esp_event_base_t event_base,
                         int32_t event_id, void *event_data);
esp_err_t stop_webserver(httpd_handle_t server);

void print_bar(uint32_t value, uint32_t total)
{
#ifndef CONFIG_BOOTLOADER_LOG_LEVEL_NONE
    uint8_t v;

    if (total < 50)
        printf(" total = %" PRIu32, total);
    v = (value * 100) / total;
    printf("\r");
    printf(" Progress:|");
    for (int i = 0; i < 50; i++)
    {
        if (i < v / 2)
            printf("X");
        else
            printf("_");
    }
    printf("| %" PRIu32 " of %" PRIu32 " bytes (%3.2f%%)", value, total,
           (value * 100.0) / total);
#endif
}

FotaServer::FotaServer()
{
    m_server = NULL;
    m_image_checked = false;
    m_bin_len = 0;
    m_update = {};
    m_hello = {};
    m_update_handle = 0;
    m_update_partition = NULL;
    m_update_ok = false;

    m_ssid = NULL;
    m_pswd = NULL;
    m_ssid_len = 0;
    m_pswd_len = 0;
    m_port = WEBSERVER_PORT_DEFAULT;
    m_channel = WEBSERVER_CHANNEL_DEFAULT;
    m_priority = UPDATE_TASK_PRIORITY_DEFAULT;

    m_update_task = NULL;

    m_err = ESP_OK;
    m_req = NULL;
    m_err_msg = NULL;

    m_fs = NULL;
    m_ff = NULL;

    m_cc = NULL;
    m_dc = NULL;

    m_esp_netif_ap = NULL;

    m_stop = false;
}

FotaServer::~FotaServer()
{
    // if (m_update_task != NULL)
    //     vTaskDelete(m_update_task);

    // if (xUpdateQueue != NULL)
    //     vQueueDelete(xUpdateQueue);

    // if (m_server != NULL)
    //     stop_webserver(m_server);

    // if (m_update_handle != NULL)
    //     esp_ota_abort(m_update_handle);

    // esp_wifi_stop();
    // esp_wifi_deinit();

    // if (m_esp_netif_ap != NULL)
    // {
    //     esp_wifi_clear_default_wifi_driver_and_handlers(m_esp_netif_ap); // <-add this!
    //     esp_netif_destroy(m_esp_netif_ap);
    // }
}

esp_err_t FotaServer::init(const char *ssid, uint32_t ssid_len, const char *pswd, uint32_t pswd_len, uint16_t port, uint8_t channel, uint8_t priority)
{
    m_ssid = ssid;
    m_ssid_len = ssid_len;
    m_pswd = pswd;
    m_pswd_len = pswd_len;
    m_port = port;
    m_channel = channel;
    m_priority = priority;

    esp_err_t ret = ESP_OK;

    xUpdateQueue = xQueueCreate(1, sizeof(UpdatePacket_t));

    xTaskCreate(update_task, "update_task", 5120, this, m_priority, &m_update_task);
    xTaskCreate(cancel_task, "cancel_task", 3072, this, 1, &m_cancel_task);

    m_configured = esp_ota_get_boot_partition();
    m_running = esp_ota_get_running_partition();

    ESP_LOGI(m_tag, "ESP_WIFI_MODE_AP");
    m_esp_netif_ap = wifi_init_softap();
    
    esp_netif_get_ip_info(m_esp_netif_ap, &m_server_info);
    ESP_LOGW(m_tag, "server ip: " IPSTR, IP2STR(&m_server_info.ip));
    ESP_LOGW(m_tag, "server gw: " IPSTR, IP2STR(&m_server_info.gw));
    ESP_LOGW(m_tag, "server netmask: " IPSTR, IP2STR(&m_server_info.netmask));

    m_update.uri = WEBSERVER_FOTA_URI;
    m_update.method = HTTP_POST;
    m_update.handler = _http_update_post_handler;
    m_update.user_ctx = NULL;

    m_hello.uri = "/hello";
    m_hello.method = HTTP_GET;
    m_hello.handler = _hello_get_handler;
    m_hello.user_ctx = (void *)"Firmware upgrade service is alive!";

    m_cancel.uri = "/cancel";
    m_cancel.method = HTTP_GET;
    m_cancel.handler = _cancel_get_handler;
    m_cancel.user_ctx = (void *)"Aborting firmware update.";

    m_server = start_webserver();
    if (m_server == NULL)
    {
        ESP_LOGI(m_tag, "Starting webserver");
        m_server = start_webserver();
    }

    if (m_configured != m_running)
    {
        ESP_LOGW(m_tag,
                 "m_configured OTA boot partition at offset 0x%08" PRIx32
                 ", but running from offset 0x%08" PRIx32,
                 m_configured->address, m_running->address);
        ESP_LOGW(m_tag, "(This can happen if either the OTA boot data or "
                        "preferred boot image become corrupted somehow.)");
    }
    ESP_LOGI(m_tag,
             "Running partition type %d subtype %d (offset 0x%08" PRIx32 ")",
             m_running->type, m_running->subtype, m_running->address);

    m_update_partition = esp_ota_get_next_update_partition(NULL);
    assert(m_update_partition != NULL);
    ESP_LOGI(m_tag,
             "Fota will write to partition subtype %d at offset 0x%" PRIx32,
             m_update_partition->subtype, m_update_partition->address);

    return ESP_OK;
}

esp_err_t FotaServer::get_ssid(const char *ssid)
{
    if (m_ssid == NULL)
        return ESP_FAIL;

    memcpy((void *)ssid, m_ssid, m_ssid_len);
    return ESP_OK;
}

esp_err_t FotaServer::get_pswd(const char *pswd)
{
    if (m_pswd == NULL)
        return ESP_FAIL;

    memcpy((void *)pswd, m_pswd, m_pswd_len);
    return ESP_OK;
}

esp_err_t FotaServer::get_port(uint16_t *port)
{
    *port = m_port;
    return ESP_OK;
}

esp_err_t FotaServer::get_channel(uint8_t *channel)
{
    *channel = m_channel;
    return ESP_OK;
}

esp_err_t FotaServer::get_priority(uint8_t *priority)
{
    *priority = m_priority;
    return ESP_OK;
}

esp_err_t FotaServer::get_server_info(esp_netif_ip_info_t *info)
{
    *info = m_server_info;
    return ESP_OK;
}

void FotaServer::on_started_callback(fota_server_handle_t f)
{
    m_fs = f;
}

void FotaServer::on_finished_callback(fota_server_handle_t f)
{
    m_ff = f;
}

void FotaServer::on_connected_callback(server_connected_handle_t c)
{
    m_cc = c;
}

void FotaServer::on_disconnected_callback(server_disconnected_handle_t c)
{
    m_dc = c;
}

esp_err_t _http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/update", req->uri) != 0 && strcmp("/hello", req->uri) != 0 && strcmp("/cancel", req->uri) != 0)
    {
        char payload[512];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(payload, 512, "%s URI is not available", req->uri);
#pragma GCC diagnostic pop
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, payload);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/* An HTTP post handler */
esp_err_t _hello_get_handler(httpd_req_t *req)
{
    const char *resp_str = (const char *)req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    
    return ESP_OK;
}


/* An HTTP GET handler */
esp_err_t _cancel_get_handler(httpd_req_t *req)
{
    const char *resp_str = (const char *)req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    xTaskNotify(m_cancel_task, 0, eSetValueWithOverwrite);
    return ESP_OK;
}

// other error handlers
// timer to close webserver if timeout
esp_err_t _http_update_post_handler(httpd_req_t *req)
{
    uint64_t remaining = req->content_len;
    bin_size = remaining;
    UpdatePacket_t update_packet;

    can_send_err = false;

    update_packet.req = req;

    ESP_LOGI(m_tag, "remaining = %" PRIu64, remaining);

    while (remaining > 0)
    {
        /* Read the data for the request */
        if ((update_packet.len = httpd_req_recv(
                 update_packet.req, update_packet.buf,
                 MIN(remaining, sizeof(update_packet.buf)))) <= 0)
        {
            if (update_packet.len == HTTPD_SOCK_ERR_TIMEOUT)
            {
                /* Retry receiving if timeout occurred */
                continue;
            }
            // todo answer err code
            return ESP_FAIL;
        }

        remaining -= update_packet.len;

        update_packet.ok = remaining <= 0 ? true : false;

        xQueueSend(xUpdateQueue, &update_packet, portMAX_DELAY);
    }

    while (!is_fota_ok && can_send_err == false);

    return ESP_OK;
}

void _wifi_event_handler(void *arg, esp_event_base_t event_base,
                         int32_t event_id, void *event_data)
{
    FOTA::FotaServer *fota = static_cast<FOTA::FotaServer *>(arg);

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED)
    {
        wifi_event_ap_staconnected_t *event =
            (wifi_event_ap_staconnected_t *)event_data;
        ESP_LOGI(m_tag, "Station " MACSTR " joined, AID=%d",
                 MAC2STR(event->mac), event->aid);
    }
    else if (event_base == WIFI_EVENT &&
             event_id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        wifi_event_ap_stadisconnected_t *event =
            (wifi_event_ap_stadisconnected_t *)event_data;
        ESP_LOGI(m_tag, "Station " MACSTR " left, AID=%d", MAC2STR(event->mac),
                 event->aid);

        if (fota->m_dc)
            fota->m_dc(event->mac);
    }
}

void _ip_event_handler(void *arg, esp_event_base_t event_base,
                         int32_t event_id, void *event_data)
{
    FOTA::FotaServer *fota = static_cast<FOTA::FotaServer *>(arg);

// IP_EVENT_STA_GOT_IP
    if (event_base == IP_EVENT &&
        event_id == IP_EVENT_AP_STAIPASSIGNED)
    {
        ip_event_ap_staipassigned_t *event = (ip_event_ap_staipassigned_t *)event_data;
        ESP_LOGI(m_tag, "ip: " IPSTR, IP2STR(&event->ip));
        
        if (fota->m_cc)
            fota->m_cc(event);
    }
}

esp_netif_t *FotaServer::wifi_init_softap(void)
{
    esp_netif_t *esp_netif_ap = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_ap_config = {};
    memcpy(wifi_ap_config.ap.ssid, m_ssid, strlen(m_ssid));
    wifi_ap_config.ap.ssid_len = strlen(m_ssid);
    wifi_ap_config.ap.channel = m_channel;
    memcpy(wifi_ap_config.ap.password, m_pswd, strlen(m_pswd));
    wifi_ap_config.ap.max_connection = WEBSERVER_MAX_CONN;
    wifi_ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_ap_config.ap.pmf_cfg.required = false;

    if (strlen(m_pswd) == 0)
        wifi_ap_config.ap.authmode = WIFI_AUTH_OPEN;

    /* Register Event handler */
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &_wifi_event_handler, this, NULL));
    /* Register Event handler */
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, ESP_EVENT_ANY_ID, &_ip_event_handler, this, NULL));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(m_tag, "wifi_init_softap finished. SSID:%s password:%s channel:%d",
             m_ssid, m_pswd, m_channel);

    return esp_netif_ap;
}

httpd_handle_t FotaServer::start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = WEBSERVER_STACK_SIZE;
    config.server_port = m_port;
    config.lru_purge_enable = true;

    ESP_LOGI(m_tag, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK)
    {
        ESP_LOGI(m_tag, "Registering URI handlers");
        httpd_register_uri_handler(server, &m_update);
        httpd_register_uri_handler(server, &m_hello);
        httpd_register_uri_handler(server, &m_cancel);
        httpd_register_err_handler(server, HTTPD_404_NOT_FOUND,
                                   _http_404_error_handler);
        return server;
    }

    ESP_LOGI(m_tag, "Error starting server!");
    return NULL;
}

esp_err_t stop_webserver(httpd_handle_t server)
{
    return httpd_stop(server);
}

void FotaServer::send_err(esp_err_t err)
{
    char payload[100];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    snprintf(payload, 100, "%s reasoning (%s)", m_err_msg, esp_err_to_name(err));
#pragma GCC diagnostic pop
    httpd_resp_send_err(m_req, HTTPD_400_BAD_REQUEST, payload);
    can_send_err = true;
}

void FotaServer::send_ok()
{
    httpd_resp_send(m_req, NULL, 0);
    stop(ESP_OK);
}

esp_err_t FotaServer::update(char *data, size_t len, bool final)
{
    esp_err_t err;

    if (m_image_checked == false)
    {
        esp_app_desc_t new_app_info;
        err = get_new_firmware_version(&new_app_info, data, len);
        if (err != ESP_OK)
        {
            m_err_msg = "Invalid data.";
            return err;
        }

        esp_app_desc_t running_app_info;
        err = get_running_firmware_version(&running_app_info);
        if (err != ESP_OK)
        {
            m_err_msg = "Failed to get running firmware version.";
            return err;
        }

        const esp_partition_t *last_invalid_app =
            esp_ota_get_last_invalid_partition();
        esp_app_desc_t invalid_app_info;

        err = is_firmware_valid(last_invalid_app, &new_app_info,
                              &invalid_app_info);
        if (err != ESP_OK)
        {
            m_err_msg = "Invalid firmware.";
            return err; // abort ota and close session?
        }

        // esp err t
        err = is_new_firmware_new(&new_app_info, &running_app_info);
        if (err != ESP_OK)
        {
            m_err_msg = "New firmware version is the same as the running firmware version. Skipping update.";
            return err; // abort ota and close session?
        }

        m_image_checked = true;

        err = fota_begin(m_update_partition, OTA_WITH_SEQUENTIAL_WRITES);
        if (err != ESP_OK)
        {
            m_err_msg = "Failed to begin update.";
            return err; // abort ota and close session?
        }

        if (m_fs)
            m_fs(err); // emit fota started signal
    }

    err = fota_write((const void *)data, len);
    if (err != ESP_OK)
    {
        m_err_msg = "Failed to write data.";
        return err;
    }

    if (final == true)
    {
        err = fota_end();
        if (err != ESP_OK)
        {
            m_err_msg = "Failed to write data.";
            return err;
        }


        send_ok();
        return err;
    }
    else
        return ESP_OK;
}

esp_err_t FotaServer::get_new_firmware_version(esp_app_desc_t *new_app_info,
                                          const char *data, size_t len)
{
    if (len < sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t))
    {
        ESP_LOGI(m_tag, "No image header found");
        return ESP_FAIL;
    }
    // check current version with downloading
    if (len < sizeof(esp_app_desc_t))
    {
        ESP_LOGI(m_tag, "Not a valid firmware");
        return ESP_FAIL;
    }

    memcpy(
        new_app_info,
        &data[sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)],
        sizeof(esp_app_desc_t));
    ESP_LOGI(m_tag, "New firmware version: %s", new_app_info->version);

    return ESP_OK;
}

esp_err_t FotaServer::get_running_firmware_version(esp_app_desc_t *running_app_info)
{
    esp_err_t err = esp_ota_get_partition_description(m_running, running_app_info);
    ESP_LOGI(m_tag, "Running firmware version: %s",
                running_app_info->version);

    return err;
}

esp_err_t FotaServer::is_firmware_valid(const esp_partition_t *last_invalid_app,
                                        esp_app_desc_t *new_app_info,
                                        esp_app_desc_t *invalid_app_info)
{
    if (esp_ota_get_partition_description(last_invalid_app, invalid_app_info) ==
        ESP_OK)
        ESP_LOGI(m_tag, "Last invalid firmware version: %s",
                 invalid_app_info->version);

    // check current version with last invalid partition
    if (last_invalid_app != NULL)
    {
        if (memcmp(invalid_app_info->version, new_app_info->version,
                   sizeof(new_app_info->version)) == 0)
        {
            ESP_LOGW(m_tag, "New version is the same as invalid version.");
            ESP_LOGW(m_tag,
                     "Previously, there was an attempt to launch "
                     "the firmware with %s version, but it failed.",
                     invalid_app_info->version);
            ESP_LOGW(m_tag, "The firmware has been rolled back "
                            "to the previous version.");

            return ESP_FAIL;
        }
    }

    return ESP_OK;
}

esp_err_t FotaServer::is_new_firmware_new(esp_app_desc_t *new_app_info,
                                          esp_app_desc_t *running_app_info)
{
    if (memcmp(new_app_info->version, running_app_info->version,
               sizeof(new_app_info->version)) == 0)
    {
        ESP_LOGW(m_tag, "Current running version is the same as a "
                        "new. We will not continue the update.");

        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t FotaServer::fota_begin(const esp_partition_t *partition, size_t image_size)
{
    esp_err_t err = esp_ota_begin(partition, image_size, &m_update_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(m_tag, "esp_ota_begin failed (%s)", esp_err_to_name(err));
        esp_ota_abort(m_update_handle);
    }
    return err;
}

esp_err_t FotaServer::fota_write(const void *data, size_t size)
{
    esp_err_t err = esp_ota_write(m_update_handle, data, size);
    if (err != ESP_OK)
    {
        esp_ota_abort(m_update_handle);
        return err;
    }

    m_bin_len += size;
    print_bar(m_bin_len, bin_size);
    
    return err;
}

esp_err_t FotaServer::fota_end()
{
    esp_err_t err = esp_ota_end(m_update_handle);
    if (err != ESP_OK)
    {
        if (err == ESP_ERR_OTA_VALIDATE_FAILED)
            ESP_LOGE(m_tag, "Image validation failed, image is corrupted");
        else
            ESP_LOGE(m_tag, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        return err;
    }
    
    err = esp_ota_set_boot_partition(m_update_partition);
    if (err != ESP_OK)
    {
        ESP_LOGE(m_tag, "esp_ota_set_boot_partition failed (%s)!",
                 esp_err_to_name(err));
        return err;
    }
    return err;
}

void FotaServer::stop(esp_err_t err)
{
    if (!m_stop)
    {
        m_stop = true;
        is_fota_ok = true;

        if (m_ff)
            m_ff(err);

        stop_webserver(m_server);
        esp_ota_abort(m_update_handle);

        esp_wifi_stop();
        esp_wifi_deinit();
        esp_wifi_clear_default_wifi_driver_and_handlers(m_esp_netif_ap); // <-add this!
        esp_netif_destroy(m_esp_netif_ap);

        vTaskDelete(m_update_task);
        vQueueDelete(xUpdateQueue);

        ESP_LOGW(m_tag, "Freeing memory from Firmware upgrade service");
    }
    else
        ESP_LOGW(m_tag, "Service already stopped");
}

void cancel_task(void *args)
{
    FOTA::FotaServer *fota = static_cast<FOTA::FotaServer *>(args);

    auto event = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

    ESP_LOGW(m_tag, "cancel_task notified");

    fota->stop(ESP_FAIL);

    vTaskDelete(NULL);
}

void update_task(void *args)
{
    FOTA::FotaServer *fota = static_cast<FOTA::FotaServer *>(args);

    UpdatePacket_t update_packet;
    esp_err_t err;

    while (!update_packet.ok)
    {
        if (xQueueReceive(xUpdateQueue, &update_packet, portMAX_DELAY))
        {
            if (fota->m_req == NULL)
                fota->m_req = update_packet.req;
        
            err = fota->update(update_packet.buf,
                         update_packet.len, update_packet.ok);

            if (err != ESP_OK)
            {
                fota->send_err(err);
                esp_ota_abort(fota->m_update_handle);
                fota->m_image_checked = false;
            }
            if (can_send_err == true) // so queue doesnt delete itself after finding an error
            {
                update_packet.ok = false;
                fota->m_req = NULL;
            }
        }

        vTaskDelay(10);
    }

    vQueueDelete(xUpdateQueue);
    vTaskDelete(NULL);
}

} // namespace FOTA

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

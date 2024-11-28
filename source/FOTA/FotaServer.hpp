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

#pragma once

#include <sys/param.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// wifi-ap
#include "esp_mac.h"
#include <esp_http_server.h>
#include "esp_netif.h"
#include <esp_wifi.h>

// fota
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

namespace FOTA
{

/**
 * @brief Fota finished event callback function definition.
 */
using fota_server_handle_t = void (*)(esp_err_t);

/**
 * @brief Fota finished event callback function definition.
 */
using server_connected_handle_t = void (*)(ip_event_ap_staipassigned_t*);
using server_disconnected_handle_t = void (*)(uint8_t*);

/**
 * @brief Fota Server class.
 */

typedef struct
{
    httpd_req_t *req;
    char buf[1024];
    uint64_t len = 0;
    bool ok = false;
} UpdatePacket_t;

class FotaServer
{
public:
    static const uint32_t DEFAULT_PERIOD_SEC =
        3600; /// Default auto fetch period in seconds.
    static const uint32_t DEFAULT_STACK_SIZE =
        4096; /// Default fota thread stack size.
    static const uint32_t DEFAULT_THREAD_PRIORITY =
        4; /// Default fota thread priority.
    static const uint32_t DEFAULT_BUFFER_SIZE =
        2048; /// Default fota buffer size.

    const char *WEBSERVER_FOTA_URI = "/update";
    static const uint32_t WEBSERVER_STACK_SIZE = 4096;
    static const uint16_t WEBSERVER_PORT_DEFAULT = 8000;
    static const uint8_t WEBSERVER_CHANNEL_DEFAULT = 1;
    static const uint16_t WEBSERVER_MAX_CONN = 1;
    static const uint8_t UPDATE_TASK_PRIORITY_DEFAULT = 10;

    /**
     * @brief Object constructor.
     */
    FotaServer();

    /**
     * @brief Object destructor.
     */
    ~FotaServer();

    esp_err_t get_ssid(const char *ssid);
    esp_err_t get_pswd(const char *pswd);
    esp_err_t get_port(uint16_t *port);
    esp_err_t get_channel(uint8_t *channel);
    esp_err_t get_priority(uint8_t *priority);
    esp_err_t get_server_info(esp_netif_ip_info_t *info);
    void on_started_callback(fota_server_handle_t f);
    void on_finished_callback(fota_server_handle_t f);
    void on_connected_callback(server_connected_handle_t c);
    void on_disconnected_callback(server_disconnected_handle_t c);
    esp_err_t init(const char *ssid, uint32_t ssid_len, const char *pswd, uint32_t pswd_len, uint16_t port, uint8_t channel, uint8_t priority);
    void stop(esp_err_t err);

private:

    httpd_handle_t m_server;
    bool m_image_checked; // image header check
    uint64_t m_bin_len;
    esp_ota_handle_t m_update_handle;
    esp_netif_t *m_esp_netif_ap;
    const esp_partition_t *m_update_partition;
    const esp_partition_t *m_configured;
    const esp_partition_t *m_running;
    const char *m_tag = "FotaServer.cpp";
    httpd_uri_t m_update;
    httpd_uri_t m_hello;
    httpd_uri_t m_cancel;
    bool m_update_ok;
    bool m_stop;

    const char *m_ssid;
    const char *m_pswd;
    uint32_t m_ssid_len;
    uint32_t m_pswd_len;
    uint16_t m_port;
    uint8_t m_channel;
    uint8_t m_priority;

    TaskHandle_t m_update_task;
    httpd_req_t *m_req;

    esp_err_t m_err;
    const char *m_err_msg;

    fota_server_handle_t m_ff;
    fota_server_handle_t m_fs;
    server_connected_handle_t m_cc;
    server_disconnected_handle_t m_dc;

    esp_netif_ip_info_t m_server_info;

    /**
     * @brief Fota worker task.
     *
     * This task is used to call @f run without blocking the user task.
     *
     * @param[in] param Pointer to the fota object that will be run.
     */

    esp_netif_t *wifi_init_softap(void);
    httpd_handle_t start_webserver(void);
    esp_err_t update(char *data, size_t len, bool final);
    esp_err_t get_new_firmware_version(esp_app_desc_t *new_app_info, const char *data, size_t len);
    esp_err_t get_running_firmware_version(esp_app_desc_t *running_app_info);
    esp_err_t is_firmware_valid(const esp_partition_t *last_invalid_app,
                           esp_app_desc_t *new_app_info,
                           esp_app_desc_t *invalid_app_info);
    esp_err_t is_new_firmware_new(esp_app_desc_t *new_app_info,
                             esp_app_desc_t *running_app_info);
    esp_err_t fota_begin(const esp_partition_t *partition, size_t image_size);
    esp_err_t fota_write(const void *data, size_t size);
    esp_err_t fota_end();

    void send_err(esp_err_t err);
    void send_ok();

    friend void update_task(void *args);
    friend void cancel_task(void *args);

    friend void _wifi_event_handler(void *arg, esp_event_base_t event_base,
                         int32_t event_id, void *event_data);
    friend void _ip_event_handler(void *arg, esp_event_base_t event_base,
                         int32_t event_id, void *event_data);
};

} // namespace FOTA

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

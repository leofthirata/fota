#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "esp_log.h"

#include "FOTA/FotaServer.hpp"

static const char *TAG = "example";

#define SERVER_SSID "fota server"
#define SERVER_PSWD "12345678"
#define SERVER_SSID_LEN 11
#define SERVER_PSWD_LEN 8

FOTA::FotaServer *fota = new FOTA::FotaServer();
bool finished = false;

/*
    Fota finished event.
*/
void fotaFinished(esp_err_t rslt)
{
    finished = true;
    // Get final heap size.
    uint32_t finalHeap, minimalHeap;

    finalHeap = esp_get_free_heap_size();
    minimalHeap = esp_get_minimum_free_heap_size();

    // delete fota;
    // Log heap.
    ESP_LOGI(TAG, "HEAP: FINAL=%" PRIu32 ", MIN=%" PRIu32, finalHeap, minimalHeap);

    if (rslt == ESP_OK)
    {
        ESP_LOGI(TAG, "FOTA SUCCESS");
    }
    else
    {
        ESP_LOGE(TAG, "FOTA FAILED: %s", esp_err_to_name(rslt));
    }
}

void on_connected(ip_event_ap_staipassigned_t *dev)
{
    ESP_LOGW(TAG, "connected");
    ESP_LOGI(TAG, "ip: " IPSTR, IP2STR(&dev->ip));
    ESP_LOG_BUFFER_HEX(TAG, dev->mac, 6);
}

void on_disconnected(uint8_t mac[6])
{
    ESP_LOGW(TAG, "disconnected");
    ESP_LOG_BUFFER_HEX(TAG, mac, 6);
}

extern "C" void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Get final heap size.
    uint32_t initialHeap, minimalHeap;
    initialHeap = esp_get_free_heap_size();
    minimalHeap = esp_get_minimum_free_heap_size();

    // Log heap.
    ESP_LOGI(TAG, "HEAP: INITIAL=%" PRIu32 ", MIN=%" PRIu32, initialHeap, minimalHeap);

    char ssid[30];
    char pswd[30];
    uint16_t port;
    uint8_t priority;
    uint8_t channel;

    fota->on_finished_callback(fotaFinished);
    fota->on_connected_callback(on_connected);
    fota->on_disconnected_callback(on_disconnected);

    ESP_ERROR_CHECK(fota->init(SERVER_SSID, SERVER_SSID_LEN, SERVER_PSWD, SERVER_PSWD_LEN, 8000, 5, 1));

    if (fota->get_ssid(ssid) == ESP_OK)
        ESP_LOGI(TAG, "ssid %s", ssid);
    
    if (fota->get_pswd(pswd) == ESP_OK)
        ESP_LOGI(TAG, "pswd %s", pswd);
   
    fota->get_port(&port);
    fota->get_priority(&priority);
    fota->get_channel(&channel);

    esp_netif_ip_info_t info;
    fota->get_server_info(&info);
    ESP_LOGW(TAG, "server ip: " IPSTR, IP2STR(&info.ip));
    ESP_LOGW(TAG, "server gw: " IPSTR, IP2STR(&info.gw));
    ESP_LOGW(TAG, "server netmask: " IPSTR, IP2STR(&info.netmask));

    ESP_LOGI(TAG, "port: %d", port);
    ESP_LOGI(TAG, "priority: %d", priority);
    ESP_LOGI(TAG, "channel: %d", channel);

    while (1)
    {
        if (finished)
            ESP_LOGI(TAG, "HEAP: ACTUAL=%" PRIu32 ", MIN=%" PRIu32, esp_get_free_heap_size(), esp_get_minimum_free_heap_size());
        vTaskDelay(1000/portTICK_PERIOD_MS);
    }
}
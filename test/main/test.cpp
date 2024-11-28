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
    // Get final heap size.
    uint32_t finalHeap, minimalHeap;

    finalHeap = esp_get_free_heap_size();
    minimalHeap = esp_get_minimum_free_heap_size();

    // delete fota;
    // Log heap.
    ESP_LOGI(TAG, "HEAP: FINAL=%" PRIu32 ", MIN=%" PRIu32, finalHeap, minimalHeap);

    finished = true;

    if (rslt == ESP_OK)
    {
        ESP_LOGI(TAG, "FOTA SUCCESS");
    }
    else
    {
        ESP_LOGE(TAG, "FOTA FAILED: %s", esp_err_to_name(rslt));
    }
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

    fota->set_ssid(SERVER_SSID, SERVER_SSID_LEN);
    fota->set_pswd(SERVER_PSWD, SERVER_PSWD_LEN);
    fota->set_port(8000);
    fota->set_priority(5);
    fota->set_channel(1);

    char ssid[30];
    char pswd[30];
    uint16_t port;
    uint8_t priority;
    uint8_t channel;
    if (fota->get_ssid(ssid) == ESP_OK)
        ESP_LOGI(TAG, "ssid %s", ssid);
    
    if (fota->get_pswd(pswd) == ESP_OK)
        ESP_LOGI(TAG, "pswd %s", pswd);
   
    fota->get_port(&port);
    fota->get_priority(&priority);
    fota->get_channel(&channel);

    ESP_LOGI(TAG, "port: %d", port);
    ESP_LOGI(TAG, "priority: %d", priority);
    ESP_LOGI(TAG, "channel: %d", channel);

    fota->on_finished_callback(fotaFinished);

    ESP_ERROR_CHECK(fota->begin());

    // ESP_LOGI(TAG, "HEAP: BEGIN=%" PRIu32 ", MIN=%" PRIu32, esp_get_free_heap_size(), esp_get_minimum_free_heap_size());

    // fota->stop(ESP_OK);

    // ESP_LOGI(TAG, "HEAP: STOP=%" PRIu32 ", MIN=%" PRIu32, esp_get_free_heap_size(), esp_get_minimum_free_heap_size());

    // delete fota;

    // ESP_LOGI(TAG, "HEAP: DELETE=%" PRIu32 ", MIN=%" PRIu32, esp_get_free_heap_size(), esp_get_minimum_free_heap_size());

    while (1)
    {
        if (finished)
            ESP_LOGI(TAG, "HEAP: ACTUAL=%" PRIu32 ", MIN=%" PRIu32, esp_get_free_heap_size(), esp_get_minimum_free_heap_size());
        vTaskDelay(1000/portTICK_PERIOD_MS);
    }
}
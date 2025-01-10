set(COMPONENT_SRCDIRS "source/FOTA")
set(COMPONENT_ADD_INCLUDEDIRS "source")
set(COMPONENT_REQUIRES )
set(COMPONENT_PRIV_REQUIRES app_update esp_http_server esp_netif esp_wifi espressif__esp_encrypted_img)
set(COMPONENT_EMBED_TXTFILES "private.pem")

register_component()

idf_component_register(
    SRCS "key_storage.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES nvs_flash
)

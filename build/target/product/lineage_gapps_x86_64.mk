$(call inherit-product, vendor/lineage/build/target/product/lineage_x86_64.mk)

PRODUCT_NAME := lineage_gapps_x86_64

PRODUCT_USE_DYNAMIC_PARTITIONS := false
PRODUCT_SOONG_NAMESPACES += vendor/gapps/overlay

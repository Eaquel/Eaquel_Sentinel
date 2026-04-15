# Eaquel_Sentinel - Root Makefile (Syntax hatası düzeltildi)
BUILD_DIR := $(CURDIR)/build

include common.mk

OBJ_DIR = \( (BUILD_DIR)/obj/ \)(BUILD_TYPE)
MODULE_OUT = \( (BUILD_DIR)/module/ \)(BUILD_TYPE)
ZIP_DIR = $(BUILD_DIR)/out

ZIP_NAME = Eaquel_Sentinel-\( (VER_NAME)- \)(VER_CODE)-\( (COMMIT_HASH)- \)(BUILD_TYPE).zip
ZIP_FILE = \( (ZIP_DIR)/ \)(ZIP_NAME)

LOADER_DONE = $(OBJ_DIR)/loader/.done
MODULE_DONE = \( (BUILD_DIR)/module- \)(BUILD_TYPE).done

LOADER_INPUTS = common.mk loader/Makefile \
        $(shell find loader/src -type f | sort)

.PHONY: debug release build clean

debug:
	\( (MAKE) BUILD_TYPE=debug BUILD_DIR= \)(BUILD_DIR) build

release:
	\( (MAKE) BUILD_TYPE=release BUILD_DIR= \)(BUILD_DIR) build

build: $(ZIP_FILE)

$(LOADER_DONE): $(LOADER_INPUTS)
	\( (MAKE) -C loader BUILD_TYPE= \)(BUILD_TYPE) BUILD_DIR=$(BUILD_DIR)
	@mkdir -p $(dir $@)
	@touch $@

$(MODULE_DONE): $(LOADER_DONE)
	@rm -rf $(MODULE_OUT)
	@mkdir -p $(MODULE_OUT)/META-INF/com/google/android

	@echo "Copying META-INF files..."
	@cp module/src/META-INF/com/google/android/update-binary \
	   module/src/META-INF/com/google/android/updater-script \
	   $(MODULE_OUT)/META-INF/com/google/android/ 2>/dev/null || true

	@echo "Copying module files..."
	@cp module/src/sepolicy.rule module/src/customize.sh \
	   module/src/post-fs-data.sh module/src/service.sh \
	   module/src/uninstall.sh $(MODULE_OUT)/ 2>/dev/null || true

	@echo "Customizing module.prop..."
	@sed -e 's/\[ {moduleId}/$(MODULE_ID)/g' \
	    -e 's/ \]{moduleName}/$(MODULE_NAME)/g' \
	    -e 's/\[ {versionName}/\( (VER_NAME) ( \)(VER_CODE)-\( (COMMIT_HASH)- \)(BUILD_TYPE))/g' \
	    -e 's/ \]{versionCode}/$(VER_CODE)/g' \
	    module/src/module.prop > $(MODULE_OUT)/module.prop 2>/dev/null || true

	@echo "Copying binaries..."
	@for arch in $(ARCHS); do \
		mkdir -p $(MODULE_OUT)/lib/\[ arch; \
		cp $(OBJ_DIR)/loader/ \]arch/stripped/libzygisk.so \
		   $(MODULE_OUT)/lib/$$arch/libzygisk.so 2>/dev/null || true; \
	done

	@echo "Skipping module signing for Eaquel_Sentinel"

	@mkdir -p $(ZIP_DIR)
	@cd $(MODULE_OUT) && zip -r9 $(ZIP_FILE) . -x '*.DS_Store' > /dev/null || true

	@echo "Eaquel_Sentinel build completed: $(ZIP_NAME)"

clean:
	rm -rf $(BUILD_DIR)
	\( (MAKE) -C loader clean BUILD_DIR= \)(BUILD_DIR) 2>/dev/null || true
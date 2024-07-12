/*
 * PS Vita RE-Savedata
 * Copyright (C) 2022, Princess of Sleeping
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/fios2.h>
#include <taihen.h>

#define taiHookImportKernel(module_name, library_nid, func_nid, func_name) taiHookFunctionImportForKernel(KERNEL_PID, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patch)
#define taiHookOffsetKernel(modid, seg_index, thumb, offset, func_name) taiHookFunctionOffsetForKernel(KERNEL_PID, &func_name ## _ref, modid, seg_index, offset, thumb, func_name ## _patch);

#define RE_SAVEDATA_PATH "ux0:reSavedata"
#define ACCESS_MODE 0666

static const char sdSlotMagic[] = {
	'S', 'D', 'S', 'L',
	0x0, 0x0, 0x0, 0x0,
	0x0, 0x1, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0
};

static int writeFile(const char *path, const void *data, size_t size)
{
	SceUID fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, ACCESS_MODE);
	if(fd < 0)
		return fd;

	ksceIoWrite(fd, data, size);
	ksceIoClose(fd);
	return 0;
}

static SceUID sceAppMgrInitSafemem_hook;
static tai_hook_ref_t sceAppMgrInitSafemem_ref;
static int sceAppMgrInitSafemem_patch(SceUID pid, int a2, const char *savedata0_sce_sys_path, char *a4, SceSize safemem_size)
{
	void *mem_base = NULL; SceIoStat stat;
	char path[0x100], titleid[0x20], process_path_savedata0[0x20];

	ksceKernelSysrootGetProcessTitleId(pid, titleid, sizeof(titleid));
	if(strncmp(titleid, "NPXS", 4) == 0)
		goto tai_continue;

	snprintf(path, sizeof(path), "%s/%s", savedata0_sce_sys_path, "safemem.dat");
	if(ksceIoGetstat(path, &stat) < 0)
	{
		SceUID memid = ksceKernelAllocMemBlock("ReSdSlot", SCE_KERNEL_MEMBLOCK_TYPE_RW_UNK0, safemem_size, NULL);
		ksceKernelGetMemBlockBase(memid, &mem_base);
		writeFile(path, mem_base, safemem_size);
		ksceKernelFreeMemBlock(memid);
	}
 
	memset(process_path_savedata0, 0, sizeof(process_path_savedata0));
	ksceFiosKernelOverlayResolveSync(pid, 1, "savedata0:", process_path_savedata0, sizeof(process_path_savedata0));
	if(strncmp(process_path_savedata0, "savedata0:", 10) == 0)
		goto tai_continue;

	snprintf(path, sizeof(path), "%s/", RE_SAVEDATA_PATH);
	if(ksceIoGetstat(path, &stat) < 0)
		ksceIoMkdir(path, ACCESS_MODE);

	snprintf(path, sizeof(path), "%s/%s/", RE_SAVEDATA_PATH, titleid);
	if(ksceIoGetstat(path, &stat) < 0)
		ksceIoMkdir(path, ACCESS_MODE);

	snprintf(path, sizeof(path), "%s/%s/sce_sys/", RE_SAVEDATA_PATH, titleid);
	if(ksceIoGetstat(path, &stat) < 0)
		ksceIoMkdir(path, ACCESS_MODE);

	snprintf(path, sizeof(path), "%s/%s/sce_sys/%s", RE_SAVEDATA_PATH, titleid, "safemem.dat");
	if(ksceIoGetstat(path, &stat) < 0)
	{
		SceUID memid = ksceKernelAllocMemBlock("ReSafemem", SCE_KERNEL_MEMBLOCK_TYPE_RW_UNK0, safemem_size, NULL);
		ksceKernelGetMemBlockBase(memid, &mem_base);
		writeFile(path, mem_base, safemem_size);
		ksceKernelFreeMemBlock(memid);
	}

	snprintf(path, sizeof(path), "%s/%s/sce_sys/%s", RE_SAVEDATA_PATH, titleid, "sdslot.dat");
	if(ksceIoGetstat(path, &stat) < 0)
	{
		SceUID memid = ksceKernelAllocMemBlock("ReSdSlot", SCE_KERNEL_MEMBLOCK_TYPE_RW_UNK0, 0x50000, NULL);
		ksceKernelGetMemBlockBase(memid, &mem_base);
		memcpy(mem_base, sdSlotMagic, 16);
		writeFile(path, mem_base, 0x40400);
		ksceKernelFreeMemBlock(memid);
	}

tai_continue:
	return TAI_CONTINUE(int, sceAppMgrInitSafemem_ref, pid, a2, savedata0_sce_sys_path, a4, safemem_size);
}

static SceUID ksceFiosKernelOverlayAddForProcess_hook;
static tai_hook_ref_t ksceFiosKernelOverlayAddForProcess_ref;
static int ksceFiosKernelOverlayAddForProcess_patch(SceUID pid, SceFiosOverlay *overlay, SceFiosOverlayID *outID)
{
	if(strcmp(overlay->dst, "savedata0:") != 0)
		goto tai_continue;

	char titleid[0x20];
	ksceKernelSysrootGetProcessTitleId(pid, titleid, sizeof(titleid));
	if(strcmp(titleid, "main") == 0 || strncmp(titleid, "NPXS", 4) == 0)
		goto tai_continue;

	SceFiosOverlay locOverlay;
	memcpy(&locOverlay, overlay, sizeof(locOverlay));
	snprintf(locOverlay.src, sizeof(locOverlay.src), "%s/%s/", RE_SAVEDATA_PATH, titleid);
	overlay = &locOverlay;

tai_continue:	
	return TAI_CONTINUE(int, ksceFiosKernelOverlayAddForProcess_ref, pid, overlay, outID);
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
	tai_module_info_t info; info.size = sizeof(info);
	if(taiGetModuleInfoForKernel(KERNEL_PID, "SceAppMgr", &info) < 0)
		return SCE_KERNEL_START_FAILED;

	switch(info.module_nid)
	{
	case 0x94CEFE4B: // 3.55 retail
	case 0xDFBC288C: // 3.57 retail
		sceAppMgrInitSafemem_hook = taiHookOffsetKernel(info.modid, 0, 1, 0x2DF9C, sceAppMgrInitSafemem);
		break;
	case 0xDBB29DB7: // 3.60 retail
	case 0xB5F8EA7C: // 3.61 retail
		sceAppMgrInitSafemem_hook = taiHookOffsetKernel(info.modid, 0, 1, 0x2E0C4, sceAppMgrInitSafemem);
		break;
	case 0x23B967C5: // 3.63 retail
	case 0x1C9879D6: // 3.65 retail
		sceAppMgrInitSafemem_hook = taiHookOffsetKernel(info.modid, 0, 1, 0x2E0AC, sceAppMgrInitSafemem);
		break;
	case 0x54E2E984: // 3.67 retail
	case 0xC3C538DE: // 3.68 retail
		sceAppMgrInitSafemem_hook = taiHookOffsetKernel(info.modid, 0, 1, 0x2E0BC, sceAppMgrInitSafemem);
		break;
	case 0x321E4852: // 3.69 retail
	case 0x700DA0CD: // 3.70 retail
	case 0xF7846B4E: // 3.71 retail
	case 0xA8E80BA8: // 3.72 retail
	case 0xB299D195: // 3.73 retail
	case 0x30007BD3: // 3.74 retail
		sceAppMgrInitSafemem_hook = taiHookOffsetKernel(info.modid, 0, 1, 0x2E0E4, sceAppMgrInitSafemem);
		break;
	default:
		return SCE_KERNEL_START_FAILED;
		break;
	}

	if (sceAppMgrInitSafemem_hook < 0)
		return SCE_KERNEL_START_FAILED;

	ksceFiosKernelOverlayAddForProcess_hook = taiHookImportKernel("SceAppMgr", 0x54D6B9EB, 0x17E65A1C, ksceFiosKernelOverlayAddForProcess);
	if (ksceFiosKernelOverlayAddForProcess_hook < 0)
		return SCE_KERNEL_START_FAILED;

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	taiHookReleaseForKernel(ksceFiosKernelOverlayAddForProcess_hook, ksceFiosKernelOverlayAddForProcess_ref);
	taiHookReleaseForKernel(sceAppMgrInitSafemem_hook, sceAppMgrInitSafemem_ref);
	return SCE_KERNEL_STOP_SUCCESS;
}
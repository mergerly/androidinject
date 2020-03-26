//
// Created by Rose on 2020/2/18.
//

#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <elf.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include "PtraceInject.h"
#include "PrintLog.h"

#define  MAX_PATH 0x100
#define CPSR_T_MASK     ( 1u << 5 )
#define REMOTE_ADDR(addr, local_base, remote_base) ( (uint32_t)(addr) + (uint32_t)(remote_base) - (uint32_t)(local_base) )

#if defined(__aarch64__)
#define pt_regs         user_pt_regs
#define uregs    regs
#define ARM_pc    pc
#define ARM_sp    sp
#define ARM_cpsr    pstate
#define ARM_lr        regs[30]
#define ARM_r0        regs[0]
#define PTRACE_GETREGS PTRACE_GETREGSET
#define PTRACE_SETREGS PTRACE_SETREGSET
#elif defined(__x86_64__)
#define pt_regs user_regs_struct
#define eax     rax
#define esp     rsp
#define eip     rip
#endif

#if defined(__aarch64__) || defined(__x86_64__)
const char *libc_path = "/system/lib64/libc.so";
const char *linker_path = "/system/bin/linker64";
const char *libdl_path = "/system/lib64/libdl.so";
#else
const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";
const char *libdl_path = "/system/lib/libdl.so";
#endif

/***************************
 *  Description:    使用ptrace Attach附加到指定进程,发送SIGSTOP信号给指定进程让其停止下来并对其进行跟踪。
 *                  但是被跟踪进程(tracee)不一定会停下来，因为同时attach和传递SIGSTOP可能会将SIGSTOP丢失。
 *                  所以需要waitpid(2)等待被跟踪进程被停下
 *  Input:          pid表示远程进程的ID
 *  Output:         无
 *  Return:         返回0表示attach成功，返回-1表示失败
 *  Others:         无
 * ************************/
int ptrace_attach(pid_t pid) {
    int status = 0;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        LOGE("ptrace attach process error, pid:%d, err:%s", pid, strerror(errno));
        return -1;
    }

    LOGD("attach porcess success, pid:%d", pid);
    waitpid(pid, &status, WUNTRACED);

    return 0;
}

/*************************************************
 *   Description:    使用ptrace detach指定进程,完成对指定进程的跟踪操作后，使用该参数即可解除附加
 *   Input:          pid表示远程进程的ID
 *   Output:         无
 *   Return:         返回0表示detach成功，返回-1表示失败
 *   Others:         无
 * ***********************************************/
int ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        LOGE("detach process error, pid:%d, err:%s", pid, strerror(errno));
        return -1;
    }

    LOGD("detach process success, pid:%d", pid);
    return 0;
}

/*************************************************
 *  Description:    ptrace使远程进程继续运行
 *  Input:          pid表示远程进程的ID
 *  Output:         无
 *  Return:         返回0表示continue成功，返回-1表示失败
 *  Others:         无
 * ***********************************************/
int ptrace_continue(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        LOGE("ptrace continue process error, pid:%d, err:%ss", pid, strerror(errno));
        return -1;
    }

    LOGD("ptrace continue process success, pid:%d", pid);
    return 0;
}

/*************************************************
 *  Description:    使用ptrace获取远程进程的寄存器值
 *  Input:          pid表示远程进程的ID，regs为pt_regs结构，存储了寄存器值
 *  Output:         无
 *  Return:         返回0表示获取寄存器成功，返回-1表示失败
 *  Others:         无
 * ***********************************************/
int ptrace_getregs(pid_t pid, struct pt_regs *regs) {
#if defined(__aarch64__)
    int regset = NT_PRSTATUS;
    struct iovec ioVec;

    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *) regset, &ioVec) < 0) {
        LOGE("ptrace_getregs: Can not get register values, io %llx, %d", ioVec.iov_base,
             ioVec.iov_len);
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        LOGD("Get Regs error, pid:%d, err:%s", pid, strerror(errno));
        return -1;
    }
#endif
    return 0;
}

/*************************************************
 *  Description:    使用ptrace设置远程进程的寄存器值
 *  Input:          pid表示远程进程的ID，regs为pt_regs结构，存储需要修改的寄存器值
 *  Output:         无
 *  Return:         返回0表示设置寄存器成功，返回-1表示失败
 * ***********************************************/
int ptrace_setregs(pid_t pid, struct pt_regs *regs) {
#if defined(__aarch64__)
    int regset = NT_PRSTATUS;
    struct iovec ioVec;

    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *) regset, &ioVec) < 0) {
        perror("ptrace_setregs: Can not get register values");
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        LOGD("Set Regs error, pid:%d, err:%s", pid, strerror(errno));
        return -1;
    }
#endif
    return 0;
}


/*************************************************
 *  Description:    获取返回值，ARM处理器中返回值存放在ARM_r0寄存器中
 *  Input:          regs存储远程进程当前的寄存器值
 *  Return:         在ARM处理器下返回r0寄存器值
 * ***********************************************/
long ptrace_getret(struct pt_regs *regs) {
#if defined(__i386__) || defined(__x86_64__)
    return regs->eax;
#elif defined(__arm__) || defined(__aarch64__)
    return regs->ARM_r0;
#else
    LOGD("Not supported Environment %s", __FUNCTION__);
#endif
}

/*************************************************
 *  Description:    获取当前执行代码的地址，ARM处理器下存放在ARM_pc中
 *  Input:          regs存储远程进程当前的寄存器值
 *  Return:         在ARM处理器下返回pc寄存器值
 * **********************************************/
long ptrace_getpc(struct pt_regs *regs) {
#if defined(__i386__) || defined(__x86_64__)
    return regs->eip;
#elif defined(__arm__) || defined(__aarch64__)
    return regs->ARM_pc;
#else
    LOGD("Not supported Environment %s", __FUNCTION__);
#endif
}

/*************************************************
 *   Description:    使用ptrace从远程进程内存中读取数据
 *   Input:          pid表示远程进程的ID，pSrcBuf表示从远程进程读取数据的内存地址
 *                   pDestBuf表示用于存储读取出数据的地址，size表示读取数据的大小
 *   Return:         返回0表示读取数据成功
 *   other:          这里的*_t类型是typedef定义一些基本类型的别名，用于跨平台。例如
 *                   uint8_t表示无符号8位也就是无符号的char类型
 * **********************************************/
int ptrace_readdata(pid_t pid, uint8_t *pSrcBuf, uint8_t *pDestBuf, size_t size) {
    long nReadCount = 0;
    long nRemainCount = 0;
    uint8_t *pCurSrcBuf = pSrcBuf;
    uint8_t *pCurDestBuf = pDestBuf;
    long lTmpBuf = 0;
    long i = 0;

    nReadCount = size / sizeof(long);
    nRemainCount = size % sizeof(long);

    for (i = 0; i < nReadCount; i++) {
        lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurSrcBuf, 0);
        memcpy(pCurDestBuf, (char *) (&lTmpBuf), sizeof(long));
        pCurSrcBuf += sizeof(long);
        pCurDestBuf += sizeof(long);
    }

    if (nRemainCount > 0) {
        lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurSrcBuf, 0);
        memcpy(pCurDestBuf, (char *) (&lTmpBuf), nRemainCount);
    }

    return 0;
}

/*************************************************
 *  Description:    使用ptrace将数据写入到远程进程空间中
 *  Input:          pid表示远程进程的ID，pWriteAddr表示写入数据到远程进程的内存地址
 *                  pWriteData用于存储写入数据的地址，size表示写入数据的大小
 *  Return:         返回0表示写入数据成功，返回-1表示写入数据失败
 * ***********************************************/
int ptrace_writedata(pid_t pid, uint8_t *pWriteAddr, uint8_t *pWriteData,
                     size_t size) {

    long nWriteCount = 0;
    long nRemainCount = 0;
    uint8_t *pCurSrcBuf = pWriteData;
    uint8_t *pCurDestBuf = pWriteAddr;
    long lTmpBuf = 0;
    long i = 0;

    nWriteCount = size / sizeof(long);
    nRemainCount = size % sizeof(long);

    // 先讲数据以sizeof(long)字节大小为单位写入到远程进程内存空间中
    for (i = 0; i < nWriteCount; i++) {
        memcpy((void *) (&lTmpBuf), pCurSrcBuf, sizeof(long));
        if (ptrace(PTRACE_POKETEXT, pid, (void *) pCurDestBuf, (void *) lTmpBuf) <
            0)  // PTRACE_POKETEXT表示从远程内存空间写入一个sizeof(long)大小的数据
        {
            LOGD("Write Remote Memory error, MemoryAddr:0x%lx, err:%s", (uintptr_t) pCurDestBuf,
                 strerror(errno));
            return -1;
        }
        pCurSrcBuf += sizeof(long);
        pCurDestBuf += sizeof(long);
    }

    // 将剩下的数据写入到远程进程内存空间中
    if (nRemainCount > 0) {
        lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurDestBuf,
                         NULL); //先取出原内存中的数据，然后将要写入的数据以单字节形式填充到低字节处
        memcpy((void *) (&lTmpBuf), pCurSrcBuf, nRemainCount);
        if (ptrace(PTRACE_POKETEXT, pid, pCurDestBuf, lTmpBuf) < 0) {
            LOGD("Write Remote Memory error, MemoryAddr:0x%lx, err:%s", (uintptr_t) pCurDestBuf,
                 strerror(errno));
            return -1;
        }
    }

    return 0;
}

/*************************************************
 *  Description:    使用ptrace远程call函数
 *  Input:          pid表示远程进程的ID，ExecuteAddr为远程进程函数的地址
 *                  parameters为函数参数的地址，regs为远程进程call函数前的寄存器环境
 *  Return:         返回0表示call函数成功，返回-1表示失败
 * **********************************************/
int ptrace_call(pid_t pid, uintptr_t ExecuteAddr, long *parameters, long num_params,
                struct pt_regs *regs) {
#if defined(__i386__)
    // 写入参数到堆栈
    regs->esp -= (num_params) * sizeof(long); // 分配栈空间，栈的方向是从高地址到低地址
    if (0 != ptrace_writedata(pid, (uint8_t *) regs->esp, (uint8_t *) parameters,
                              (num_params) * sizeof(long))) {
        return -1;
    }

    long tmp_addr = 0x0;
    regs->esp -= sizeof(long);
    if (0 !=
        ptrace_writedata(pid, (uint8_t *) regs->esp, (uint8_t *) &tmp_addr, sizeof(tmp_addr))) {
        return -1;
    }

    //设置eip寄存器为需要调用的函数地址
    regs->eip = ExecuteAddr;

    // 开始执行
    if (-1 == ptrace_setregs(pid, regs) || -1 == ptrace_continue(pid)) {
        LOGE("ptrace set regs or continue error, pid:%d", pid);
        return -1;
    }

    int stat = 0;
    // 对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。
    // 参数WUNTRACED表示当进程进入暂停状态后，立即返回
    waitpid(pid, &stat, WUNTRACED);

    // 判断是否成功执行函数
    LOGI("ptrace call ret status is %d\n", stat);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            LOGE("ptrace call error");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    // 获取远程进程的寄存器值，方便获取返回值
    if (ptrace_getregs(pid, regs) == -1) {
        LOGD("After call getregs error");
        return -1;
    }
#elif defined(__x86_64__)
    int num_param_registers = 6;
    // x64处理器，函数传递参数，将整数和指针参数前6个参数从左到右保存在寄存器rdi,rsi,rdx,rcx,r8和r9
    // 更多的参数则按照从右到左的顺序依次压入堆栈。
    if (num_params > 0) regs->rdi = parameters[0];
    if (num_params > 1) regs->rsi = parameters[1];
    if (num_params > 2) regs->rdx = parameters[2];
    if (num_params > 3) regs->rcx = parameters[3];
    if (num_params > 4) regs->r8 = parameters[4];
    if (num_params > 5) regs->r9 = parameters[5];

    if (num_param_registers < num_params) {
        regs->esp -= (num_params - num_param_registers) * sizeof(long);    // 分配栈空间，栈的方向是从高地址到低地址
        if (0 != ptrace_writedata(pid, (uint8_t *) regs->esp,
                                  (uint8_t *) &parameters[num_param_registers],
                                  (num_params - num_param_registers) * sizeof(long))) {
            return -1;
        }
    }

    long tmp_addr = 0x0;
    regs->esp -= sizeof(long);
    if (0 !=
        ptrace_writedata(pid, (uint8_t *) regs->esp, (uint8_t *) &tmp_addr, sizeof(tmp_addr))) {
        return -1;
    }

    //设置eip寄存器为需要调用的函数地址
    regs->eip = ExecuteAddr;

    // 开始执行
    if (-1 == ptrace_setregs(pid, regs) || -1 == ptrace_continue(pid)) {
        LOGE("ptrace set regs or continue error, pid:%d", pid);
        return -1;
    }

    int stat = 0;
    // 对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。
    // 参数WUNTRACED表示当进程进入暂停状态后，立即返回
    waitpid(pid, &stat, WUNTRACED);

    // 判断是否成功执行函数
    LOGI("ptrace call ret status is %lX\n", stat);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            LOGE("ptrace call error");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

#elif defined(__arm__) || defined(__aarch64__)
#if defined(__arm__)
    int num_param_registers = 4;
#elif defined(__aarch64__)
    int num_param_registers = 8;
#endif
    int i = 0;
    // ARM处理器，函数传递参数，将前四个参数放到r0-r3，剩下的参数压入栈中
    for (i = 0; i < num_params && i < num_param_registers; i++) {
        regs->uregs[i] = parameters[i];
    }

    if (i < num_params) {
        regs->ARM_sp -= (num_params - i) * sizeof(long);    // 分配栈空间，栈的方向是从高地址到低地址
        if (ptrace_writedata(pid, (uint8_t *) (regs->ARM_sp), (uint8_t *) &parameters[i],
                             (num_params - i) * sizeof(long)) == -1)
            return -1;
    }

    regs->ARM_pc = ExecuteAddr;           //设置ARM_pc寄存器为需要调用的函数地址
    // 与BX跳转指令类似，判断跳转的地址位[0]是否为1，如果为1，则将CPST寄存器的标志T置位，解释为Thumb代码
    // 若为0，则将CPSR寄存器的标志T复位，解释为ARM代码
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;

    // Android 7.0以上修正lr为libc.so的起始地址 getprop获取ro.build.version.sdk
    long lr_val = 0;
    char sdk_ver[32];
    memset(sdk_ver, 0, sizeof(sdk_ver));
    __system_property_get("ro.build.version.sdk", sdk_ver);
//    LOGD("ro.build.version.sdk: %s", sdk_ver);
    if (atoi(sdk_ver) <= 23) {
        lr_val = 0;
    } else { // Android 7.0
        static long start_ptr = 0;
        if (start_ptr == 0) {
            start_ptr = (long)get_module_base_addr(pid, libc_path);
        }
        lr_val = start_ptr;
    }
    regs->ARM_lr = lr_val;

    if (ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1) {
        LOGD("ptrace set regs or continue error, pid:%d", pid);
        return -1;
    }

    int stat = 0;
    // 对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。
    // 参数WUNTRACED表示当进程进入暂停状态后，立即返回
    // 将ARM_lr（存放返回地址）设置为0，会导致子进程执行发生错误，则子进程进入暂停状态
    waitpid(pid, &stat, WUNTRACED);

    // 判断是否成功执行函数
    LOGD("ptrace call ret status is %d\n", stat);
    while ((stat & 0xFF) != 0x7f) {
        if (ptrace_continue(pid) == -1) {
            LOGD("ptrace call error");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    // 获取远程进程的寄存器值，方便获取返回值
    if (ptrace_getregs(pid, regs) == -1) {
        LOGD("After call getregs error");
        return -1;
    }
#else
    LOGD("Not supported Environment %s", __FUNCTION__);
#endif
    return 0;
}

/*************************************************
  Description:    通过进程名称定位到进程的PID
  Input:          process_name为要定位的进程名称
  Output:         无
  Return:         返回定位到的进程PID，若为-1，表示定位失败
  Others:         无
*************************************************/
pid_t find_pid_by_name(const char *process_name) {
    int dirid = 0;
    pid_t pid = -1;
    FILE *fp = NULL;
    char filename[MAX_PATH] = {0};
    char cmdline[MAX_PATH] = {0};

    struct dirent *entry = NULL;

    if (process_name == NULL)
        return -1;

    DIR *dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    while ((entry = readdir(dir)) != NULL) {
        dirid = atoi(entry->d_name);
        if (dirid != 0) {
            snprintf(filename, MAX_PATH, "/proc/%d/cmdline", dirid);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strncmp(process_name, cmdline, strlen(process_name)) == 0) {
                    pid = dirid;
                    LOGI("find cmdline: %s", cmdline);
                    break;
                }
            }
        }
    }

    closedir(dir);
    return pid;
}

/*************************************************
 *  Description:    在指定进程中搜索对应模块的基址
 *  Input:          pid表示远程进程的ID，若为-1表示自身进程，ModuleName表示要搜索的模块的名称
 *  Return:         返回0表示获取模块基址失败，返回非0为要搜索的模块基址
 * **********************************************/
void *get_module_base_addr(pid_t pid, const char *ModuleName) {
    FILE *fp = NULL;
    long ModuleBaseAddr = 0;
    char *ModulePath, *MapFileLineItem;
    char szFileName[50] = {0};
    char szMapFileLine[1024] = {0};
    char szProcessInfo[1024] = {0};

    // 读取"/proc/pid/maps"可以获得该进程加载的模块
    if (pid < 0) {
        //  枚举自身进程模块
        snprintf(szFileName, sizeof(szFileName), "/proc/self/maps");
    } else {
        snprintf(szFileName, sizeof(szFileName), "/proc/%d/maps", pid);
    }

    fp = fopen(szFileName, "r");

    if (fp != NULL) {
        while (fgets(szMapFileLine, sizeof(szMapFileLine), fp)) {
            if (strstr(szMapFileLine, ModuleName)) {
                MapFileLineItem = strtok(szMapFileLine, " \t"); // 基址信息
                char *Addr = strtok(szMapFileLine, "-");
                ModuleBaseAddr = strtoul(Addr, NULL, 16);

                if (ModuleBaseAddr == 0x8000)
                    ModuleBaseAddr = 0;

                break;
            }
        }

        fclose(fp);
    }

    return (void *) ModuleBaseAddr;
}

/*************************************************
 *  Description:    获取远程进程与本进程都加载的模块中函数的地址
 *  Input:          pid表示远程进程的ID，ModuleName表示模块名称，LocalFuncAddr表示本地进程中该函数的地址
 *  Return:         返回远程进程中对应函数的地址
 * ***********************************************/
void *get_remote_func_addr(pid_t pid, const char *ModuleName, void *LocalFuncAddr) {
    void *LocalModuleAddr, *RemoteModuleAddr, *RemoteFuncAddr;

    LocalModuleAddr = get_module_base_addr(-1, ModuleName);
    RemoteModuleAddr = get_module_base_addr(pid, ModuleName);

    RemoteFuncAddr = (void *) ((uintptr_t) LocalFuncAddr - (uintptr_t) LocalModuleAddr +
                               (uintptr_t) RemoteModuleAddr);

    LOGI("[get_remote_func_addr] lmod=0x%lX, rmod=0x%lX, lfunc=0x%lX, rfunc=0x%lX",
         LocalModuleAddr, RemoteModuleAddr, LocalFuncAddr, RemoteFuncAddr);
    return RemoteFuncAddr;
}

void dump_registers(struct pt_regs *regs) {
#if defined(__i386__)
    LOGD("X86 eax:%08x, ebx:%08x, ecx:%08x, edx:%08x, esi:%08x, edi:%08x, ebp:%08x, xds:%08x, xes:%08x, xfs:%08x, xgs:%08x, orig_eax:%08x, eip:%08x, xcs:%08x, eflags:%08x, esp:%08x, xss:%08x,",
         regs->eax, regs->ebx, regs->ecx, regs->edx, regs->esi, regs->edi, regs->ebp, regs->xds,
         regs->xes, regs->xfs, regs->xgs, regs->orig_eax, regs->eip, regs->xcs, regs->eflags,
         regs->esp, regs->xss);
#elif defined(__arm__)
    LOGD("ARM_r0:0x%08X, ARM_r1:0x%08X, ARM_r2:0x%08X, ARM_r3:0x%08X, ARM_r4:0x%08X, ARM_r5:0x%08X, ARM_r6:0x%08X, ARM_r7:0x%08X, ARM_r8:0x%08X, ARM_r9:0x%08X, ARM_r10:0x%08X, ARM_fp:0x%08X, ARM_ip:0x%08X, ARM_sp:0x%08X, ARM_lr:0x%08X, ARM_pc:0x%08X, ARM_cpsr:0x%08X, ARM_ORIG_r0:0x%08X",
         regs->ARM_r0 ,regs->ARM_r1 ,regs->ARM_r2 ,regs->ARM_r3 ,regs->ARM_r4 ,regs->ARM_r5 ,regs->ARM_r6 ,regs->ARM_r7 ,regs->ARM_r8 ,regs->ARM_r9 ,regs->ARM_r10 ,regs->ARM_fp ,regs->ARM_ip ,regs->ARM_sp ,regs->ARM_lr ,regs->ARM_pc ,regs->ARM_cpsr ,regs->ARM_ORIG_r0);
#elif defined(__aarch64__)
    LOGD("x0:%016lx, x1:%016lx, x2:%016lx, x3:%016lx, x4:%016lx, x5:%016lx, x6:%016lx, x7:%016lx, x8:%016lx, x9:%016lx, x10:%016lx, x11:%016lx, x12:%016lx, x13:%016lx, x14:%016lx, x15:%016lx, x16:%016lx, x17:%016lx, x18:%016lx, x19:%016lx, x20:%016lx, x21:%016lx, x22:%016lx, x23:%016lx, x24:%016lx, x25:%016lx, x26:%016lx, x27:%016lx, x28:%016lx, x29:%016lx, x30:%016lx, sp:%016lx, pc:%016lx, pstate:%016lx",
         regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3], regs->regs[4], regs->regs[5],
         regs->regs[6], regs->regs[7], regs->regs[8], regs->regs[9], regs->regs[10], regs->regs[11],
         regs->regs[12], regs->regs[13], regs->regs[14], regs->regs[15], regs->regs[16],
         regs->regs[17], regs->regs[18], regs->regs[19], regs->regs[20], regs->regs[21],
         regs->regs[22], regs->regs[23], regs->regs[24], regs->regs[25], regs->regs[26],
         regs->regs[27], regs->regs[28], regs->regs[29], regs->regs[30], regs->sp, regs->pc,
         regs->pstate);
#elif defined(__x86_64__)
    LOGD("rax:0x%lX, rbx:0x%lX, rcx:0x%lX, rdx:0x%lX, rbp:0x%lX, rdi:0x%lX, rip:0x%lX, rsi:0x%lX, rsp:0x%lX, ss:0x%lX, cs:0x%lX, eflags:0x%lX, orig_rax:0x%lX, r8:0x%lX, r9:0x%lX, r10:0x%lX, r11:0x%lX, r12:0x%lX, r13:0x%lX, r14:0x%lX, r15:0x%lX",
         regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rbp, regs->rdi, regs->rip, regs->rsi,
         regs->rsp, regs->ss, regs->cs, regs->eflags, regs->orig_rax, regs->r8, regs->r9, regs->r10,
         regs->r11, regs->r12, regs->r13, regs->r14, regs->r15);
#else
    LOGD("Not supported Environment %s", __FUNCTION__);
#endif
}

long freespaceaddr(pid_t pid) {
    FILE *fp;
    char filename[50];
    char line[850];
    long addr;
    char str[20];
    char perms[5];
    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if (fp == NULL) {
        LOGE("open file %s failed, err:%s", filename, strerror(errno));
        exit(1);
    }

    while (fgets(line, 850, fp) != NULL) {
        sscanf(line, "%lx-%*lx %s %*s %s %*d", &addr, perms, str);

        if (strstr(perms, "x") != NULL) {
            break;
        }
    }
    fclose(fp);
    return addr;
}

#define INTEL_RET_INSTRUCTION 0xc3
#define INTEL_INT3_INSTRUCTION 0xcc

unsigned char *findRet(void *endAddr) {
    unsigned char *retInstAddr = (unsigned char *) endAddr;
    while (*retInstAddr != INTEL_RET_INSTRUCTION) {
        retInstAddr--;
    }
    return retInstAddr;
}

/*************************************************
 *  通过远程直接调用dlopen\dlsym的方法ptrace注入so模块到远程进程中
 *  Input:          pid表示远程进程的ID，LibPath为被远程注入的so模块路径，FunctionName为远程注入的模块后调用的函数
 *                  FuncParameter指向被远程调用函数的参数（若传递字符串，需要先将字符串写入到远程进程空间中），NumParameter为参数的个数
 *  Return:         返回0表示注入成功，返回-1表示失败
 * ***********************************************/
int inject_remote_process(pid_t pid, char *LibPath, char *FunctionName,
                          long *FuncParameter, long NumParameter) {
    int iRet = -1;
    long parameters[6];

    if (ptrace_attach(pid) != 0) {
        return iRet;
    }

    do {
        struct pt_regs CurrentRegs, OriginalRegs;

        if (ptrace_getregs(pid, &CurrentRegs) != 0) {
            break;
        }
        dump_registers(&CurrentRegs);

        memcpy(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs));

#if defined(__x86_64__)

        LOGD("__x86_64__ run %d ", pid);

        long addr = freespaceaddr(pid) + sizeof(long);

        LOGD("freespaceaddr is %lx  ", addr);
//        memset(&CurrentRegs, 0, sizeof(CurrentRegs));
        CurrentRegs.rip = addr + 2;

        CurrentRegs.rdi = (long)get_remote_func_addr(pid, libc_path, (void *) malloc);
        CurrentRegs.rsi =  (long)get_remote_func_addr(pid, libc_path, (void *) free);
        CurrentRegs.rdx = (long)get_remote_func_addr(pid, libc_path, (void *) dlopen);
        CurrentRegs.rcx = strlen(LibPath) + 1;

        ptrace_setregs(pid, &CurrentRegs);
        if (ptrace_getregs(pid, &CurrentRegs) != 0) {
            break;
        }
        dump_registers(&CurrentRegs);


        size_t injectSharedLibrary_size = (intptr_t)injectSharedLibrary_end - (intptr_t)injectSharedLibrary;
        intptr_t injectSharedLibrary_ret = (intptr_t)findRet((void*)injectSharedLibrary_end) - (intptr_t)injectSharedLibrary;

        char* backup = (char*)malloc(injectSharedLibrary_size * sizeof(char));
        ptrace_readdata(pid, (uint8_t *)addr, (uint8_t *)backup, injectSharedLibrary_size);
        char* newcode = (char*)malloc(injectSharedLibrary_size * sizeof(char));
        memset(newcode, 0, injectSharedLibrary_size * sizeof(char));

        memcpy(newcode, (const void*)injectSharedLibrary, injectSharedLibrary_size - 1);
        newcode[injectSharedLibrary_ret] = INTEL_INT3_INSTRUCTION;

        if(-1 == ptrace_writedata(pid, (uint8_t *)addr, (uint8_t *)newcode, injectSharedLibrary_size))
        {
            LOGE("Write shell code to RemoteProcess error: %s", strerror(errno));
            break;
        }
        ptrace_continue(pid);

        if (ptrace_getregs(pid, &CurrentRegs) != 0) {
            break;
        }
        dump_registers(&CurrentRegs);
        // 获取mmap函数执行后的返回值，也就是内存映射的起始地址
        void *RemoteMapMemoryAddr = (void *) ptrace_getret(&CurrentRegs);
        LOGD("Remote Process Map Memory Addr:0x%lx", (uintptr_t) RemoteMapMemoryAddr);
        dump_registers(&CurrentRegs);
#else
        void *mmap_addr = get_remote_func_addr(pid, libc_path, (void *) mmap);
        LOGD("mmap RemoteFuncAddr:0x%lx", (uintptr_t) mmap_addr);

        // mmap映射
        parameters[0] = 0;  // 设置为NULL表示让系统自动选择分配内存的地址
        parameters[1] = 0x1000; // 映射内存的大小
        parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // 表示映射内存区域可读可写可执行
        parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // 建立匿名映射
        parameters[4] = 0; //  若需要映射文件到内存中，则为文件的fd
        parameters[5] = 0; //文件映射偏移量

        if (ptrace_call(pid, (uintptr_t) mmap_addr, parameters, 6, &CurrentRegs) == -1) {
            LOGD("Call Remote mmap Func Failed, err:%s", strerror(errno));
            break;
        }

        LOGI("ptrace_call mmap success, return value=%lX, pc=%lX", ptrace_getret(&CurrentRegs),
             ptrace_getpc(&CurrentRegs));
        dump_registers(&CurrentRegs);

        // 获取mmap函数执行后的返回值，也就是内存映射的起始地址
        void *RemoteMapMemoryAddr = (void *) ptrace_getret(&CurrentRegs);
        LOGD("Remote Process Map Memory Addr:0x%lx", (uintptr_t) RemoteMapMemoryAddr);
#endif
        // 分别获取dlopen、dlsym、dlclose等函数的地址
        void *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
        char sdk_ver[32];
        memset(sdk_ver, 0, sizeof(sdk_ver));
        __system_property_get("ro.build.version.sdk", sdk_ver);
        if (atoi(sdk_ver) <= 23) {
            dlopen_addr = get_remote_func_addr(pid, linker_path, (void *) dlopen);
            dlsym_addr = get_remote_func_addr(pid, linker_path, (void *) dlsym);
            dlclose_addr = get_remote_func_addr(pid, linker_path, (void *) dlclose);
            dlerror_addr = get_remote_func_addr(pid, linker_path, (void *) dlerror);
        }else{
            dlopen_addr = get_remote_func_addr(pid, libdl_path, (void *) dlopen);
            dlsym_addr = get_remote_func_addr(pid, libdl_path, (void *) dlsym);
            dlclose_addr = get_remote_func_addr(pid, libdl_path, (void *) dlclose);
            dlerror_addr = get_remote_func_addr(pid, libdl_path, (void *) dlerror);
        }

        LOGD("dlopen RemoteFuncAddr:0x%lx", (uintptr_t) dlopen_addr);
        LOGD("dlsym RemoteFuncAddr:0x%lx", (uintptr_t) dlsym_addr);
        LOGD("dlclose RemoteFuncAddr:0x%lx", (uintptr_t) dlclose_addr);
        LOGD("dlerror RemoteFuncAddr:0x%lx", (uintptr_t) dlerror_addr);

        // 将要加载的so库路径写入到远程进程内存空间中
        if (ptrace_writedata(pid, (uint8_t *) RemoteMapMemoryAddr, (uint8_t *) LibPath,
                             strlen(LibPath) + 1) == -1) {
            LOGD("Write LibPath:%s to RemoteProcess error", LibPath);
            break;
        }

        // 设置dlopen的参数,返回值为模块加载的地址
        // void *dlopen(const char *filename, int flag);
        parameters[0] = (uintptr_t) RemoteMapMemoryAddr;
        parameters[1] = RTLD_NOW | RTLD_GLOBAL;

        if (ptrace_call(pid, (uintptr_t) dlopen_addr, parameters, 2, &CurrentRegs) == -1) {
            LOGD("Call Remote dlopen Func Failed");
            break;
        }

        // RemoteModuleAddr为远程进程加载注入模块的地址
        void *RemoteModuleAddr = (void *) ptrace_getret(&CurrentRegs);
        LOGI("ptrace_call dlopen success, Remote Process load module Addr:0x%lx", (long) RemoteModuleAddr);

        if ((long) RemoteModuleAddr == 0x0)   // dlopen 错误
        {
            LOGD("dlopen error");
            if (ptrace_call(pid, (uintptr_t) dlerror_addr, parameters, 0, &CurrentRegs) == -1) {
                LOGD("Call Remote dlerror Func Failed");
                break;
            }
            char *Error = (char *) ptrace_getret(&CurrentRegs);
            char LocalErrorInfo[1024] = {0};
            ptrace_readdata(pid, (uint8_t *) Error, (uint8_t *) LocalErrorInfo, 1024);
            LOGD("dlopen error:%s", LocalErrorInfo);
            break;
        }

        // 将so库中需要调用的函数名称写入到远程进程内存空间中
        if (ptrace_writedata(pid, (uint8_t *) RemoteMapMemoryAddr + strlen(LibPath) + 2,
                             (uint8_t *) FunctionName, strlen(FunctionName) + 1) == -1) {
            LOGD("Write FunctionName:%s to RemoteProcess error", FunctionName);
            break;
        }

        // 设置dlsym的参数，返回值为远程进程内函数的地址
        // void *dlsym(void *handle, const char *symbol);
        parameters[0] = (uintptr_t) RemoteModuleAddr;
        parameters[1] = (uintptr_t) ((uint8_t *) RemoteMapMemoryAddr + strlen(LibPath) + 2);

        if (ptrace_call(pid, (uintptr_t) dlsym_addr, parameters, 2, &CurrentRegs) == -1) {
            LOGD("Call Remote dlsym Func Failed");
            break;
        }

        // RemoteModuleFuncAddr为远程进程空间内获取的函数地址
        void *RemoteModuleFuncAddr = (void *) ptrace_getret(&CurrentRegs);
        LOGI("ptrace_call dlsym success, Remote Process ModuleFunc Addr:0x%lx", (uintptr_t) RemoteModuleFuncAddr);

        if (ptrace_call(pid, (uintptr_t) RemoteModuleFuncAddr, FuncParameter, NumParameter,
                        &CurrentRegs) == -1) {
            LOGD("Call Remote injected Func Failed");
            break;
        }

        if (ptrace_setregs(pid, &OriginalRegs) == -1) {
            LOGD("Recover reges failed");
            break;
        }
        LOGD("Recover Regs Success");
        ptrace_getregs(pid, &CurrentRegs);
        if (memcmp(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs)) != 0) {
            LOGD("Set Regs Error");
        }
        iRet = 0;
    } while (false);

    ptrace_detach(pid);
    return iRet;
}

// SeLinux的强制实施，使得dlopen()外部的so动态库有可能会失败返回。
// 关闭SeLinux setenforce 0; getenforce
// SeLinux会检测so动态库的label标签与权限是否满足可加载的要求，不满足就会无情的拒绝！
// 为了解决这个问题，需要调用setxattr()修改so的属性信息。
// chcon -v u:object_r:system_file:s0 /data/local/tmp/libInjectModule.so
//int setxattr(const char *path, const char *value) {
//    if ((access("/sys/fs/selinux", F_OK)) != -1) {
//        return 0;
//    }
//    return syscall(__NR_setxattr, path, "security.selinux", value, strlen(value), 0);
//}

int test() {
    char InjectModuleName[MAX_PATH] = "/data/local/tmp/libInjectModule.so";    // 注入模块全路径
    char RemoteCallFunc[MAX_PATH] = "Inject_entry";              // 注入模块后调用模块函数名称
//    char InjectProcessName[MAX_PATH] = "com.example.androidinject";
    char InjectProcessName[MAX_PATH] = "zygote";

    char *LibPath = InjectModuleName;
    char *FunctionName = RemoteCallFunc;

    LOGI("find process name %s", InjectProcessName);

    pid_t pid = find_pid_by_name(InjectProcessName);
    if (pid == -1) {
        LOGE("find process name error");
        return -1;
    }

    return inject_remote_process(pid, LibPath, FunctionName, NULL, 0);
//    return inject_remote_process_shellcode(pid, LibPath, FunctionName, NULL, 0);
}
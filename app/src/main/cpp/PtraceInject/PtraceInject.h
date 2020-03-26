//
// Created by Rose on 2020/2/18.
//

#ifndef INJECT_PTRACEINJECT_H
#define INJECT_PTRACEINJECT_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>

#if defined(__aarch64__)
#define pt_regs         user_pt_regs
#elif defined(__x86_64__)
#define pt_regs user_regs_struct
#endif

void* get_module_base_addr(pid_t pid, const char *ModuleName);
void* get_remote_func_addr(pid_t pid, const char *ModuleName, void *LocalFuncAddr);
pid_t find_pid_by_name(const char *process_name);
int ptrace_attach(pid_t pid);
int ptrace_continue(pid_t pid);
int ptrace_detach(pid_t pid);
int ptrace_getregs(pid_t pid, struct pt_regs *regs);
int ptrace_setregs(pid_t pid, struct pt_regs *regs);
int ptrace_readdata(pid_t pid, uint8_t *pSrcBuf, uint8_t *pDestBuf, size_t size);
int ptrace_writedata(pid_t pid, uint8_t *pWriteAddr, uint8_t *pWriteData, size_t size);
int ptrace_call(pid_t pid, uintptr_t ExecuteAddr, long *parameters, long num_params, struct pt_regs* regs);
int inject_remote_process(pid_t pid, char *LibPath, char *FunctionName, long *FuncParameter, long NumParameter);
int test();

#endif //INJECT_PTRACEINJECT_H

#include <jni.h>
#include <string>
#include <unistd.h>

#include "PrintLog.h"

extern "C" __attribute__ ((visibility ("default"))) int Inject_entry()
{
    LOGE("[InjectModule] Inject_entry Func is called\n");
    return 0;
}

__attribute__((constructor)) void _init_array(void)
{
    int pid=getpid();
    LOGE("[InjectModule]Load So _init_array function is called, __from pid:%d",pid);
}

extern "C" void _init(void) {
    int pid=getpid();
    LOGE("[InjectModule]Load So _init function is called, __from pid:%d",pid);
}
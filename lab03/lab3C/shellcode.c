#include <unistd.h>
 
int main(void)
{
    char *argv[] = { "/bin//sh", NULL };   /* ecx : argv = { path, NULL } */
    char *envp[] = { NULL };               /* edx : envp = { NULL }       */
 
    execve(argv[0], argv, envp);           /* eax = 0x0b (execve); int 0x80 */
 
    return 0;                              /* reached only if execve fails  */
}
 

#include <stdio.h>
/* Simple script wrapper that can be setuid to execute /usr/sbin/iotop
 * Used since capabilities were not effective at wrapping python script
 *
 * Author: Keith Wright(wrightrocket)
 * July 15, 2019
 */

int main (int argc, char ** argv, char ** envp) {
	execve("/usr/sbin/iotop", argv, envp );
}

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    /* IFF_NO_PI ... prepends 4 bytes of meta-information to each
       packet read*(). */
    ifr.ifr_flags = IFF_TAP;
    if( *dev )
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

static int setup_tap(void) {
    char devname[IFNAMSIZ] = {0, };
    /* Specifying a non-existant name, possibly containing %d, will
       create a new intrface. For now, use a Makefile target
       (currently `run`) to create the tap interface outside of this
       executable. */
    strcpy(devname, "mytundev0");

    int fd = tun_alloc(devname);

    return fd;
}

int main(int argc, char* argv[]) {

    int fd = setup_tap();

    while (true) {

        uint8_t buf[2048] = {0, };

        int rc = read(fd, buf, sizeof(buf));

        if (rc == -1) {
            perror("read()");
            exit(EXIT_FAILURE);
        }

        printf("bytes= %d\n", rc);

        int i = 0;
        for (i = 1; i <= rc; i++) {
            printf("%02x ", buf[i-1]);

            if (i % 8 == 0)
                printf("\t");
            if (i % 32 == 0)
                printf("\n");
        }

        // Print newline if packet did not end on a 32-byte boundary
        // (i.e., avoid double \n).
        if (i % 32 != 0)
            printf("\n");
    }

    return EXIT_SUCCESS;
}

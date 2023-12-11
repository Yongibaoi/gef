#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <fcntl.h>
#include <sys/types.h>
#include <mqueue.h>
#include <semaphore.h>
#include <sys/mman.h>

int main(int argc, char* argv[]) {
    if (argc < 1) {
        printf("%s [ [s|r|d]\n", argv[0]);
        puts("* POSIX sem/shm can be accessed from under /dev/shm");
        puts("* POSIX mq can be accessed from under /dev/mqueue");
        exit(1);
    }

    if (argc < 2 || argv[1][0] == 's') {
        /* POSIX semaphore */
        sem_t* semid = sem_open("/sample", O_CREAT, 0666, 0);
        printf("semid: %lx\n", (unsigned long)semid);
        sem_close(semid);

        /* POSIX message queue */
        mqd_t msqid = mq_open("/sample", O_WRONLY | O_CREAT, 0666, NULL);
        printf("msqid: %d\n", msqid);
        char buf[] = "AAAA";
        mq_send(msqid, (char*)&buf, strlen(buf), 0);
        mq_close(msqid);

        /* POSIX shared memory */
        int shmid = shm_open("/sample", O_RDWR | O_CREAT, 0666);
        printf("shmid: %d\n", shmid);
        close(shmid);

    } else if (argv[1][0] == 'r') {
        /* POSIX semaphore */
        // do nothing

        /* POSIX message queue */
        mqd_t msqid = mq_open("/sample", O_RDONLY);
        struct mq_attr attr;
        mq_getattr(msqid, &attr);
        char *buf = malloc(attr.mq_msgsize);
        mq_receive(msqid, (char*)buf, attr.mq_msgsize, NULL);
        puts(buf);
        free(buf);
        mq_close(msqid);

        /* POSIX shared memory */
        // do nothing

    } else if (argv[1][0] == 'd') {
        /* POSIX semaphore */
        sem_unlink("/sample");

        /* POSIX message queue */
        mq_unlink("/sample");

        /* POSIX shared memory */
        shm_unlink("/sample");
    }
    return 0;
}

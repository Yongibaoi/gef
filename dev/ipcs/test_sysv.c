#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <sys/shm.h>

#define NSEMS 10
union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

#define MSGTYPE 1
struct msgbuf {
    long mtype;
    char mtext[4];
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("%s <PATH> [s|r|d]\n", argv[0]);
        puts("* System-V IPCs can be dumped by `ipcs`");
        exit(1);
    }

    key_t key = ftok(argv[1], 'S');
    if (key == -1) {
        perror("ftok");
        exit(1);
    }

    if (argc < 3 || argv[2][0] == 's') {
        /* SystemV semaphore */
        int semid = semget(key, NSEMS, IPC_CREAT | 0666);
        printf("semid: %d\n", semid);
        union semun arg = { .val = 1 };
        semctl(semid, 0, SETVAL, arg);

        /* SystemV message queue */
        int msqid = msgget(key, IPC_CREAT | 0666);
        printf("msqid: %d\n", msqid);
        struct msgbuf message = { .mtype = MSGTYPE, .mtext = {'A', 'A', 'A', '\0'} };
        msgsnd(msqid, &message, sizeof(message.mtext), IPC_NOWAIT);

        /* SystemV shared memory */
        int shmid = shmget(key, 0x1000, IPC_CREAT | 0666);
        printf("shmid: %d\n", semid);

    } else if (argv[2][0] == 'r') {
        /* SystemV semaphore */
        // do nothing

        /* SystemV message queue */
        int msqid = msgget(key, 0);
        printf("msqid: %d\n", msqid);
        struct msgbuf message = { .mtype = MSGTYPE };
        msgrcv(msqid, &message, sizeof(message.mtext), MSGTYPE, IPC_NOWAIT);
        puts(message.mtext);

        /* SystemV shared memory */
        // do nothing

    } else if (argv[2][0] == 'd') {
        /* SystemV semaphore */
        int semid = semget(key, 0, 0);
        printf("semid: %d\n", semid);
        semctl(semid, 0, IPC_RMID);

        /* SystemV message queue */
        int msqid = msgget(key, 0);
        printf("msqid: %d\n", msqid);
        msgctl(msqid, IPC_RMID, NULL);

        /* SystemV shared memory */
        int shmid = shmget(key, 0, 0);
        printf("shmid: %d\n", semid);
        shmctl(shmid, IPC_RMID, NULL);
    }
    return 0;
}

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <mosquitto.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <signal.h>
#include <assert.h>
#include <openssl/crypto.h>
#include <map>
#include "MyEpoll.h"
#include "MyTimer.h"

using namespace std;


int g_iThreadCount ;
int g_iPayloadLen;
int g_iTopicMode;
int g_iClientId;
int g_iHandleCount = 2;
volatile int g_iRun = 1;
int g_iSleepUs = 1;
int g_iSSL = 0;
int g_iQOS = 1;
int g_iShortConn = 0;
string g_sServerIp;
int g_iServerPort;
char* g_pTopicPre = (char *)"mqtt_test";
map<unsigned long long, unsigned long long> g_vLastIdMap;

struct ThreadLocalInfo{
    ThreadLocalInfo(){
        iConnCount = 0;
    }
    int iConnCount;
};

ThreadLocalInfo g_vThreadConn[10000];


#define GetSessionId(iTid, iHid) ((unsigned long long)g_iClientId * 1000000 + iTid * 10000 +iHid)

#define USE_TLS

unsigned myUSleep(double fStart, unsigned usec){
    while(true){
        unsigned uIntv = (unsigned)((get_now() - fStart) * 1000);
        if(uIntv + 500>= usec){
            return uIntv;
        }
        usec -= uIntv;
        usleep(usec);
    }
}


struct MessageInfo{
	double fCreateTime;
    unsigned long long iMsgId;
	int iClientId;
	int iHandleId;
	int iTId;
};

#define TOPIC_MAX_LEN 50
struct HandleInfo{
    char *pPayload;
	MessageInfo*pvMsg;
    char pTopic[TOPIC_MAX_LEN];
};

struct SessionInfo{
	int iTid;
	int iHid;
	unsigned long long uNeedId;
	string sTopic;
    int iFd;
    int bFirst;
    CEpoll * pEpoll;
    MyTimer *pvMyTimer;
    struct mosquitto *pMos;
    char pClientId[50];
    char cConn;
};

struct ThreadInfo{
    void Change(){
        iSendCount = 0;
        fStartTime = get_now();
    }
	void Init(int iParamTid){
        iTid = iParamTid;
        pHandleInfo = new HandleInfo[g_iHandleCount];
        for(int i=0; i < g_iHandleCount; i++){
            pHandleInfo[i].pPayload = new char[g_iPayloadLen];
            for(int x=0; x < g_iPayloadLen; x++){
                pHandleInfo[i].pPayload[x] = 'a' + (x%26);
            }
            pHandleInfo[i].pvMsg = (MessageInfo*)pHandleInfo[i].pPayload;
            pHandleInfo[i].pvMsg->iClientId = g_iClientId;
            pHandleInfo[i].pvMsg->iHandleId = i;
            pHandleInfo[i].pvMsg->iTId = iParamTid;
            if(g_iTopicMode == 0){
                sprintf(pHandleInfo[i].pTopic, "%s", g_pTopicPre);
            }
            else{
                sprintf(pHandleInfo[i].pTopic, "%s/cid_%d/tid_%d/hid_%d", g_pTopicPre, g_iClientId, iParamTid, i);
            }
        }
        Change();
        iRun = 1;
	}
    HandleInfo* pHandleInfo;
	double fStartTime;
	double fEndTime;
	unsigned iSendCount;
	int iTid;
	int iRun;
};
ThreadInfo *volatile g_pAllThread;

 ThreadInfo * g_pAllThreadMem;
 ThreadInfo * g_pAllThread2Mem;

using namespace std;

struct UserInfo{
	UserInfo(){
		clientid = iIndex = 0;
		iState = -1;
	}
	int clientid;
	int iIndex;
	int iState;
};
void addHandle(int iTid, int iHid, CEpoll * pvMyEpoll, SessionInfo * pSInfo);
int addHandleCallBack(void *pData);
void ecos_locking_callback(int mode, int type, const char *file, int line);
typedef pthread_mutex_t cyg_mutex_t;
static pthread_mutex_t *lock_cs;
void thread_setup(void)
{
    int i;

    // 动态创建 lock 数组
    // Allocate lock array according to OpenSSL's requirements
    lock_cs=(pthread_mutex_t *)malloc(CRYPTO_num_locks() * sizeof(cyg_mutex_t));

    // lock 数组初始化
    // Initialize the locks
    for (i=0; i<CRYPTO_num_locks(); i++)
    {
        pthread_mutex_init(&(lock_cs[i]),NULL);
    }
    //printf("init mutex %d\n", (int)CRYPTO_num_locks());
    //  注册两个回调函数
    // Register callbacks
    //CRYPTO_THREADID_set_callback(ecos_thread_id_callback);
    //CRYPTO_set_id_callback((unsigned long (*)())ecos_thread_id_callback);
    CRYPTO_set_locking_callback(ecos_locking_callback);
}

void ecos_locking_callback(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
    {
        pthread_mutex_lock(&(lock_cs[type]));
    }
    else
    {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}

int PublishOneMsg(void* pData){
    //printf("PublishOneMsg %p\n", pData);
    SessionInfo* pSInfo = (SessionInfo*)pData;
	ThreadInfo *pThread = &g_pAllThread[pSInfo->iTid];
    pThread->pHandleInfo[pSInfo->iHid].pvMsg->fCreateTime = get_now();
    //printf("Sid: %llu\n", GetSessionId(iTid, iHid));
    pThread->pHandleInfo[pSInfo->iHid].pvMsg->iMsgId =pSInfo->uNeedId++;
    int iRet;
    iRet = mosquitto_publish(pSInfo->pMos, NULL, pThread->pHandleInfo[pSInfo->iHid].pTopic, g_iPayloadLen, pThread->pHandleInfo[pSInfo->iHid].pPayload, g_iQOS, false);
    if(iRet != MOSQ_ERR_SUCCESS){
        printf("mosquitto_publish failed %d %s\n", iRet, mosquitto_strerror(iRet));
        pThread->iRun = 0;
        return -1;
    }
    return 0;
}

int EpollCallbackPub(void* pData, epoll_event* pEvent){
    //if(pEvent->events &EPOLLIN)
    //    printf("get event sock%d %d %p\n", mosquitto_socket((struct mosquitto *)pData), pEvent->events, pData);
    int iRet;
    iRet = mosquitto_loop_simple(((SessionInfo * )pData)->pMos, 1, 3);
    if(iRet != 0){
        printf("mosquitto_loop failed %d %s\n", iRet, mosquitto_strerror(iRet));
    }
    return iRet;
    /*mosquitto_loop_read(pSInfo->pMos, 10);
    if(mosquitto_want_write(pSInfo->pMos))
        mosquitto_loop_write(pSInfo->pMos, 1);
    //return mosquitto_loop_misc((struct mosquitto *)pData);
    return 0;*/
}

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	//printf("on_connect %p\n",mosq);
	if(rc){
		printf("on_connect failed %d\n", rc);
		return;
	}else{
        SessionInfo* pSInfo = (SessionInfo*)obj;
        int iTid = pSInfo->iTid;
        int iHid = pSInfo->iHid;
        ThreadInfo *pThread = &g_pAllThread[iTid];
        if(pSInfo->cConn != 1){
            printf("connect state is %d, Hid %d, state %d\n", iTid, iHid, pSInfo->cConn);
            return;
        }
        pSInfo->cConn = 2;
        g_vThreadConn[iTid].iConnCount++;
        //printf("test tid add to %d %d\n", iTid ,g_vThreadConn[iTid].iConnCount);
        if( ((SessionInfo*)obj)->bFirst){
    		rc = mosquitto_publish(mosq, NULL, "new_topic", strlen(pThread->pHandleInfo[iHid].pTopic)+1, pThread->pHandleInfo[iHid].pTopic, g_iQOS, false);
    		if(rc != MOSQ_ERR_SUCCESS){
    			printf("mosquitto_publish failed1 %d ", rc);
                pThread->iRun = 0;
    			return;
    		}
            if(!g_iShortConn && g_iSleepUs){
                ((SessionInfo*)obj)->pvMyTimer->AddTimerPoint(PublishOneMsg, obj, g_iSleepUs, true);
            }
        }
        else{// short connection
            PublishOneMsg(obj);
        }
	}
}

void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
    SessionInfo* pSInfo = (SessionInfo*)obj;
	//printf("on_disconnect %d\n",mosquitto_socket(mosq));
    //addHandle(pSInfo->iTid, pSInfo->iHid, pSInfo->pEpoll, pSInfo);
    if(pSInfo->cConn!=2){
        printf("disconnect state is %d\n", pSInfo->cConn);
    }
    if(pSInfo->cConn == 2){
        g_vThreadConn[pSInfo->iTid].iConnCount--;
    }
    else if(pSInfo->cConn == 0)
        return;
    
    if(g_vThreadConn[pSInfo->iTid].iConnCount < 0)
        printf("fuck here redisconnect %d %d %d\n", pSInfo->iTid, pSInfo->iHid, g_vThreadConn[pSInfo->iTid].iConnCount);
    pSInfo->cConn = 0;
    if(g_iShortConn && (!g_iSleepUs)){
        addHandleCallBack(obj);
        //((SessionInfo*)obj)->pvMyTimer->AddTimerPoint(addHandleCallBack, obj, 0, false);
        //int iRet = mosquitto_reconnect_async( mosq);
        //if(iRet != 0){
        //    printf("mosquitto_reconnect_async failed %d %s\n", iRet, mosquitto_strerror(iRet));
        //}
    }
    //printf("test tid minus to %d %d\n", ((SessionInfo*)obj)->iTid,g_vThreadConn[((SessionInfo*)obj)->iTid].iConnCount);
	//printf("run on_disconnect %d %d %s %d\n", rc, mosquitto_socket(mosq), mosquitto_strerror(rc), g_vThreadConn[((SessionInfo*)obj)->iTid].iConnCount);
	//printf("run on_disconnect2 %d %d %s\n", rc, mosquitto_socket(mosq), mosquitto_strerror(rc));
}

void on_publish(struct mosquitto *mosq, void *obj, int mid){
    if(!((SessionInfo*)obj)->bFirst){
        int iTid = ((SessionInfo*)obj)->iTid;
        ThreadInfo *pThread = &g_pAllThread[iTid];
        pThread->iSendCount++;//first topic message will add this additionally
    }
    ((SessionInfo*)obj)->bFirst = false;
    if(g_iShortConn){
        mosquitto_disconnect( mosq );
        //printf("call mosquitto_disconnect \n");
    }
    else if(!g_iSleepUs){
        PublishOneMsg(obj);
    }
}
void action(int a)
{
    printf("get terminal\n");
    g_iRun = 0;
}

void signalDeal(){
    struct sigaction s;
    memset(&s, 0, sizeof(s));
    s.sa_handler = action;
    sigfillset(&s.sa_mask);
    //s.sa_flags |= SA_RESTART;
    assert(sigaction(SIGINT, &s, NULL) != 1);
}
void printThreadInfo(ThreadInfo* pLastAllThread){
    if(!pLastAllThread)
        return;
    double fUseTime = pLastAllThread[0].fEndTime - pLastAllThread[0].fStartTime;
    unsigned uTotalCount = 0;
    unsigned uTotalConn = 0;

    for (int i = 0; i< g_iThreadCount; i++) {
        uTotalCount += pLastAllThread[i].iSendCount;
        uTotalConn += g_vThreadConn[i].iConnCount;
    }
    double fMsgPerSec = (double)uTotalCount*1000 /fUseTime;
    double fBytesPerSec = fMsgPerSec * g_iPayloadLen;
    printf("last last second: total: %u msgs, conn: %u, avg: %0.4f msgs/sec, %0.4f KB/sec\n", uTotalCount, uTotalConn, fMsgPerSec, fBytesPerSec/1024);

}

void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}

int addHandleCallBack(void *pData){
    SessionInfo * pSInfo = (SessionInfo * )pData;
    if(pSInfo->cConn > 0)
        return 0;
    pSInfo->cConn = 1;
    struct mosquitto *pMos;
    int iRet;

    if(!pSInfo->pMos  ){
        pMos = mosquitto_new(pSInfo->pClientId, false, pSInfo);
    }
    else{
        pMos = pSInfo->pMos;
        pSInfo->pEpoll->Del(pSInfo->iFd);
        /*mosquitto_destroy( pMos);
        pMos= mosquitto_new(pSInfo->pClientId, true, pSInfo);*/
        iRet = mosquitto_reinitialise( pMos,pSInfo->pClientId, false,pSInfo);
        if(iRet != 0){
            printf("mosquitto_reinitialise failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
        /*//printf("get here1\n");
        iRet = mosquitto_reconnect_async(pMos);
        if(iRet != MOSQ_ERR_SUCCESS){
            printf("connect failed12 %s %d %s\n", g_sServerIp.c_str(), g_iServerPort, mosquitto_strerror(iRet));
            return -1;
        }
        g_vThreadConn[pSInfo->iTid].iConnCount++;
        PublishOneMsg(pData);
        //printf("get here2\n");
        //printf("mosquitto_connect_async success %d\n", mosquitto_socket(pMos));*/
    }
    pSInfo->pMos = pMos;
    if(g_iSSL){
    	
        /*iRet = mosquitto_tls_opts_set(pMos, 1, "tlsv1", NULL);
        if(iRet != 0){
            printf("mosquitto_tls_opts_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
        iRet = mosquitto_tls_insecure_set(	pMos, true);
        if(iRet != 0){
            printf("mosquitto_tls_insecure_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
        iRet = mosquitto_threaded_set( pMos, true);
        if(iRet != 0){
            printf("mosquitto_threaded_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }*/
    	iRet = mosquitto_tls_set(pMos, "./ca.crt", NULL, NULL, NULL, NULL);
        if(iRet != 0){
            printf("mosquitto_tls_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
        iRet = mosquitto_tls_opts_set(	pMos, 0 ,NULL,NULL);
        if(iRet != 0){
            printf("mosquitto_tls_opts_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
    }
    mosquitto_connect_callback_set(pMos, on_connect);
	//mosquitto_log_callback_set(pMos, my_log_callback);
	mosquitto_disconnect_callback_set(pMos, on_disconnect);
	mosquitto_publish_callback_set(pMos,on_publish);
    iRet = mosquitto_connect_async(pMos, g_sServerIp.c_str(), g_iServerPort, 60);
    if(iRet != MOSQ_ERR_SUCCESS){
        printf("connect failed11 %s %d %s\n", g_sServerIp.c_str(), g_iServerPort, mosquitto_strerror(iRet));
        return -1;
    }
    int sock = mosquitto_socket(pMos);
    pSInfo->pEpoll->eventAdd( sock, true, true, pSInfo, EpollCallbackPub);
    pSInfo->iFd = sock;
    //printf("tid: topic:%s\n", pSInfo->sTopic.c_str());
    return 0;
}

void addHandle(int iTid, int iHid, CEpoll * pvMyEpoll, MyTimer * pvMyTimer, SessionInfo * pSInfo){
    struct mosquitto *pMos;
    int iRet;

    if(pSInfo == NULL){
        pSInfo = new SessionInfo;
        pSInfo->iHid = iHid;
        pSInfo->iTid = iTid;
        pSInfo->uNeedId = 0;
        pSInfo->bFirst = true;
        pSInfo->pEpoll = pvMyEpoll;
        pSInfo->cConn = 0;
        pSInfo->pvMyTimer =  pvMyTimer;
        sprintf(pSInfo->pClientId, "pub%d_%d_%d", g_iClientId, iTid, iHid);
        if(g_iSleepUs){
            if(g_iShortConn){
                pSInfo->pMos = NULL;
                pSInfo->pvMyTimer->AddTimerPoint(addHandleCallBack, pSInfo, g_iSleepUs, true);
                return;
            }
        }
        pMos= mosquitto_new(pSInfo->pClientId, false, pSInfo);
        pSInfo->pMos = pMos;
    }
    else{
        pMos = pSInfo->pMos;
        pSInfo->pEpoll->Del(pSInfo->iFd);
        
        /*mosquitto_destroy( pMos);
        pMos= mosquitto_new(pSInfo->pClientId, true, pSInfo);*/
        iRet = mosquitto_reinitialise( pMos,pSInfo->pClientId, false,pSInfo);
        if(iRet != 0){
            printf("mosquitto_reinitialise failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
        pSInfo->pMos = pMos;
    }
    if(g_iSSL){
    	
        /*iRet = mosquitto_tls_opts_set(pMos, 1, "tlsv1", NULL);
        if(iRet != 0){
            printf("mosquitto_tls_opts_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
        iRet = mosquitto_tls_insecure_set(	pMos, true);
        if(iRet != 0){
            printf("mosquitto_tls_insecure_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }*/
    	iRet = mosquitto_tls_set(pMos, "./ca.crt", NULL, NULL, NULL, NULL);
        if(iRet != 0){
            printf("mosquitto_tls_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
        iRet = mosquitto_tls_opts_set(	pMos, 0 ,NULL,NULL);
        if(iRet != 0){
            printf("mosquitto_tls_opts_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
    }
    mosquitto_connect_callback_set(pMos, on_connect);
	mosquitto_disconnect_callback_set(pMos, on_disconnect);
	//mosquitto_log_callback_set(pMos, my_log_callback);
	mosquitto_publish_callback_set(pMos,on_publish);
    iRet = mosquitto_connect_async(pMos, g_sServerIp.c_str(), g_iServerPort, 60);
    if(iRet != MOSQ_ERR_SUCCESS){
        printf("connect failed1 %s %d %s \n", g_sServerIp.c_str(), g_iServerPort, mosquitto_strerror(iRet));
        return;
    }
    int sock = mosquitto_socket(pMos);
    pvMyEpoll->eventAdd( sock, true, true, pSInfo, EpollCallbackPub);
    pSInfo->iFd = sock;
    //printf("tid: %d, hid %d, sockfd: %d, topic:%s\n", iTid, iHid, sock, pSInfo->sTopic.c_str());
}
int main(int argc, char *argv[])
{
	if(argc != 13){
		printf("Usage: %s ipaddr port thread_count conn_per_thread payload_len topic_mode clientid sleepMs ssl(0|1) short_connect(0|1) qos topic_pre\n", argv[0]);
		return -1;
	}
	printf("Start test:\nipaddr:\t%s\nport:\t%d\nthread_count:\t%d\nconn_per_thread:\t%d\npayload_len:\t%d\ntopic_mode:\t%s\nconn_count:\t%d\nclientid:\t%d\nsleep ms:\t%d\nssl:\t%d\nshort_connect:\t%d\nqos:\t%d\ntopic_pre:\t%s\n==============\n",
	argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6])==0?"0 single":"1 mult", atoi(argv[3])*atoi(argv[4]), atoi(argv[7]), atoi(argv[8]), atoi(argv[9]), atoi(argv[10]), atoi(argv[11]), argv[12]);
	g_sServerIp = argv[1];
	g_iServerPort = atoi(argv[2]);
	g_iThreadCount = atoi(argv[3]);
    g_iHandleCount = atoi(argv[4]);
	g_iPayloadLen = atoi(argv[5]);
	g_iTopicMode = atoi(argv[6]);
	g_iClientId = atoi(argv[7]);
	g_iSleepUs = atoi(argv[8]);
    g_iSSL = atoi(argv[9]);
    g_iShortConn = atoi(argv[10]);
    g_iQOS = atoi(argv[11]);
    g_pTopicPre = (char*)argv[12];
	if(g_iPayloadLen < 40){
		printf("payload_len is too small.\n");
		exit(-1);
	}
    if(g_iSSL && g_iThreadCount){
        thread_setup();
    }
	mosquitto_lib_init();
    signalDeal();
    std::thread **sendingThreads = (thread**)malloc(sizeof(thread*) * g_iThreadCount);

	g_pAllThreadMem = new ThreadInfo[g_iThreadCount];
	g_pAllThread2Mem = new ThreadInfo[g_iThreadCount];
    g_pAllThread = g_pAllThreadMem;
    for (int i = 0; i< g_iThreadCount; i++) {
        g_pAllThreadMem[i].Init(i);
        g_pAllThread2Mem[i].Init(i);
		sendingThreads[i] = new thread([i, &argv]{
			int rc;
			char pvClientId[100];
            MyTimer vMyTimer;
            CEpoll vMyEpoll;
            vMyEpoll.Init(g_iHandleCount*2);
            for(int im = 0; im< g_iHandleCount; im++){
                addHandle(i, im, &vMyEpoll, &vMyTimer, NULL);
            }
            g_pAllThread[i].Change();
			while(g_iRun){
                vMyEpoll.doEpoll(0);
                vMyTimer.DoTimer();
			}
		});
	}
    thread * pStatisticThread = new thread([]{
        ThreadInfo* pLastAllThread = g_pAllThread;
        while(true){
            myUSleep(get_now(), 1000000); //sleep 1 sec
            if(pLastAllThread == NULL){
                pLastAllThread = g_pAllThread;
                continue;
            }
            else{
                printThreadInfo(pLastAllThread);
                double fNow = get_now();
                pLastAllThread = g_pAllThread;
                
                if(g_pAllThread == g_pAllThreadMem){
                    for (int i = 0; i< g_iThreadCount; i++) {
                        g_pAllThread2Mem[i].Change();
                    }
                    g_pAllThread = g_pAllThread2Mem;
                }
                else{
                    for (int i = 0; i< g_iThreadCount; i++) {
                        g_pAllThreadMem[i].Change();
                    }
                    g_pAllThread = g_pAllThreadMem;
                }
                fNow = get_now();
                for (int i = 0; i< g_iThreadCount; i++) {
                    pLastAllThread[i].fEndTime = fNow;
                }
            }
            if(!g_iRun){
                printf("over \n");
                printThreadInfo(pLastAllThread);
                exit(0);
            }
        }
    });
    while(true){
        sleep(100);
    }
	mosquitto_lib_cleanup();
	return 0;
}

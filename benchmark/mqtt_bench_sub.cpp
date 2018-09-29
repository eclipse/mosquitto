#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <thread>
#include <mosquitto.h>
#include <unistd.h>
#include <sys/time.h>
#include <atomic>
#include <chrono>
#include <signal.h>
#include <assert.h>
#include <map>
#include <mutex>
#include <openssl/crypto.h>
#include<list>
#include "MyEpoll.h"
#include "MyTimer.h"

using namespace std;


int g_iThreadCount ;
int g_iPayloadLen= 100;
int g_iTopicMode;
int g_iSingleModeSession = 0;
int g_iClientCount;
int g_iHandleCount = 1;
volatile int g_iRun = 1;
int g_iSSL = 0;
int g_iQOS = 1;


string g_sServerIp;
int g_iServerPort;

mutex g_vLockVec;
list<string> g_vTopicVec;
volatile bool g_bHasNewTopic = false;
map<unsigned long long, unsigned long long> g_vLastIdMap;

#define GetSessionId(iCid, iTid, iHid) (iCid * 1000000 + iTid * 10000 +iHid)

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

map<unsigned long long, unsigned long long> *g_pvLastIdMap;


struct ThreadInfo{
    void Change(){
        iSendCount = 0;
        uByteCount = 0;
        uLostMsg = 0;
        fLatency = 0.0;
        fStartTime = get_now();
    }
	void Init(int iParamTid){
        iTid = iParamTid;
        pHandleInfo = new HandleInfo[g_iHandleCount];
        for(int i=0; i < g_iHandleCount; i++){
            pHandleInfo[i].pPayload = new char[g_iPayloadLen];
            pHandleInfo[i].pvMsg = (MessageInfo*)pHandleInfo[i].pPayload;
            //pHandleInfo[i].pvMsg->iClientId = g_iClientCount;
            pHandleInfo[i].pvMsg->iHandleId = i;
            pHandleInfo[i].pvMsg->iTId = iParamTid;
            if(g_iTopicMode == 0){
                sprintf(pHandleInfo[i].pTopic, "mqtt_test2");
            }
            else{
                sprintf(pHandleInfo[i].pTopic, "mqtt_test2/+/tid_%d/hid_%d", iParamTid, i);
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
	unsigned long long uByteCount;
	double fLatency;
	unsigned uLostMsg;
};
ThreadInfo *volatile g_pAllThread;

 ThreadInfo * g_pAllThreadMem;
 ThreadInfo * g_pAllThread2Mem;

using namespace std;

struct SessionInfo{
	int iTid;
	int iHid;
	unsigned long long uNeedId;
	string sTopic;
    int iFd;
    map<unsigned long long, unsigned long long> vLastIdMap;
};
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

void on_connect_manager(struct mosquitto *mosq, void *obj, int rc)
{
	if(rc){
		printf("on_connect failed %d\n", rc);
		return;
	}else{
		mosquitto_subscribe(mosq, NULL, "new_topic", g_iQOS);
	}
}


void on_message_manager(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
    g_vLockVec.lock();
    if(g_iTopicMode == 0){
        if(g_iSingleModeSession >= g_iThreadCount * g_iHandleCount){
            g_vLockVec.unlock();
            return;
        }
        else 
            g_iSingleModeSession++;
    }
    //printf("get new topic %s\n", (char*)msg->payload);
    g_vTopicVec.push_back(string((char*)msg->payload));
    g_bHasNewTopic = true;
    g_vLockVec.unlock();
}

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	if(rc){
		printf("on_connect failed %d\n", rc);
		return;
	}else{
		printf("on_connect sucess %d\n", rc);
		mosquitto_subscribe(mosq, NULL, ((SessionInfo*)obj)->sTopic.c_str(), g_iQOS);
	}
}


void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
	if(msg->retain)
		return;
    
    int iTid = ((SessionInfo*)obj)->iTid;
	ThreadInfo *pThread = &g_pAllThread[iTid];

    double fNow = get_now();
	pThread->iSendCount++;
    pThread->uByteCount += msg->payloadlen;
    MessageInfo* pMsg = (MessageInfo*)msg->payload;
    pThread->fLatency += fNow - pMsg->fCreateTime;
    unsigned long long uSid = GetSessionId(pMsg->iClientId, pMsg->iTId, pMsg->iHandleId);
    unsigned long long &uNeedId = ((SessionInfo*)obj)->vLastIdMap[uSid];//g_vLastIdMap[uSid];((SessionInfo*)obj)->uNeedId;
    //printf("need is %llu, get %llu, RemoteSid:%llu, localSid:%d, %p\n", uNeedId, pMsg->iMsgId, uSid, GetSessionId(0, iTid, ((SessionInfo*)obj)->iHid), obj);
    if( uNeedId != pMsg->iMsgId){
        printf("need is %llu, get %llu, RemoteSid:%llu, localSid:%d, %p\n", uNeedId, pMsg->iMsgId, uSid, GetSessionId(0, iTid, ((SessionInfo*)obj)->iHid), obj);
        pThread->uLostMsg += pMsg->iMsgId  - uNeedId;
    }
    uNeedId = pMsg->iMsgId+1;
	/*printf("message mid:%d, qos:%d, topic:%s, content_len:%d, retain:%d, "
        "createTime:%f, clientId:%d, Tid:%d, HandleId:%d, delay:%f\n", msg->mid, msg->qos,
        msg->topic, msg->payloadlen, (int)msg->retain,
        pMsg->fCreateTime, pMsg->iClientId, pMsg->iTId, pMsg->iHandleId, get_now() - pMsg->fCreateTime
        );
    */
		//printf("message total: %d, totalTime %d ms, %0.5f msgs/s\n", g_iRecvCount, ms, (double)g_iRecvCount*1000/ms);
}

void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	printf("run on_disconnect %d %s\n", rc, mosquitto_strerror(rc));
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
    unsigned long long uTotalBytes = 0;
    double fTotalLatency = 0.0;
    unsigned long long uTotalLost = 0;
    for (int i = 0; i< g_iThreadCount; i++) {
        uTotalCount += pLastAllThread[i].iSendCount;
        uTotalBytes += pLastAllThread[i].uByteCount;
        fTotalLatency += pLastAllThread[i].fLatency;
        uTotalLost += pLastAllThread[i].uLostMsg;
    }
    double fMsgPerSec = (double)uTotalCount*1000 /fUseTime;
    double fBytesPerSec = (double)uTotalBytes*1000 /fUseTime;
    printf("last last second: total: %u msgs, latency:%0.4f ms, lost: %llu, avg: %0.4f msgs/sec, %0.4f KB/sec\n", uTotalCount, fTotalLatency/uTotalCount, uTotalLost, fMsgPerSec, fBytesPerSec/1024);

}
int EpollCallbackSub(void* pData, epoll_event* pEvent){
    //printf("get event %d %d\n", ((SessionInfo*)((struct mosquitto *)pData)->userdata)->iFd, pEvent->events);
    return mosquitto_loop((struct mosquitto *)pData, -1, 1);
    //if(mosquitto_want_write((struct mosquitto *)pData))
    //    mosquitto_loop_write((struct mosquitto *)pData, 1);
    //return mosquitto_loop_read((struct mosquitto *)pData, 1);
    return mosquitto_loop_misc((struct mosquitto *)pData);
}


void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	printf("%s\n", str);
}
void on_subscribe(struct mosquitto *mosq, void *obj, int mid)
{
	printf("subscribe success\n");
}

void addHandle(CEpoll & vMyEpoll, int iTid, int iHid){
    if(!g_bHasNewTopic)
        return;
    g_vLockVec.lock();
    if(!g_bHasNewTopic){
        g_vLockVec.unlock();
        return;
    }
    string &sTopic = g_vTopicVec.front();
    char pvClientId[100];
    SessionInfo * pSInfo = new SessionInfo;
    pSInfo->iHid = iHid;
    pSInfo->iTid = iTid;
    pSInfo->uNeedId = 0;
    pSInfo->sTopic = sTopic;
    sprintf(pvClientId, "subv2%d_%d", iTid, iHid);
    struct mosquitto *pMos= mosquitto_new(pvClientId, true, pSInfo);
    if(g_iSSL){
    	int iRet = mosquitto_tls_set(pMos, "./ca.crt", NULL, NULL, NULL, NULL);
        if(iRet != 0){
            printf("mosquitto_tls_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
        iRet = mosquitto_tls_opts_set(	pMos, 0 ,NULL,NULL);
        if(iRet != 0){
            printf("mosquitto_tls_opts_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
        }
    }
    //mosquitto_subscribe_callback_set(pMos, on_subscribe);
    mosquitto_connect_callback_set(pMos, on_connect);
	mosquitto_disconnect_callback_set(pMos, on_disconnect);
    mosquitto_message_callback_set(pMos, on_message);
    
    mosquitto_publish_callback_set(pMos,on_subscribe);
    int rc = mosquitto_connect(pMos, g_sServerIp.c_str(), g_iServerPort, 60);
    if(rc != MOSQ_ERR_SUCCESS){
        printf("connect failed %s %d", g_sServerIp.c_str(), g_iServerPort);
        g_vLockVec.unlock();
        return;
    }
    int sock = mosquitto_socket(pMos);
    vMyEpoll.eventAdd( sock, true, true, pMos, EpollCallbackSub);
    g_vTopicVec.pop_front();
    if(g_vTopicVec.size() == 0)
        g_bHasNewTopic = false;
    g_vLockVec.unlock();
    pSInfo->iFd = sock;
    printf("tid: %d, hid %d, topic:%s\n", iTid, iHid, sTopic.c_str());
}
int main(int argc, char *argv[])
{
	if(argc != 9){
		printf("Usage: %s ipaddr port thread_count conn_per_thread topic_mode client_count ssl(0|1) qos\n", argv[0]);
		return -1;
	}
	printf("Start test:\nipaddr:\t%s\nport:\t%d\nthread_count:\t%d\n"
	"conn_per_thread:\t%d\ntopic_mode:\t%s\nconn_count:\t%d\nclient_count:\t%d\nqos:\t%d\n"
	"ssl:\t%d\n==============\n",
	argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5])==0?"0 single":"1 mult",
	atoi(argv[3])*atoi(argv[4]), atoi(argv[6]), atoi(argv[7]), atoi(argv[8]));
	
	g_sServerIp = argv[1];
	g_iServerPort = atoi(argv[2]);
    g_iThreadCount = atoi(argv[3]);
    g_iHandleCount = 1; //atoi(argv[4]);
	g_iTopicMode = atoi(argv[5]);
	g_iClientCount = atoi(argv[6]);
    g_iSSL = atoi(argv[7]);
    g_iQOS = atoi(argv[8]);
	mosquitto_lib_init();
    signalDeal();
    std::thread **sendingThreads = (thread**)malloc(sizeof(thread*) * g_iThreadCount);

    if(g_iSSL && g_iThreadCount){
        thread_setup();
    }

	g_pAllThreadMem = new ThreadInfo[g_iThreadCount];
	g_pAllThread2Mem = new ThreadInfo[g_iThreadCount];
    g_pvLastIdMap = new map<unsigned long long, unsigned long long>[g_iThreadCount];
    g_pAllThread = g_pAllThreadMem;
    for (int i = 0; i< g_iThreadCount; i++) {
        g_pAllThreadMem[i].Init(i);
        g_pAllThread2Mem[i].Init(i);
		sendingThreads[i] = new thread([i, &argv]{
			int rc;
			char pvClientId[100];
            CEpoll vMyEpoll;
            vMyEpoll.Init(10000);
            int iSid = 0;
            g_pAllThread[i].Change();
			while(g_iRun){
                vMyEpoll.doEpoll(1);
                if(g_bHasNewTopic){
                    addHandle(vMyEpoll, i, iSid++);
                }
                /*for(int im = 0; im< g_iHandleCount; im++){
				    mosquitto_loop(pAllMos[im], -1, 1);
                }*/
			}
		});
	}

    thread * pManagerThread = new thread([&argv]{
    			struct mosquitto *pMMos= mosquitto_new("manager_sub", true, NULL);
                if(g_iSSL){
    	            int iRet;
                    /*iRet = mosquitto_tls_opts_set(pMos, 1, "tlsv1", NULL);
                    if(iRet != 0){
                        printf("mosquitto_tls_opts_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
                    }
                    iRet = mosquitto_tls_insecure_set(	pMos, true);
                    if(iRet != 0){
                        printf("mosquitto_tls_insecure_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
                    }*/
                	iRet = mosquitto_tls_set(pMMos, "./ca.crt", NULL, NULL, NULL, NULL);
                    if(iRet != 0){
                        printf("mosquitto_tls_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
                    }
                    iRet = mosquitto_tls_opts_set(	pMMos, 0 ,NULL,NULL);
                    if(iRet != 0){
                        printf("mosquitto_tls_opts_set failed %d %s\n", iRet, mosquitto_strerror(iRet));
                    }
                }
                //mosquitto_log_callback_set(pMMos, my_log_callback);
                //mosquitto_subscribe_callback_set(pMMos, on_subscribe_manager);
    			mosquitto_connect_callback_set(pMMos, on_connect_manager);
    			//mosquitto_disconnect_callback_set(pMMos, on_disconnect);
                mosquitto_message_callback_set(pMMos, on_message_manager);
    			int rc = mosquitto_connect(pMMos, argv[1], atoi(argv[2]), 60);
    			if(rc != MOSQ_ERR_SUCCESS){
    				printf("manager connect failed");
    				return;
    			}
                while(g_iRun){
                    mosquitto_loop(pMMos, -1, 1);
                }
        });

    
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

#include <iostream>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include "MyEpoll.h"

EpollCB_t g_callbacks[FUNC_DEEP_MAX];
int g_cbHead = 0;


CEpoll::CEpoll()
{
    m_bInited = false;
}

CEpoll::~CEpoll()
{
    if(!m_bInited)
        return;
	if(epfd > 0)
	{
		close(epfd);
		epfd = -1;
	}
    
    m_bInited = false;
}
 
 
void CEpoll::Init(int iMaxEvent)
{
    if(m_bInited)
        return;
    epfd = epoll_create(iMaxEvent);
	if(epfd < 0)
	{
		std::cout << "create epoll handle err\n";
		return;
	}
    m_iMaxEvent = iMaxEvent;
    events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * iMaxEvent);
	memset(events, 0, sizeof(struct epoll_event)*iMaxEvent);
    m_bInited = true;
}
bool CEpoll::eventAdd(int	sockfd, bool readable, bool writeable, void* pData, EpollCB_t func)
{
	fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);
    int enable = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));
	if(sockfd < 0)
	{
		std::cout << "eventAdd the socket fd err\n";
		return false;
	}
    
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	//ev.events |= EPOLLET; //ET modle as default
	if(readable)
		ev.events |= EPOLLIN;
	if(writeable)
		ev.events |= EPOLLOUT;
    //printf("EPOLLIN 1, EPOLLOUT 4\n");
    EpollData *pEData = new EpollData;
    pEData->pUserData = pData;
    pEData->iFlag = ev.events;
    int iCbid=0;
    for (int i = 0; i < g_cbHead; i++) {
        if (g_callbacks[i] == func) {
            iCbid = i;
            break;
        }
    }
    if (iCbid == g_cbHead) {
        g_callbacks[g_cbHead++] = func;
    }
    pEData->iCbid = iCbid;
    assert(g_cbHead < FUNC_DEEP_MAX);
	ev.data.ptr = pEData;
    int iRet = epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    if(iRet != 0){
        perror("epoll_crl failed\n");
    }
	return iRet == 0;
}
 
void CEpoll::Del(int	sockfd)
{
    epoll_event event;
    epoll_ctl(epfd, EPOLL_CTL_DEL, sockfd, &event);
}
void CEpoll::doEpoll(int epollTimeout) {


    int numFdReady = epoll_wait(epfd, events, m_iMaxEvent, epollTimeout);

    for (int i = 0; i < numFdReady; i++) {
        g_callbacks[((EpollData*)events[i].data.ptr)->iCbid](((EpollData*)events[i].data.ptr)->pUserData, &events[i]);
    }

}


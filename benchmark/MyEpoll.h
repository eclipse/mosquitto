#include <sys/epoll.h>  
 

#define FUNC_DEEP_MAX 16

typedef int (*EpollCB_t)(void* pData, epoll_event* pEvent);
extern EpollCB_t g_callbacks[FUNC_DEEP_MAX];
extern int g_cbHead;

struct EpollData{
    void* pUserData;
    int iFlag;
    int iCbid;
};

class CEpoll
{
public:
    CEpoll();
    virtual ~CEpoll();
    void Init(int iMaxEvent);
    void doEpoll(int epollTimeout);
	bool eventAdd(int	sockfd, bool readable, bool writeable, void* pData, EpollCB_t func);
    void Del(int    sockfd);
	struct epoll_event *events;
    int m_iMaxEvent;
private:
	int epfd;
	bool m_bInited;
	CEpoll(const CEpoll&);
	CEpoll& operator=(const CEpoll&);
};
 

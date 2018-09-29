#include <map>
#include <string.h>
 

//typedef unsigned long long uint64_t;
typedef int (*TimeCallBack_t)(void* pData);
double get_now();

struct TimePoint{
    bool bIsInterval;
    uint64_t uTime; // ms
    uint64_t uInterval; // ms
    TimeCallBack_t vFunc;
    void * pData;
    TimePoint * pNext;
    TimePoint(){
        memset(this, 0, sizeof(*this));
    }
};

class MyTimer
{
public:
    MyTimer();
    ~MyTimer();
    void DoTimer();
    void AddTimerPoint(TimePoint *pvTimePoint);
	//void AddRandInterval(TimeCallBack_t vFunc, void * pData, uint64_t uInterval);
    void AddTimerPoint(TimeCallBack_t vFunc, void * pData, uint64_t uInterval, bool bLoop);
private:
	std::map<uint64_t, TimePoint*> m_vTimerMap;
	std::map<uint64_t, TimePoint*> m_vOnceTimerMap;
	MyTimer(const MyTimer&);
    int m_iMaxTaskOneRund;
};
 

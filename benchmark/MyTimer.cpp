#include "MyTimer.h"
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>

double get_now()
{
    struct timeval tt;
    gettimeofday(&tt,NULL);
    return (double)(tt.tv_sec) * 1000 + ((double)tt.tv_usec / 1000);
}

MyTimer::MyTimer(){
    m_iMaxTaskOneRund = 100;

}
MyTimer::~MyTimer(){

}
void MyTimer::DoTimer(){
    
    uint64_t uNow = get_now();
    int i = 0;
    for(auto vItemIter = m_vTimerMap.begin(); vItemIter != m_vTimerMap.end(); )
    {
        if(vItemIter->first > uNow)
            break;
        TimePoint *pvTimePoint;
        for(pvTimePoint = vItemIter->second; i < m_iMaxTaskOneRund && pvTimePoint !=NULL; ){
            pvTimePoint->vFunc(pvTimePoint->pData);
            i++;
            pvTimePoint = pvTimePoint->pNext;
        }
        if(i >= m_iMaxTaskOneRund && pvTimePoint != vItemIter->second && pvTimePoint){
            TimePoint *pvSaveTimePoint = vItemIter->second;
            vItemIter->second = pvTimePoint;
            TimePoint * pTmp = NULL;
            for(pTmp = pvSaveTimePoint; pTmp != NULL && pTmp->pNext != pvTimePoint; pTmp = pTmp->pNext);
            if(pTmp != NULL){
                pTmp->pNext = NULL;
            }
            pvSaveTimePoint->uTime = uNow + pvTimePoint->uInterval;
            AddTimerPoint(pvSaveTimePoint);
            return;
        }
        else{
            pvTimePoint = vItemIter->second;
            pvTimePoint->uTime = uNow + pvTimePoint->uInterval;
            AddTimerPoint(pvTimePoint);
        }
        m_vTimerMap.erase(vItemIter++);
    }
    for(auto vItemIter = m_vOnceTimerMap.begin(); i < m_iMaxTaskOneRund && vItemIter != m_vOnceTimerMap.end(); )
    {
        if(vItemIter->first > uNow)
            break;
        TimePoint *pvTimePoint;
        for(pvTimePoint = vItemIter->second; i < m_iMaxTaskOneRund && pvTimePoint !=NULL; ){
            pvTimePoint->vFunc(pvTimePoint->pData);
            i++;
            TimePoint *pTmp = pvTimePoint;
            pvTimePoint = pvTimePoint->pNext;
            delete pTmp;
        }
        if(pvTimePoint){
                vItemIter->second = pvTimePoint;
                break;
        }
        m_vOnceTimerMap.erase(vItemIter++);
    }
}

void MyTimer::AddTimerPoint(TimePoint *pvTimePoint)
{
    if(!pvTimePoint)
        return;
    
    std::map<uint64_t, TimePoint*> * pvTimer;
    if(pvTimePoint->bIsInterval){
        pvTimer = &m_vTimerMap;
    }
    else{
        pvTimer = &m_vOnceTimerMap;
    }
    auto vItemIter = pvTimer->find(pvTimePoint->uTime);
    if(vItemIter == pvTimer->end())
    {
        (*pvTimer)[pvTimePoint->uTime] = pvTimePoint;
    }
    else{
        TimePoint *pvT=vItemIter->second;
        for(; pvT != NULL && pvT->pNext != NULL; pvT = pvT->pNext);/*{
            if(pvT == pvTimePoint){
                return;
            }
        }*/
        pvT->pNext = pvTimePoint;
    }
}

void MyTimer::AddTimerPoint(TimeCallBack_t vFunc, void * pData, uint64_t uInterval, bool bLoop)
{
    uint64_t uNow = get_now();
    if(uInterval > 0){
        uNow += rand() % uInterval;
        if(bLoop){
            uNow += rand() % uInterval;
            uNow += rand() % uInterval;
            uNow += rand() % uInterval;
            uNow += rand() % uInterval;
            uNow += rand() % uInterval;
        }
    }
    TimePoint *pvTimePoint = new TimePoint;
    pvTimePoint->uTime = uNow;
    pvTimePoint->bIsInterval = bLoop;
    pvTimePoint->pData = pData;
    pvTimePoint->uInterval = uInterval;
    pvTimePoint->vFunc = vFunc;
    pvTimePoint->pNext = NULL;
    AddTimerPoint(pvTimePoint);
    return;
}



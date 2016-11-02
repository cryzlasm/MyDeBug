// DeBug.h: interface for the CDeBug class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_DEBUG_H__CCFCD8C7_A313_4B5F_9343_626594F87C8E__INCLUDED_)
#define AFX_DEBUG_H__CCFCD8C7_A313_4B5F_9343_626594F87C8E__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "stdafx.h"
#include "TagDeal.h"
#include "ResolveCMD.h"
#include "Decode2Asm.h"

#include <afxtempl.h>
#include <COMDEF.H>

#pragma comment(lib, "Decode2Asm.lib")

//=========================================================================
#define CONTEXT_ALL             (CONTEXT_CONTROL | CONTEXT_INTEGER | \
    CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | \
CONTEXT_DEBUG_REGISTERS)

typedef HANDLE (__stdcall *PFN_OpenThread)(
                                           DWORD dwDesiredAccess,  // access right
                                           BOOL bInheritHandle,    // handle inheritance option
                                           DWORD dwThreadId        // thread identifier
                                           );

#define _OUT_       //输出参数
#define _IN_        //输入参数
//=========================================================================
using namespace std;
#ifdef _UNICODE
#define tcout wcout
#define tcin  wcin

#else
#define tcout cout
#define tcin  cin

#endif
//=========================================================================

class CDeBug  
{
public:
    CDeBug();
    virtual ~CDeBug();
    BOOL GetFun();                      //获取OpenThread
    BOOL Start(_IN_ TCHAR* argv[]);		//程序开始
    BOOL EventLoop();                   //事件消息循环
    BOOL Interaction(LPVOID lpAddr);                 //人机交互
    BOOL GetUserInput(CMD_INFO& CmdInfo);                //获取用户输入, 带出输入状态
    BOOL HandleCmd(CMD_INFO& CmdInfo, LPVOID lpAddr);          //执行命令
    
    //写入远程字节，返回旧字节
    BOOL WriteRemoteCode(_IN_ LPVOID lpRemoteAddr, _IN_ DWORD btInChar, _OUT_ DWORD& pbtOutChar);
    //判断地址是否在链表中
    BOOL IsAddrInBpList(_IN_ LPVOID lpAddr, _IN_ CList<PMYBREAK_POINT, PMYBREAK_POINT&>& bpSrcLst, _OUT_ POSITION& dwOutPos);
    
    BOOL OnExceptionEvent();        //处理异常事件
    
    BOOL OnCreateProcessEvent();    //处理创建进程事件
    
    BOOL OnLoadDll();               //模块加载
    BOOL OnUnLoadDll();             //模块卸载
    BOOL ShowDllLst();              //显示当前存在的模块信息
    
    BOOL OnBreakPointEvent();       //一般断点
    BOOL OnSingleStepEvent();       //单步异常
    BOOL OnAccessVolationEvent();   //内存访问异常
    
    //显示当前所有调试信息,默认显示一条
    BOOL ShowCurAllDbg(LPVOID lpAddr, DWORD dwState = CMD_SHOWONCE);    
    
    BOOL ShowRemoteMem(LPVOID lpAddr);           //显示远程内存
    BOOL ShowRemoteReg();                        //显示远程寄存器
    BOOL ShowRemoteDisAsm(LPVOID lpAddr, DWORD dwCount = 10);        //显示远程反汇编


    static void __stdcall OutErrMsg(_IN_ LPCTSTR strErrMsg);    //输出错误信息
private:
    CResolveCMD m_CMD;          //解析CMD

    DWORD m_dwErrCount;           //错误计数, 十次错误
    
    DEBUG_EVENT m_DbgEvt;   //目标进程调试事件
    CONTEXT m_DstContext;   //目标进程上下文
    HANDLE m_hDstProcess;   //目标进程当前进程句柄
    HANDLE m_hDstThread;    //目标进程当前线程

    CList<PMODLST, PMODLST&>   m_ModuleLst;     //模块链表
    CList<PMYBREAK_POINT, PMYBREAK_POINT&> m_BreakPoint;    //一般断点列表
    CList<PMYBREAK_POINT, PMYBREAK_POINT&> m_SingleStep;    //单步断点列表
    
    PFN_OpenThread m_pfnOpenThread;
};

#endif // !defined(AFX_DEBUG_H__CCFCD8C7_A313_4B5F_9343_626594F87C8E__INCLUDED_)

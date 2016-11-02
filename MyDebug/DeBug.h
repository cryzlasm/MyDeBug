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

#define _OUT_       //�������
#define _IN_        //�������
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
    BOOL GetFun();                      //��ȡOpenThread
    BOOL Start(_IN_ TCHAR* argv[]);		//����ʼ
    BOOL EventLoop();                   //�¼���Ϣѭ��
    BOOL Interaction(LPVOID lpAddr);                 //�˻�����
    BOOL GetUserInput(CMD_INFO& CmdInfo);                //��ȡ�û�����, ��������״̬
    BOOL HandleCmd(CMD_INFO& CmdInfo, LPVOID lpAddr);          //ִ������
    
    //д��Զ���ֽڣ����ؾ��ֽ�
    BOOL WriteRemoteCode(_IN_ LPVOID lpRemoteAddr, _IN_ DWORD btInChar, _OUT_ DWORD& pbtOutChar);
    //�жϵ�ַ�Ƿ���������
    BOOL IsAddrInBpList(_IN_ LPVOID lpAddr, _IN_ CList<PMYBREAK_POINT, PMYBREAK_POINT&>& bpSrcLst, _OUT_ POSITION& dwOutPos);
    
    BOOL OnExceptionEvent();        //�����쳣�¼�
    
    BOOL OnCreateProcessEvent();    //�����������¼�
    
    BOOL OnLoadDll();               //ģ�����
    BOOL OnUnLoadDll();             //ģ��ж��
    BOOL ShowDllLst();              //��ʾ��ǰ���ڵ�ģ����Ϣ
    
    BOOL OnBreakPointEvent();       //һ��ϵ�
    BOOL OnSingleStepEvent();       //�����쳣
    BOOL OnAccessVolationEvent();   //�ڴ�����쳣
    
    //��ʾ��ǰ���е�����Ϣ,Ĭ����ʾһ��
    BOOL ShowCurAllDbg(LPVOID lpAddr, DWORD dwState = CMD_SHOWONCE);    
    
    BOOL ShowRemoteMem(LPVOID lpAddr);           //��ʾԶ���ڴ�
    BOOL ShowRemoteReg();                        //��ʾԶ�̼Ĵ���
    BOOL ShowRemoteDisAsm(LPVOID lpAddr, DWORD dwCount = 10);        //��ʾԶ�̷����


    static void __stdcall OutErrMsg(_IN_ LPCTSTR strErrMsg);    //���������Ϣ
private:
    CResolveCMD m_CMD;          //����CMD

    DWORD m_dwErrCount;           //�������, ʮ�δ���
    
    DEBUG_EVENT m_DbgEvt;   //Ŀ����̵����¼�
    CONTEXT m_DstContext;   //Ŀ�����������
    HANDLE m_hDstProcess;   //Ŀ����̵�ǰ���̾��
    HANDLE m_hDstThread;    //Ŀ����̵�ǰ�߳�

    CList<PMODLST, PMODLST&>   m_ModuleLst;     //ģ������
    CList<PMYBREAK_POINT, PMYBREAK_POINT&> m_BreakPoint;    //һ��ϵ��б�
    CList<PMYBREAK_POINT, PMYBREAK_POINT&> m_SingleStep;    //�����ϵ��б�
    
    PFN_OpenThread m_pfnOpenThread;
};

#endif // !defined(AFX_DEBUG_H__CCFCD8C7_A313_4B5F_9343_626594F87C8E__INCLUDED_)

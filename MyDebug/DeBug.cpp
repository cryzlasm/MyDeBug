// DeBug.cpp: implementation of the CDeBug class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "MyDebug.h"
#include "DeBug.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
void __stdcall CDeBug::OutErrMsg(LPCTSTR strErrMsg)
{
    OutputDebugString(strErrMsg);
}

CDeBug::CDeBug()
{
    memset(&m_DbgEvt, 0, sizeof(DEBUG_EVENT));
    memset(&m_DstContext, 0, sizeof(CONTEXT));
    m_hDstProcess = INVALID_HANDLE_VALUE;
    m_hDstThread = INVALID_HANDLE_VALUE;

    m_pfnOpenThread = NULL;

    m_dwErrCount = 0;
}

CDeBug::~CDeBug()
{
    POSITION pos = m_ModuleLst.GetHeadPosition();
    POSITION posTmp = NULL;
    while(pos)
    {
        posTmp = pos;
        PMODLST pMod = m_ModuleLst.GetNext(pos);
        if(pMod != NULL)
        {
            delete pMod;
            m_ModuleLst.RemoveAt(posTmp);
        }
    }

    pos = m_BreakPoint.GetHeadPosition();
    while(pos)
    {
        posTmp = pos;
        PMYBREAK_POINT pBp = m_BreakPoint.GetNext(pos);
        if(pBp != NULL)
        {
            delete pBp;
            m_BreakPoint.RemoveAt(posTmp);
        }
    }
}

BOOL CDeBug::GetFun()
{

    m_pfnOpenThread = (PFN_OpenThread)GetProcAddress(
                                    LoadLibrary("Kernel32.dll"), 
                                    "OpenThread");
    if(m_pfnOpenThread == NULL)
    {
        tcout << TEXT("��ȡ����ʧ�ܣ�����ϵ����Ա��") << endl;
        return FALSE;
    }

    return TRUE;
}

BOOL CDeBug::Start(TCHAR* argv[])			//����ʼ
{
    BOOL bRet = FALSE;
    CString strArgv = argv[1];
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if(strArgv.Find(TEXT(".exe")) == -1)
    {
        //�������Թ�ϵ
        bRet = CreateProcess(NULL, 
                             argv[1], 
                            NULL,
                            NULL,
                            FALSE,
                            DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                            NULL,
                            NULL,
                            &si,
                            &pi);
        if(bRet == FALSE)
        {
            tcout << TEXT("��������ȷ�ı����Գ�������") << endl;
            return FALSE;
        }
    }

    if(!GetFun())
        return FALSE;

    EventLoop();

    return TRUE;
}

BOOL CDeBug::EventLoop()       //��Ϣѭ��
{
    DWORD dwState = DBG_EXCEPTION_NOT_HANDLED;
    BOOL bRet = FALSE;

    while(TRUE == WaitForDebugEvent(&m_DbgEvt, INFINITE))
    {
        if(m_dwErrCount > 10)
        {
            tcout << TEXT("����������࣬����ϵ����Ա��") << endl;
            break;
        }

        m_hDstProcess = OpenProcess(PROCESS_ALL_ACCESS, 
                                    FALSE, 
                                    m_DbgEvt.dwProcessId);
        if(m_hDstProcess == NULL)
        {
            tcout << TEXT("�򿪵��Խ���ʧ�ܣ�") << endl;
            m_dwErrCount++;
            continue;
        }

        m_hDstThread = m_pfnOpenThread(THREAD_ALL_ACCESS, 
                                       FALSE, 
                                       m_DbgEvt.dwThreadId);
        if(m_hDstThread == NULL)
        {
            tcout << TEXT("�򿪵��Խ���ʧ�ܣ�") << endl;
            m_dwErrCount++;
            continue;
        }


        m_DstContext.ContextFlags = CONTEXT_ALL;
        GetThreadContext(m_hDstThread, &m_DstContext);
        
        switch(m_DbgEvt.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
            tcout << TEXT("EXCEPTION_DEBUG_EVENT") << endl;

            bRet = OnExceptionEvent();

            break;
        case CREATE_THREAD_DEBUG_EVENT:		
            tcout << TEXT("CREATE_THREAD_DEBUG_EVENT") << endl;

            //bRet = OnCreateThreadEvent();

            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            //tcout << TEXT("CREATE_PROCESS_DEBUG_EVENT") << endl;
            
            bRet = OnCreateProcessEvent();

            break;

        case EXIT_THREAD_DEBUG_EVENT:		
            tcout << TEXT("EXIT_THREAD_DEBUG_EVENT") << endl;
            break;

        case EXIT_PROCESS_DEBUG_EVENT:	
            tcout << TEXT("EXIT_PROCESS_DEBUG_EVENT") << endl;	
            return TRUE;

        case LOAD_DLL_DEBUG_EVENT:	
            bRet = OnLoadDll();

            //tcout << TEXT("LOAD_DLL_DEBUG_EVENT") << endl;		
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            //tcout << TEXT("UNLOAD_DLL_DEBUG_EVENT") << endl;
            bRet = OnUnLoadDll();
            break;

        case OUTPUT_DEBUG_STRING_EVENT:	
            tcout << TEXT("OUTPUT_DEBUG_STRING_EVENT") << endl;		
            break;

        default:
            break;
        }

        //����Ѿ������򷵻��Ѵ�������Ĭ�Ϸ���û����
        if(bRet)
            dwState = DBG_CONTINUE;
        
        //m_DstContext.Dr6 = 0;
        
        //�����߳�������
        if(!SetThreadContext(m_hDstThread, &m_DstContext))
        {
            tcout << TEXT("�����߳���Ϣʧ�ܣ�����ϵ����Ա") << endl;
        }
        
        //�رս��̾��
        if (m_hDstProcess != NULL)
        {
            CloseHandle(m_hDstProcess);
            m_hDstProcess = NULL;
        }

        //�ر��߳̾��
        if (m_hDstThread != NULL)
        {
            CloseHandle(m_hDstThread);
            m_hDstThread = NULL;
        }
        
        //���ô���״̬
        if(ContinueDebugEvent(m_DbgEvt.dwProcessId, 
            m_DbgEvt.dwThreadId, 
            dwState) == FALSE)
        {
            break;
        }
    }//End While
    
    return TRUE;
}

#define MAX_MEM 0x80000000
BOOL CDeBug::Interaction(LPVOID lpAddr)                //�˻�����
{   
    //����ַ�Ƿ�Խ��
    if((DWORD)lpAddr >= MAX_MEM)
    {
        tcout << TEXT("��Ч���򣬳���������գ�") << endl;
        return TRUE;
    }

    //��ʾ��ǰ������Ϣ
    if(!ShowCurAllDbg(lpAddr))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("Interaction��δ֪������ʾ����"));
        return FALSE;
    }

    //��ʼ����ȡ�û�����
    CMD_INFO CmdInfo;
    ZeroMemory(&CmdInfo, sizeof(CMD_INFO));
    CmdInfo.dwState = CMD_INVALID;

    //��ȡ�û�����
    if(!GetUserInput(CmdInfo))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("Interaction��δ֪�����������"));
        return FALSE;
    }

    //�����û�����
    if(!HandleCmd(CmdInfo, lpAddr))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("Interaction��δ֪����ִ�д���"));
        return FALSE;
    }

    return TRUE;
}

BOOL CDeBug::HandleCmd(CMD_INFO& CmdInfo, LPVOID lpAddr)          //ִ������
{
    return TRUE;
}

#define MAX_INPUT   32
BOOL CDeBug::GetUserInput(CMD_INFO& CmdInfo)
{
    try
    {   
        //��ȡ����
        TCHAR szBuf[MAX_INPUT] = {0};
        tcout << TEXT('-');
        tcin.getline(szBuf, MAX_INPUT, TEXT('\n'));
        tcin.clear();
        tcin.sync();

        //��������
        CmdInfo.strCMD = szBuf;
        
        //����Сд
        CmdInfo.strCMD.MakeLower();
        
        //ת��Ϊ������
        m_CMD.Resolve(CmdInfo);
    }
    catch(...)
    {
        return FALSE;
    }

    return TRUE;
}

BOOL CDeBug::OnBreakPointEvent()       //һ��ϵ�
{
    //static BOOL bIsFirstInto = TRUE;
    EXCEPTION_RECORD& pExceptionRecord = m_DbgEvt.u.Exception.ExceptionRecord; 
    POSITION pos = NULL;

//     //��һ��������ϵͳ�ϵ㣬���ڶ�����ڵ�
//     if(bIsFirstInto)
//     {
//         if(IsAddrInBpList(pExceptionRecord.ExceptionAddress, m_BreakPoint, pos))
//         {
//             PMYBREAK_POINT bp = m_BreakPoint.GetAt(pos);
//             if(WriteRemoteCode(bp->lpAddr, bp->dwOldOrder, bp->dwCurOrder))
//             {
//                 m_BreakPoint.RemoveAt(pos);
//                 delete bp;
//             }
//         }
//         ShowCurAll(pExceptionRecord.ExceptionAddress);
//         Interaction(pExceptionRecord.ExceptionAddress);
//         bIsFirstInto = FALSE;
//         return TRUE;
//     }

    //�����ϵ�
    if(IsAddrInBpList(pExceptionRecord.ExceptionAddress, m_BreakPoint, pos))
    {
        PMYBREAK_POINT bp = m_BreakPoint.GetAt(pos);
        //��ԭ����
        if(!WriteRemoteCode(bp->lpAddr, bp->dwOldOrder, bp->dwCurOrder))
        {
            return FALSE;
        }

        //�޸�Ŀ���߳�EIP
        m_DstContext.Eip = m_DstContext.Eip - 1;
        
        //ϵͳһ���Զϵ㣬���ڶ�����ڵ�
        if(bp->dwState == BP_SYS)
        {
            m_BreakPoint.RemoveAt(pos);
            delete bp;
        }
        //����ϵ�
        else if(bp->dwState == BP_NORMAL)
        {
            //���õ�����־λ
            m_DstContext.EFlags |= 0x100;
            
            bp->bIsSingleStep = TRUE;
        }

        Interaction(pExceptionRecord.ExceptionAddress);

        return TRUE;
    }

    return FALSE;
}

BOOL CDeBug::OnSingleStepEvent()       //�����쳣
{
    EXCEPTION_RECORD& pExceptionRecord = m_DbgEvt.u.Exception.ExceptionRecord; 
    POSITION pos = NULL;

    //�����ϵ�
    if(IsAddrInBpList(pExceptionRecord.ExceptionAddress, m_BreakPoint, pos))
    {
        PMYBREAK_POINT bp = m_BreakPoint.GetAt(pos);
        if(bp->bIsSingleStep == TRUE)
        {
            //����ϵ�
            if(!WriteRemoteCode(bp->lpAddr, bp->dwCurOrder, bp->dwOldOrder))
            {
                return FALSE;
            }
            //�޸�Ŀ���߳�EIP
            m_DstContext.Eip = m_DstContext.Eip - 1;
        
            //���õ�����־λ
            m_DstContext.EFlags |= 0x100;
            
            bp->bIsSingleStep = FALSE;
        
            return TRUE;
        }
    }

    return FALSE;
}

BOOL CDeBug::OnAccessVolationEvent()   //�ڴ�����쳣
{
    
    


    return FALSE;
}

BOOL CDeBug::ShowCurAllDbg(LPVOID lpAddr, DWORD dwState)  //��ʾ��ǰ���е�����Ϣ
{
    //ShowRemoteMem(lpAddr);
    ShowRemoteReg();
    DWORD dwCount = 1;

    if(dwState != CMD_SHOWONCE)
        dwCount = 10;

    //��ʾ�����
    if(!ShowRemoteDisAsm(lpAddr, dwCount))
        return FALSE;

    return TRUE;
}

#define RemoteOneReadSize 0x60  //һ�ζ�ȡԶ�����ݵĳ���
BOOL CDeBug::ShowRemoteMem(LPVOID lpAddr)           //��ʾԶ���ڴ�
{
    DWORD dwAddr = (DWORD)lpAddr;
    DWORD dwRead = 0;
    UCHAR szBuf[RemoteOneReadSize] = {0};
    PUCHAR pszBuf = szBuf;
    
    //��ȡԶ���ڴ���Ϣ
    if(!ReadProcessMemory(m_hDstProcess, lpAddr, szBuf, RemoteOneReadSize, &dwRead))
    {
        OutErrMsg(TEXT("ShowRemoteDisAsm����ȡԶ���ڴ�ʧ�ܣ�"));
        return FALSE;
    }
    
    //����ڴ���Ϣ
    int nCount = dwRead / 0X10;
    for(int i = 0; i < nCount; i++)
    {
        //�����ַ
        _tprintf(TEXT("%08X   "), dwAddr);
        //tcout << ios::hex << dwAddr << TEXT("    ");

        //���ʮ������ֵ
        for(int j = 0; j < 0x10; j++)
        {
            _tprintf(TEXT("%02X "), pszBuf[j]);
            //tcout << ios::hex << pszBuf[j] << TEXT(' ');
        }

        tcout << TEXT("  ");

        //��������ַ���
        for(int n = 0; n < 0x10; n++)
        {
            putchar(pszBuf[n]);
        }
        
        //���س�����
        tcout << endl;

        dwAddr += 0x10;
        pszBuf += 0x10;
    }
    
    return TRUE;
}

BOOL CDeBug::ShowRemoteReg()           //��ʾԶ�̼Ĵ���
{
// EAX=00000000   EBX=00000000   ECX=B2A10000   EDX=0008E3C8   ESI=FFFFFFFE
// EDI=00000000   EIP=7703103C   ESP=0018FB08   EBP=0018FB34   DS =0000002B
// ES =0000002B   SS =0000002B   FS =00000053   GS =0000002B   CS =00000023
    //��ȡEFlags
    EFLAGS& eFlags = *(PEFLAGS)&m_DstContext.EFlags;

    CONTEXT& text = m_DstContext;
    _tprintf(TEXT("EAX=%08X   EBX=%08X   ECX=%08X   EDX=%08X   ESI=%08X\r\n"),
                 text.Eax,
                 text.Ebx,
                 text.Ecx,
                 text.Edx,
                 text.Esi);

    _tprintf(TEXT("EDI=%08X   EIP=%08X   ESP=%08X   EBP=%08X   DS =%08X\r\n"),
                 text.Edi,
                 text.Eip,
                 text.Esp,
                 text.Ebp,
                 text.SegDs);

    _tprintf(TEXT("ES =%08X   SS =%08X   FS =%08X   GS =%08X   CS =%08X\r\n"),
                 text.SegEs,
                 text.SegSs,
                 text.SegFs,
                 text.SegGs,
                 text.SegCs);

    _tprintf(TEXT("OF   DF   IF   TF   SF   ZF   AF   PF   CF\r\n"));

    _tprintf(TEXT("%02d   %02d   %02d   %02d   %02d   %02d   %02d   %02d   %02d\r\n\r\n"),
                eFlags.dwOF,
                eFlags.dwDF,
                eFlags.dwIF,
                eFlags.dwTF,
                eFlags.dwSF,
                eFlags.dwZF,
                eFlags.dwAF,
                eFlags.dwPF,
                eFlags.dwCF);

    return TRUE;
}


#define OneAsmSize 10
BOOL CDeBug::ShowRemoteDisAsm(LPVOID lpAddr, DWORD dwCount)        //��ʾԶ�̷����
{
    DWORD dwRead = 0;
    UCHAR szBuf[MAXBYTE] = {0};
    
    BOOL bRet = FALSE;
    DWORD dwReadLen = 0;
    BYTE btCode[MAXBYTE] = {0};
    char szAsmBuf[MAXBYTE] = {0};
    char szOpcodeBuf[MAXBYTE] = {0};
    unsigned int nCodeSize = 0;
    unsigned int nCount = 0;
    DWORD nCodeAddress = (DWORD)lpAddr;
    PBYTE pCode = szBuf;
    char szFmt[MAXBYTE *2] = {0};

    //��ȡԶ����Ϣ
    if(!ReadProcessMemory(m_hDstProcess, lpAddr, szBuf, RemoteOneReadSize, &dwRead))
    {
        OutErrMsg(TEXT("ShowRemoteDisAsm����ȡԶ���ڴ�ʧ�ܣ�"));
        return FALSE;
    }

    //ת��5�������
    DWORD dwRemaining = 0;
    while(nCount < dwCount)
    {
        Decode2AsmOpcode(pCode, szAsmBuf, szOpcodeBuf,
            &nCodeSize, (DWORD)nCodeAddress);

        _tprintf(TEXT("%p:%s"),nCodeAddress, szOpcodeBuf);
        
        dwRemaining = 0x18 - _tcsclen(szOpcodeBuf);
        //���ո�
        while(dwRemaining--)
        {
            putchar(' ');
        }
        
        puts(szAsmBuf);

        
        pCode += nCodeSize;
        nCount++;
        nCodeAddress += nCodeSize;
    }

    return TRUE;
}

BOOL CDeBug::OnExceptionEvent()
{
    BOOL bRet = FALSE;
    EXCEPTION_RECORD& pExceptionRecord = m_DbgEvt.u.Exception.ExceptionRecord; 
    switch(pExceptionRecord.ExceptionCode)
    {
    case EXCEPTION_BREAKPOINT:          //�ϵ�
        bRet = OnBreakPointEvent();
        break;

    case EXCEPTION_SINGLE_STEP:         //����
        bRet = OnSingleStepEvent();
        break;

    case EXCEPTION_ACCESS_VIOLATION:    //C05
        bRet = OnAccessVolationEvent();
        break;

    }
    
    return bRet;
}

BOOL CDeBug::OnCreateProcessEvent()
{
    //������ڵ�ϵ㣬
    CREATE_PROCESS_DEBUG_INFO& pCreateEvent = m_DbgEvt.u.CreateProcessInfo;
    LPVOID lpEntryPoint = pCreateEvent.lpStartAddress;

    PMYBREAK_POINT ptagBp = new MYBREAK_POINT;
    ZeroMemory(ptagBp, sizeof(MYBREAK_POINT));

    ptagBp->dwState = BP_SYS;
    ptagBp->lpAddr = lpEntryPoint;
    ptagBp->dwCurOrder = NORMAL_CC;

    if(!WriteRemoteCode(lpEntryPoint, ptagBp->dwCurOrder, ptagBp->dwOldOrder))
    {
        tcout << TEXT("ϵͳ�ϵ�: ����BUG������ϵ����Ա��") << endl;

        //�ͷ���Դ
        if(ptagBp != NULL)
            delete ptagBp;

        return FALSE;
    }

    //��Ӷϵ�ڵ�
    m_BreakPoint.AddTail(ptagBp);

    return TRUE;
}

BOOL CDeBug::IsAddrInBpList(LPVOID lpAddr, 
                            CList<PMYBREAK_POINT, PMYBREAK_POINT&>& bpSrcLst, 
                            _OUT_ POSITION& dwOutPos)
{
    BOOL bRet = FALSE;
    POSITION pos = bpSrcLst.GetHeadPosition();
    POSITION posTmp = NULL;

    //��������
    while(pos)
    {
        posTmp = pos;
        MYBREAK_POINT& bp = *bpSrcLst.GetNext(pos);
        if(bp.lpAddr == lpAddr)
        {
            bRet = TRUE;
            //���ҵ�
            dwOutPos = posTmp;
            break;
        }
    }

    return bRet;
}

BOOL CDeBug::ShowDllLst()
{
    POSITION pos = m_ModuleLst.GetHeadPosition();
    tcout << TEXT("==============================================================") << endl;
    //��������
    while(pos)
    {
        
        MODLST& ModLst = *m_ModuleLst.GetNext(pos);
        tcout << TEXT("��ַ:") << ModLst.dwBaseAddr << TEXT("\t")
              << TEXT("·��:") << ModLst.strPath << endl;
    }
    tcout << TEXT("==============================================================") << endl;
    return TRUE;
}

BOOL CDeBug::OnUnLoadDll()
{
    BOOL bRet = FALSE;
    POSITION pos = m_ModuleLst.GetHeadPosition();
    POSITION posTmp = NULL;

    //��������
    while(pos)
    {
        posTmp = pos;
        PMODLST pModLst = m_ModuleLst.GetNext(pos);
        if(m_DbgEvt.u.UnloadDll.lpBaseOfDll == (LPVOID)pModLst->dwBaseAddr)
        {
            if(pModLst != NULL)
            {
                delete pModLst;
                m_ModuleLst.RemoveAt(posTmp);
            }
            bRet = TRUE;
            break;
        }

    }
    return bRet;
}

BOOL CDeBug::OnLoadDll()
{
    TCHAR szBuf[MAX_PATH * 2] = {0};
    LPVOID lpString = NULL;

    //��������ڵ�
    LOAD_DLL_DEBUG_INFO& DllInfo = m_DbgEvt.u.LoadDll;    
    if(DllInfo.lpImageName == NULL)
    {
        return FALSE;
    }

    PMODLST pModLst = new MODLST;
    //RtlZeroMemory(pModLst, sizeof(MODLST));
    if(pModLst == NULL)
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("OnLoadDll������ڵ�ʧ�ܣ�"));
        return FALSE;
    }
    
    //����DLL ��ַ
    pModLst->dwBaseAddr = (DWORD)DllInfo.lpBaseOfDll;
    
    //��ȡDLL ��ַ
    if (ReadProcessMemory(m_hDstProcess, DllInfo.lpImageName, \
        &lpString, sizeof(LPVOID), NULL) == NULL)
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("OnLoadDll����ȡԶ�̵�ַʧ�ܣ�"));
        return FALSE;
    }
    
    //��ȡDLL·��
    if (ReadProcessMemory(m_hDstProcess, lpString, szBuf, \
        sizeof(szBuf) / sizeof(TCHAR), NULL) == NULL)
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("OnLoadDll����ȡģ��·��ʧ�ܣ�"));
        return FALSE;
	}
    

    //ascii
    if(!DllInfo.fUnicode)
    {
        pModLst->strPath = szBuf;
    }
    //unicode
    else
    {
        //ת��UNICODEΪASCII
        _bstr_t bstrPath = (wchar_t*)szBuf;
        pModLst->strPath = (LPCTSTR)bstrPath;
    }

    m_ModuleLst.AddTail(pModLst);

    return TRUE;
}

BOOL CDeBug::WriteRemoteCode(LPVOID lpRemoteAddr, DWORD btInChar, DWORD& pbtOutChar)
{
    DWORD dwOldProtect = 0;
    DWORD dwReadLen = 0;
    
    //����ڴ汣������
    if(!VirtualProtectEx(m_hDstProcess, lpRemoteAddr, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("WriteRemoteCode����ȡ��������ʧ�ܣ�"));
        return FALSE;
    }

    //��ȡ�ɴ��벢����
    if(!ReadProcessMemory(m_hDstProcess, lpRemoteAddr, &pbtOutChar, sizeof(BYTE), &dwReadLen))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("WriteRemoteCode����ȡԶ���ڴ�ʧ�ܣ�"));
        return FALSE;
    }

    //д���´���
    if(!WriteProcessMemory(m_hDstProcess, lpRemoteAddr, &btInChar, sizeof(BYTE), &dwReadLen))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("WriteRemoteCode��д��Զ���ڴ�ʧ�ܣ�"));
        return FALSE;
    }
    
    //��ԭ�ڴ汣������
    if(!VirtualProtectEx(m_hDstProcess, lpRemoteAddr, 1, dwOldProtect, &dwOldProtect))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("WriteRemoteCode����ԭ��������ʧ�ܣ�"));
        return FALSE;
    }

    return TRUE;
}

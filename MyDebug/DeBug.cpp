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
        tcout << TEXT("获取函数失败！请联系管理员！") << endl;
        return FALSE;
    }

    return TRUE;
}

BOOL CDeBug::Start(TCHAR* argv[])			//程序开始
{
    BOOL bRet = FALSE;
    CString strArgv = argv[1];
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if(strArgv.Find(TEXT(".exe")) == -1)
    {
        //建立调试关系
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
            tcout << TEXT("请输入正确的被调试程序名！") << endl;
            return FALSE;
        }
    }

    if(!GetFun())
        return FALSE;

    EventLoop();

    return TRUE;
}

BOOL CDeBug::EventLoop()       //消息循环
{
    DWORD dwState = DBG_EXCEPTION_NOT_HANDLED;
    BOOL bRet = FALSE;

    while(TRUE == WaitForDebugEvent(&m_DbgEvt, INFINITE))
    {
        if(m_dwErrCount > 10)
        {
            tcout << TEXT("错误次数过多，请联系管理员！") << endl;
            break;
        }

        m_hDstProcess = OpenProcess(PROCESS_ALL_ACCESS, 
                                    FALSE, 
                                    m_DbgEvt.dwProcessId);
        if(m_hDstProcess == NULL)
        {
            tcout << TEXT("打开调试进程失败！") << endl;
            m_dwErrCount++;
            continue;
        }

        m_hDstThread = m_pfnOpenThread(THREAD_ALL_ACCESS, 
                                       FALSE, 
                                       m_DbgEvt.dwThreadId);
        if(m_hDstThread == NULL)
        {
            tcout << TEXT("打开调试进程失败！") << endl;
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

        //如果已经处理，则返回已处理，否则默认返回没处理
        if(bRet)
            dwState = DBG_CONTINUE;
        
        //m_DstContext.Dr6 = 0;
        
        //设置线程上下文
        if(!SetThreadContext(m_hDstThread, &m_DstContext))
        {
            tcout << TEXT("设置线程信息失败，请联系管理员") << endl;
        }
        
        //关闭进程句柄
        if (m_hDstProcess != NULL)
        {
            CloseHandle(m_hDstProcess);
            m_hDstProcess = NULL;
        }

        //关闭线程句柄
        if (m_hDstThread != NULL)
        {
            CloseHandle(m_hDstThread);
            m_hDstThread = NULL;
        }
        
        //设置处理状态
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
BOOL CDeBug::Interaction(LPVOID lpAddr)                //人机交互
{   
    //检查地址是否越界
    if((DWORD)lpAddr >= MAX_MEM)
    {
        tcout << TEXT("无效区域，超出程序领空！") << endl;
        return TRUE;
    }

    //显示当前调试信息
    if(!ShowCurAllDbg(lpAddr))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("Interaction：未知程序显示错误！"));
        return FALSE;
    }

    //初始化获取用户输入
    CMD_INFO CmdInfo;
    ZeroMemory(&CmdInfo, sizeof(CMD_INFO));
    CmdInfo.dwState = CMD_INVALID;

    //获取用户输入
    if(!GetUserInput(CmdInfo))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("Interaction：未知程序输入错误！"));
        return FALSE;
    }

    //处理用户输入
    if(!HandleCmd(CmdInfo, lpAddr))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("Interaction：未知程序执行错误！"));
        return FALSE;
    }

    return TRUE;
}

BOOL CDeBug::HandleCmd(CMD_INFO& CmdInfo, LPVOID lpAddr)          //执行命令
{
    return TRUE;
}

#define MAX_INPUT   32
BOOL CDeBug::GetUserInput(CMD_INFO& CmdInfo)
{
    try
    {   
        //获取输入
        TCHAR szBuf[MAX_INPUT] = {0};
        tcout << TEXT('-');
        tcin.getline(szBuf, MAX_INPUT, TEXT('\n'));
        tcin.clear();
        tcin.sync();

        //缓存命令
        CmdInfo.strCMD = szBuf;
        
        //命令小写
        CmdInfo.strCMD.MakeLower();
        
        //转换为操作码
        m_CMD.Resolve(CmdInfo);
    }
    catch(...)
    {
        return FALSE;
    }

    return TRUE;
}

BOOL CDeBug::OnBreakPointEvent()       //一般断点
{
    //static BOOL bIsFirstInto = TRUE;
    EXCEPTION_RECORD& pExceptionRecord = m_DbgEvt.u.Exception.ExceptionRecord; 
    POSITION pos = NULL;

//     //第一次来，是系统断点，用于断在入口点
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

    //其他断点
    if(IsAddrInBpList(pExceptionRecord.ExceptionAddress, m_BreakPoint, pos))
    {
        PMYBREAK_POINT bp = m_BreakPoint.GetAt(pos);
        //还原代码
        if(!WriteRemoteCode(bp->lpAddr, bp->dwOldOrder, bp->dwCurOrder))
        {
            return FALSE;
        }

        //修改目标线程EIP
        m_DstContext.Eip = m_DstContext.Eip - 1;
        
        //系统一次性断点，用于断在入口点
        if(bp->dwState == BP_SYS)
        {
            m_BreakPoint.RemoveAt(pos);
            delete bp;
        }
        //常规断点
        else if(bp->dwState == BP_NORMAL)
        {
            //设置单步标志位
            m_DstContext.EFlags |= 0x100;
            
            bp->bIsSingleStep = TRUE;
        }

        Interaction(pExceptionRecord.ExceptionAddress);

        return TRUE;
    }

    return FALSE;
}

BOOL CDeBug::OnSingleStepEvent()       //单步异常
{
    EXCEPTION_RECORD& pExceptionRecord = m_DbgEvt.u.Exception.ExceptionRecord; 
    POSITION pos = NULL;

    //其他断点
    if(IsAddrInBpList(pExceptionRecord.ExceptionAddress, m_BreakPoint, pos))
    {
        PMYBREAK_POINT bp = m_BreakPoint.GetAt(pos);
        if(bp->bIsSingleStep == TRUE)
        {
            //重设断点
            if(!WriteRemoteCode(bp->lpAddr, bp->dwCurOrder, bp->dwOldOrder))
            {
                return FALSE;
            }
            //修改目标线程EIP
            m_DstContext.Eip = m_DstContext.Eip - 1;
        
            //设置单步标志位
            m_DstContext.EFlags |= 0x100;
            
            bp->bIsSingleStep = FALSE;
        
            return TRUE;
        }
    }

    return FALSE;
}

BOOL CDeBug::OnAccessVolationEvent()   //内存访问异常
{
    
    


    return FALSE;
}

BOOL CDeBug::ShowCurAllDbg(LPVOID lpAddr, DWORD dwState)  //显示当前所有调试信息
{
    //ShowRemoteMem(lpAddr);
    ShowRemoteReg();
    DWORD dwCount = 1;

    if(dwState != CMD_SHOWONCE)
        dwCount = 10;

    //显示反汇编
    if(!ShowRemoteDisAsm(lpAddr, dwCount))
        return FALSE;

    return TRUE;
}

#define RemoteOneReadSize 0x60  //一次读取远程数据的长度
BOOL CDeBug::ShowRemoteMem(LPVOID lpAddr)           //显示远程内存
{
    DWORD dwAddr = (DWORD)lpAddr;
    DWORD dwRead = 0;
    UCHAR szBuf[RemoteOneReadSize] = {0};
    PUCHAR pszBuf = szBuf;
    
    //读取远程内存信息
    if(!ReadProcessMemory(m_hDstProcess, lpAddr, szBuf, RemoteOneReadSize, &dwRead))
    {
        OutErrMsg(TEXT("ShowRemoteDisAsm：读取远程内存失败！"));
        return FALSE;
    }
    
    //输出内存信息
    int nCount = dwRead / 0X10;
    for(int i = 0; i < nCount; i++)
    {
        //输出地址
        _tprintf(TEXT("%08X   "), dwAddr);
        //tcout << ios::hex << dwAddr << TEXT("    ");

        //输出十六进制值
        for(int j = 0; j < 0x10; j++)
        {
            _tprintf(TEXT("%02X "), pszBuf[j]);
            //tcout << ios::hex << pszBuf[j] << TEXT(' ');
        }

        tcout << TEXT("  ");

        //输出解析字符串
        for(int n = 0; n < 0x10; n++)
        {
            putchar(pszBuf[n]);
        }
        
        //补回车换行
        tcout << endl;

        dwAddr += 0x10;
        pszBuf += 0x10;
    }
    
    return TRUE;
}

BOOL CDeBug::ShowRemoteReg()           //显示远程寄存器
{
// EAX=00000000   EBX=00000000   ECX=B2A10000   EDX=0008E3C8   ESI=FFFFFFFE
// EDI=00000000   EIP=7703103C   ESP=0018FB08   EBP=0018FB34   DS =0000002B
// ES =0000002B   SS =0000002B   FS =00000053   GS =0000002B   CS =00000023
    //获取EFlags
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
BOOL CDeBug::ShowRemoteDisAsm(LPVOID lpAddr, DWORD dwCount)        //显示远程反汇编
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

    //获取远程信息
    if(!ReadProcessMemory(m_hDstProcess, lpAddr, szBuf, RemoteOneReadSize, &dwRead))
    {
        OutErrMsg(TEXT("ShowRemoteDisAsm：读取远程内存失败！"));
        return FALSE;
    }

    //转换5条汇编码
    DWORD dwRemaining = 0;
    while(nCount < dwCount)
    {
        Decode2AsmOpcode(pCode, szAsmBuf, szOpcodeBuf,
            &nCodeSize, (DWORD)nCodeAddress);

        _tprintf(TEXT("%p:%s"),nCodeAddress, szOpcodeBuf);
        
        dwRemaining = 0x18 - _tcsclen(szOpcodeBuf);
        //补空格
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
    case EXCEPTION_BREAKPOINT:          //断点
        bRet = OnBreakPointEvent();
        break;

    case EXCEPTION_SINGLE_STEP:         //单步
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
    //设置入口点断点，
    CREATE_PROCESS_DEBUG_INFO& pCreateEvent = m_DbgEvt.u.CreateProcessInfo;
    LPVOID lpEntryPoint = pCreateEvent.lpStartAddress;

    PMYBREAK_POINT ptagBp = new MYBREAK_POINT;
    ZeroMemory(ptagBp, sizeof(MYBREAK_POINT));

    ptagBp->dwState = BP_SYS;
    ptagBp->lpAddr = lpEntryPoint;
    ptagBp->dwCurOrder = NORMAL_CC;

    if(!WriteRemoteCode(lpEntryPoint, ptagBp->dwCurOrder, ptagBp->dwOldOrder))
    {
        tcout << TEXT("系统断点: 严重BUG，请联系管理员！") << endl;

        //释放资源
        if(ptagBp != NULL)
            delete ptagBp;

        return FALSE;
    }

    //添加断点节点
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

    //遍历链表
    while(pos)
    {
        posTmp = pos;
        MYBREAK_POINT& bp = *bpSrcLst.GetNext(pos);
        if(bp.lpAddr == lpAddr)
        {
            bRet = TRUE;
            //已找到
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
    //遍历链表
    while(pos)
    {
        
        MODLST& ModLst = *m_ModuleLst.GetNext(pos);
        tcout << TEXT("地址:") << ModLst.dwBaseAddr << TEXT("\t")
              << TEXT("路径:") << ModLst.strPath << endl;
    }
    tcout << TEXT("==============================================================") << endl;
    return TRUE;
}

BOOL CDeBug::OnUnLoadDll()
{
    BOOL bRet = FALSE;
    POSITION pos = m_ModuleLst.GetHeadPosition();
    POSITION posTmp = NULL;

    //遍历链表
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

    //生成链表节点
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
        OutErrMsg(TEXT("OnLoadDll：申请节点失败！"));
        return FALSE;
    }
    
    //保存DLL 基址
    pModLst->dwBaseAddr = (DWORD)DllInfo.lpBaseOfDll;
    
    //读取DLL 地址
    if (ReadProcessMemory(m_hDstProcess, DllInfo.lpImageName, \
        &lpString, sizeof(LPVOID), NULL) == NULL)
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("OnLoadDll：读取远程地址失败！"));
        return FALSE;
    }
    
    //读取DLL路径
    if (ReadProcessMemory(m_hDstProcess, lpString, szBuf, \
        sizeof(szBuf) / sizeof(TCHAR), NULL) == NULL)
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("OnLoadDll：读取模块路径失败！"));
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
        //转换UNICODE为ASCII
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
    
    //抽掉内存保护属性
    if(!VirtualProtectEx(m_hDstProcess, lpRemoteAddr, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("WriteRemoteCode：抽取保护属性失败！"));
        return FALSE;
    }

    //读取旧代码并保存
    if(!ReadProcessMemory(m_hDstProcess, lpRemoteAddr, &pbtOutChar, sizeof(BYTE), &dwReadLen))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("WriteRemoteCode：读取远程内存失败！"));
        return FALSE;
    }

    //写入新代码
    if(!WriteProcessMemory(m_hDstProcess, lpRemoteAddr, &btInChar, sizeof(BYTE), &dwReadLen))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("WriteRemoteCode：写入远程内存失败！"));
        return FALSE;
    }
    
    //还原内存保护属性
    if(!VirtualProtectEx(m_hDstProcess, lpRemoteAddr, 1, dwOldProtect, &dwOldProtect))
    {
        m_dwErrCount++;
        OutErrMsg(TEXT("WriteRemoteCode：还原保护属性失败！"));
        return FALSE;
    }

    return TRUE;
}

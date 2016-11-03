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
    
    m_bIsMyStepOver = FALSE;
    m_bIsMyStepInto = FALSE;
    
    m_bIsScript = FALSE;
    m_bIsInput = TRUE;
    
    m_bIsNormalStep = FALSE;
    m_lpTmpNormalStepAddr = NULL;
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
    
    pos = m_NorMalBpLst.GetHeadPosition();
    while(pos)
    {
        posTmp = pos;
        PMYBREAK_POINT pBp = m_NorMalBpLst.GetNext(pos);
        if(pBp != NULL)
        {
            delete pBp;
            m_NorMalBpLst.RemoveAt(posTmp);
        }
    }
}

BOOL CDeBug::GetFun()
{
    
    m_pfnOpenThread = (PFN_OpenThread)GetProcAddress(
        LoadLibrary(TEXT("Kernel32.dll")), 
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
    else
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
    }
    
    if(!GetFun())
        return FALSE;
    
    return EventLoop();
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
            //tcout << TEXT("EXCEPTION_DEBUG_EVENT") << endl;
            
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
            //tcout << TEXT("EXIT_PROCESS_DEBUG_EVENT") << endl;	
            tcout << TEXT("被调试程序已退出!") << endl;	
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
            //tcout << TEXT("OUTPUT_DEBUG_STRING_EVENT") << endl;	
            tcout << TEXT("被调试程序有调试信息输出，调试器并未进行捕获.") << endl;		
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
            return FALSE;
        }
    }//End While
    
    return TRUE;
}

#define MAX_MEM 0x80000000
BOOL CDeBug::Interaction(LPVOID lpAddr, BOOL bIsShowDbgInfo)                //人机交互
{   
    //检查地址是否越界
    if((DWORD)lpAddr >= MAX_MEM)
    {
        tcout << TEXT("无效区域，超出程序领空！") << endl;
        return TRUE;
    }
    
    if(bIsShowDbgInfo)
    {
        //显示当前调试信息
        if(!ShowCurAllDbg(lpAddr))
        {
            m_dwErrCount++;
            OutErrMsg(TEXT("Interaction：未知程序显示错误！"));
            return FALSE;
        }
    }
    
    //初始化获取用户输入
    CMD_INFO CmdInfo;
    //ZeroMemory(&CmdInfo, sizeof(CMD_INFO));
    CmdInfo.dwState = CMD_INVALID;
    CmdInfo.bIsBreakInputLoop = FALSE;
    CmdInfo.dwPreAddr = NULL;
    
    while(TRUE)
    {
        //获取用户输入
        BOOL bRet = GetUserInput(CmdInfo);
        if(bRet == FALSE)
        {
            m_dwErrCount++;
            OutErrMsg(TEXT("Interaction：未知程序输入错误！"));
            return FALSE;
        }
        else if(!m_bIsScript && !m_bIsInput)
        {
            m_bIsInput = TRUE;
            continue;
        }
        
        
        //处理用户输入
        if(!HandleCmd(CmdInfo, lpAddr))
        {
            m_dwErrCount++;
            OutErrMsg(TEXT("Interaction：未知程序执行错误！"));
            return FALSE;
        }
        
        if(CmdInfo.bIsBreakInputLoop)
            break;
    }
    
    return TRUE;
}

#define MAX_INPUT   32
BOOL CDeBug::GetUserInput(CMD_INFO& CmdInfo)
{
    CmdInfo.strCMD = TEXT("");
    try
    {   
        if(!m_bIsScript)
        {
            //获取输入
            TCHAR szBuf[MAX_INPUT] = {0};
            tcout << TEXT('>');
            
            tcin.clear();
            tcin.sync();
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
        else
        {
            m_bIsScript = FALSE;
            m_bIsInput = FALSE;
        }
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
    if(IsAddrInBpList(pExceptionRecord.ExceptionAddress, m_NorMalBpLst, pos))
    {
        PMYBREAK_POINT bp = m_NorMalBpLst.GetAt(pos);
        //还原代码
        if(!WriteRemoteCode(bp->lpAddr, bp->dwOldOrder, bp->dwCurOrder))
        {
            return FALSE;
        }
        
        //修改目标线程EIP
        m_DstContext.Eip = m_DstContext.Eip - 1;
        
        //系统一次性断点，用于断在入口点
        if(bp->dwState == BP_SYS || bp->dwState == BP_ONCE)
        {
            m_NorMalBpLst.RemoveAt(pos);
            delete bp;
        }
        //常规断点
        else if(bp->dwState == BP_NORMAL)
        {
            //设置单步标志位
            m_DstContext.EFlags |= TF;
            
            bp->bIsSingleStep = TRUE;
            m_bIsNormalStep = TRUE;
            m_lpTmpNormalStepAddr = bp->lpAddr;
            ShowCurAllDbg(pExceptionRecord.ExceptionAddress, CMD_SHOWFIVE);
            return TRUE;
        }
        
        return Interaction(pExceptionRecord.ExceptionAddress);
    }
    
    return FALSE;
}

BOOL CDeBug::OnSingleStepEvent()       //单步异常
{
    EXCEPTION_RECORD& pExceptionRecord = m_DbgEvt.u.Exception.ExceptionRecord; 
    POSITION pos = NULL;
    
    //其他断点
    if(m_bIsNormalStep)
    {
        if(IsAddrInBpList(m_lpTmpNormalStepAddr, m_NorMalBpLst, pos))
        {
            PMYBREAK_POINT bp = m_NorMalBpLst.GetAt(pos);
            if(bp->bIsSingleStep == TRUE)
            {
                //重设断点
                if(!WriteRemoteCode(bp->lpAddr, bp->dwCurOrder, bp->dwOldOrder))
                {
                    return FALSE;
                }
                
                bp->bIsSingleStep = FALSE;
                m_bIsNormalStep = FALSE;
                return Interaction(pExceptionRecord.ExceptionAddress, FALSE);
            }
        }
    }
    else if(m_bIsMyStepInto)
    {
        m_bIsMyStepInto = FALSE;
        return Interaction(pExceptionRecord.ExceptionAddress);
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
    DWORD dwNotUse = 0;
    
    if(dwState == CMD_SHOWONCE)
        dwCount = 1;
    else if(dwState == CMD_SHOWFIVE)
        dwCount = 5;
    else
        dwCount = 10;
    
    //显示反汇编
    if(!ShowRemoteDisAsm(lpAddr, dwNotUse, dwCount))
        return FALSE;
    
    return TRUE;
}

BOOL CDeBug::CmdShowAsm(CMD_INFO& CmdInfo, LPVOID lpAddr)  //显示反汇编
{
    BOOL bRet = TRUE;
    if(CmdInfo.strCMD.GetLength() >1)
    {
        int nAddr = 0;
        if(CmdInfo.dwPreAddr == NULL)
        {
            PTCHAR pTmp = NULL;
            nAddr = _tcstol((LPCTSTR)CmdInfo.strCMD, &pTmp, 16);
        }
        else
        {
            nAddr = CmdInfo.dwPreAddr;
        }
        //int nAddr = atoi(CmdInfo.strCMD);
        bRet = ShowRemoteDisAsm((LPVOID)nAddr, CmdInfo.dwPreAddr);
    }
    else
    {
        bRet = ShowRemoteDisAsm(lpAddr, CmdInfo.dwPreAddr);
    }
    
    return bRet;
}

BOOL CDeBug::CmdShowMem(CMD_INFO& CmdInfo, LPVOID lpAddr)
{
    BOOL bRet = TRUE;
    if(CmdInfo.strCMD.GetLength() >1)
    {
        PTCHAR pTmp = NULL;
        int nAddr = _tcstol(CmdInfo.strCMD, &pTmp, 16);
        //int nAddr = atoi(CmdInfo.strCMD);
        bRet = ShowRemoteMem((LPVOID)nAddr);
    }
    else
    {
        bRet = ShowRemoteMem(lpAddr);
    }
    
    return bRet;
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
            if(pszBuf[n] < 32 || pszBuf[n] > 127)
                _puttchar(TEXT('.'));
            else
                _puttchar(pszBuf[n]);
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


//反汇编指定地址一条数据
BOOL CDeBug::GetOneAsm(LPVOID lpAddr, DWORD& dwOrderCount, CString& strOutAsm)
{
    UINT unCodeAddress = (DWORD)lpAddr;    //基址
    DWORD dwRead = 0;
    UCHAR szBuf[MAXBYTE] = {0};         //远程内存缓冲区
    //BYTE btCode[MAXBYTE] = {0};         //
    char szAsmBuf[MAXBYTE] = {0};       //反汇编缓冲区
    char szOpcodeBuf[MAXBYTE] = {0};    //操作码缓冲区
    
    PBYTE pCode = szBuf;
    UINT unCodeSize = 0;
    
    
    //获取远程信息
    if(!ReadProcessMemory(m_hDstProcess, lpAddr, szBuf, RemoteOneReadSize, &dwRead))
    {
        OutErrMsg(TEXT("ShowRemoteDisAsm：读取远程内存失败！"));
        return FALSE;
    }
    
    Decode2AsmOpcode(pCode, szAsmBuf, szOpcodeBuf,
        &unCodeSize, unCodeAddress);
    
    strOutAsm = szAsmBuf;
    dwOrderCount = unCodeSize;
    return TRUE;
}

#define OneAsmSize 10
BOOL CDeBug::ShowRemoteDisAsm(LPVOID lpAddr, DWORD& dwOutCurAddr, DWORD dwAsmCount)        //显示远程反汇编
{
    DWORD dwRead = 0;
    UCHAR szBuf[MAXBYTE] = {0};
    
    BOOL bRet = FALSE;
    DWORD dwReadLen = 0;
    //BYTE btCode[MAXBYTE] = {0};
    char szAsmBuf[MAXBYTE] = {0};           //反汇编指令缓冲区
    char szOpcodeBuf[MAXBYTE] = {0};        //机器码缓冲区
    UINT unCodeSize = 0;
    UINT unCount = 0;
    UINT unCodeAddress = (DWORD)lpAddr;
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
    while(unCount < dwAsmCount)
    {
        Decode2AsmOpcode(pCode, szAsmBuf, szOpcodeBuf,
            &unCodeSize, unCodeAddress);
        
        _tprintf(TEXT("%p:%-20s%s\r\n"), unCodeAddress, szOpcodeBuf, szAsmBuf);
        
        //         dwRemaining = 0x18 - _tcsclen(szOpcodeBuf);
        // 
        //         //补空格
        //         while(dwRemaining--)
        //         {
        //             _puttchar(' ');
        //         }
        //         
        //         puts(szAsmBuf);
        
        
        pCode += unCodeSize;
        unCount++;
        unCodeAddress += unCodeSize;
    }
    dwOutCurAddr = unCodeSize;
    
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
    m_NorMalBpLst.AddTail(ptagBp);
    
    return TRUE;
}

BOOL CDeBug::IsAddrInBpList(LPVOID lpAddr, 
                            CList<PMYBREAK_POINT, PMYBREAK_POINT&>& bpSrcLst, 
                            _OUT_ POSITION& dwOutPos,
                            BOOL bIsNextAddr)
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
        _tprintf(TEXT("地址:%08X\t路径:%s\r\n"),
            ModLst.dwBaseAddr,
            (LPCTSTR)ModLst.strPath);
        //         tcout << TEXT("地址:") << ios::hex << ModLst.dwBaseAddr << TEXT("\t")
        //               << TEXT("路径:") << ModLst.strPath << endl;
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

BOOL CDeBug::CmdSetNormalBp(CMD_INFO& CmdInfo, LPVOID lpAddr)      //设置一般断点
{
    if(CmdInfo.strCMD.GetLength() > 0)
    {
        //转换操作数
        PTCHAR pTmp = NULL;
        int nAddr = _tcstol(CmdInfo.strCMD, &pTmp, 16);
        
        //检查是否超范围
        if((DWORD)nAddr > MAX_MEM)
        {
            _tprintf(TEXT("不支持的地址: %08X\r\n"), nAddr);
            return FALSE;
        }
        
        PMYBREAK_POINT ptagBp = new MYBREAK_POINT;
        if(ptagBp == NULL)
        {
            OutErrMsg(TEXT("CmdSetNormalBp：内存不足，请联系管理员！"));
            m_dwErrCount++;
            tcout << TEXT("内存断点：未知错误，请联系管理员！") << endl;
        }
        ZeroMemory(ptagBp, sizeof(MYBREAK_POINT));
        
        ptagBp->dwState = BP_NORMAL;
        ptagBp->lpAddr = (LPVOID)nAddr;
        ptagBp->dwCurOrder = NORMAL_CC;
        
        //设置CC断点
        if(!WriteRemoteCode(ptagBp->lpAddr, ptagBp->dwCurOrder, ptagBp->dwOldOrder))
        {
            tcout << TEXT("系统断点: 严重BUG，请联系管理员！") << endl;
            
            //释放资源
            if(ptagBp != NULL)
                delete ptagBp;
            
            return FALSE;
        }
        
        //添加断点节点
        m_NorMalBpLst.AddTail(ptagBp);
    }
    else
    {
        tcout << TEXT("一般断点需要操作数") << endl;
        return FALSE;
    }
    
    return TRUE;
}

BOOL CDeBug::CmdSetHardBp(CMD_INFO& CmdInfo, LPVOID lpAddr)        //设置硬件断点
{
    return TRUE;
}

BOOL CDeBug::CmdSetMemBp(CMD_INFO& CmdInfo, LPVOID lpAddr)         //设置内存断点
{
    return TRUE;
}

BOOL CDeBug::CmdSetOneStepInto(CMD_INFO& CmdInfo, LPVOID lpAddr)       //设置单步
{
    m_bIsMyStepInto = TRUE;
    
    //设置单步标志位
    m_DstContext.EFlags |= TF;
    
    return TRUE;
}

BOOL CDeBug::CmdSetOneStepOver(CMD_INFO& CmdInfo, LPVOID lpAddr)   //单步步过
{
    DWORD dwCount = 0;
    CString strAsm = TEXT("");
    if(!GetOneAsm(lpAddr, dwCount, strAsm))
        m_dwErrCount++;
    
    strAsm.MakeLower();
    if(strAsm.Find(TEXT("call")) != -1)
    {
        PMYBREAK_POINT ptagBp = new MYBREAK_POINT;
        ZeroMemory(ptagBp, sizeof(MYBREAK_POINT));
        
        ptagBp->dwState = BP_ONCE;
        ptagBp->lpAddr = (LPVOID)(m_DstContext.Eip + dwCount);
        ptagBp->dwCurOrder = NORMAL_CC;
        
        if(!WriteRemoteCode(ptagBp->lpAddr, ptagBp->dwCurOrder, ptagBp->dwOldOrder))
        {
            tcout << TEXT("系统断点: 严重BUG，请联系管理员！") << endl;
            
            //释放资源
            if(ptagBp != NULL)
                delete ptagBp;
            
            return FALSE;
        }
        
        //添加断点节点
        m_NorMalBpLst.AddTail(ptagBp);
        
    }
    else
    {
        m_bIsMyStepInto = TRUE;
        
        //设置单步标志位
        m_DstContext.EFlags |= TF;
    }
    return TRUE;
}


BOOL CDeBug::CmdShowReg(CMD_INFO& CmdInfo, LPVOID lpAddr)  //显示
{
    BOOL bRet = TRUE;
    TCHAR szBuf[MAXBYTE] = {0};
    DWORD dwTmpReg = 0;
    bRet = ShowRemoteReg();
    while(TRUE)
    {
        //获取用户输入
        tcout << TEXT("-请输入寄存器:");
        
        
        tcin.clear();
        tcin.sync();
        tcin.getline(szBuf, 4, TEXT('\n'));
        tcin.clear();
        tcin.sync();
        
        //_tscanf(TEXT("%[a-z, A-Z]4s"), szBuf);
        CString strBuf = szBuf;
        strBuf.MakeUpper();
        
        //EAX
        if(strBuf == TEXT("EAX"))
        {
            tcout << TEXT("-EAX: ");
            _tscanf("%X", &dwTmpReg);
            m_DstContext.Eax = dwTmpReg;
        }
        //EBX
        else if(strBuf == TEXT("EBX"))
        {
            tcout << TEXT("-EBX: ");
            _tscanf("%X", &dwTmpReg);
            m_DstContext.Ebx = dwTmpReg;
        }
        //ECX
        else if(strBuf == TEXT("ECX"))
        {
            tcout << TEXT("-ECX: ");
            _tscanf("%X", &dwTmpReg);
            m_DstContext.Ecx = dwTmpReg;
        }
        //EDX
        else if(strBuf == TEXT("EDX"))
        {
            tcout << TEXT("-EDX: ");
            _tscanf("%X", &dwTmpReg);
            m_DstContext.Edx = dwTmpReg;
        }
        //ESI
        else if(strBuf == TEXT("ESI"))
        {
            tcout << TEXT("-ESI: ");
            _tscanf("%X", &dwTmpReg);
            m_DstContext.Edx = dwTmpReg;
        }
        //EDI
        else if(strBuf == TEXT("EDI"))
        {
            tcout << TEXT("-EDI: ");
            _tscanf("%X", &dwTmpReg);
            m_DstContext.Edx = dwTmpReg;
        }
        //回车
        else if(strBuf.GetLength() == 0)
        {
            break;
        }
        else
        {
            tcout << TEXT("无效命令") << endl;
            continue;
        }
        
    }
    return bRet;
}


BOOL CDeBug::CmdShowNormalBpLst(CMD_INFO& CmdInfo, LPVOID lpAddr)  //显示一般断点
{
    DWORD dwCount = 0;
    POSITION pos = m_NorMalBpLst.GetHeadPosition();
    tcout << TEXT("=====================内存断点=====================") << endl;
    if(m_NorMalBpLst.IsEmpty())
    {
        tcout << TEXT("暂无") << endl;
    }
    else
    {
        while(pos)
        {
            MYBREAK_POINT& Bp = *m_NorMalBpLst.GetNext(pos);
            _tprintf(TEXT("\t\t序号：%d\t地址：%p\r\n"), dwCount++, (DWORD)Bp.lpAddr);
        }
    }
    
    tcout << TEXT("=====================内存断点=====================") << endl;
    
    return TRUE;
}

BOOL CDeBug::CmdClearNormalBp(CMD_INFO& CmdInfo, LPVOID lpAddr)
{
    CmdShowNormalBpLst(CmdInfo, lpAddr);
    if(!m_NorMalBpLst.IsEmpty())
    {
        BOOL bIsDel = FALSE;
        DWORD dwNum = 0;
        DWORD dwLstCount = m_NorMalBpLst.GetCount();
        
        while(TRUE)
        {
            //获取用户输入
            tcout << TEXT("请输入编号：") ;
            _tscanf(TEXT("%d"), &dwNum);
            if(dwNum < 0 || dwNum >= dwLstCount)
            {
                tcout << TEXT("输入编号有误！") << endl;
                continue;
            }
            
            //遍历链表
            POSITION pos = m_NorMalBpLst.GetHeadPosition();
            POSITION posTmp = NULL;
            while(pos)
            {
                posTmp = pos;
                MYBREAK_POINT& bp = *m_NorMalBpLst.GetNext(pos);
                
                if(0 == dwNum--)
                {
                    //修补断点抽取的代码
                    if(WriteRemoteCode(bp.lpAddr, bp.dwOldOrder, bp.dwCurOrder))
                    {
                        //移除节点
                        m_NorMalBpLst.RemoveAt(posTmp);
                        bIsDel = TRUE;
                    }
                    else
                    {
                        tcout << TEXT("内存操作有误！") << endl;
                        OutErrMsg(TEXT("CmdClearNormalBp：修补断点失败"));
                        return FALSE;
                    }
                }
            }
            if(bIsDel)
            {
                tcout << TEXT("成功") << endl;
                break;
            }
        }
    }
    return TRUE;
}

BOOL CDeBug::ShowMemLst(CMD_INFO& CmdInfo, LPVOID lpAddr)          //显示内存列表
{
    MEMORY_BASIC_INFORMATION mbi;  //被调试程序的内存信息
    PBYTE pAddress = NULL;
    
    _tprintf(_T("BaseAddr    Size    Type    State    AllocProtect    Protect\r\n"));
    
    while (true)
    {
        if (VirtualQueryEx(m_hDstProcess, pAddress, &mbi, sizeof(mbi)) != \
            sizeof(mbi))
        {
            break;
        }
        if ((mbi.AllocationBase != mbi.BaseAddress) && (mbi.State != MEM_FREE))
        {
            _tprintf(_T("%08x  %08x  "), mbi.BaseAddress, mbi.RegionSize);
        }
        else
        {
            _tprintf(_T("%08x  %08x  "), mbi.BaseAddress, mbi.RegionSize);
        }
        
        switch (mbi.Type)  //内存块类型 MEM_IMAGE MEM_MAPPED MEM_PRIVATE
        {
        case MEM_IMAGE: 
            _tprintf(_T("%-8s"), _T("Imag")); 
            break;
        case MEM_MAPPED: 
            _tprintf(_T("%-8s"), _T("Map"));
            break;
        case MEM_PRIVATE: 
            _tprintf(_T("%-8s"), _T("Priv"));
            break;
        default:
            _tprintf(_T("%-8s"), _T(" --"));
            break;
        }
        
        switch (mbi.State)  //内存块状态
        {
        case MEM_COMMIT: 
            _tprintf(_T("%-13s"), _T("COMMIT")); 
            break;
        case MEM_RESERVE: 
            _tprintf(_T("%-13s"), _T("RESERVE"));
            break;
        case MEM_FREE: 
            _tprintf(_T("%-13s"), _T("FREE "));
            break;
        default:
            _tprintf(_T("%-13s")_T("--"));
            break;
        }
        
        switch (mbi.AllocationProtect)  //内存块呗初次保留时的保护属性
        {
        case PAGE_READONLY:
            _tprintf(_T("%-12s"), _T("R_ONLY"));
            break;
        case PAGE_READWRITE:
            _tprintf(_T("%-12s"), _T("R/W"));
            break;
        case PAGE_WRITECOPY: 
            _tprintf(_T("%-12s"), _T("W/COPY "));
            break;
        case PAGE_EXECUTE: 
            _tprintf(_T("%-12s"), _T("E"));
            break;
        case PAGE_EXECUTE_READ:
            _tprintf(_T("%-12s"), _T("E/R"));
            break;
        case PAGE_EXECUTE_READWRITE:
            _tprintf(_T("%-12s"), _T("E/R/W"));
            break;
        case PAGE_EXECUTE_WRITECOPY: 
            _tprintf(_T("%-12s"), _T("E/W/COPY"));
            break;
        case PAGE_GUARD: 
            _tprintf(_T("%-12s"), _T("GUARD "));
            break;
        case PAGE_NOACCESS: 
            _tprintf(_T("%-12s"), _T("NOACCESS "));
            break;
        case PAGE_NOCACHE: 
            _tprintf(_T("%-12s"), _T("NOCACHE "));
            break;
        default: 
            _tprintf(_T("%-12s"), _T("--"));
            break;
        }
        
        switch (mbi.Protect)  //内存块属性
        {
        case PAGE_READONLY:
            _tprintf(_T("%s"), _T("R_ONLY"));
            break;
        case PAGE_READWRITE:
            _tprintf(_T("%s"), _T("R/W"));
            break;
        case PAGE_WRITECOPY:
            _tprintf(_T("%s"), _T("W/COPY "));
            break;
        case PAGE_EXECUTE:
            _tprintf(_T("%s"), _T("E"));
            break;
        case PAGE_EXECUTE_READ:
            _tprintf(_T("%s"), _T("E/R"));
            break;
        case PAGE_EXECUTE_READWRITE:
            _tprintf(_T("%s"), _T("E/R/W"));
            break;
        case PAGE_EXECUTE_WRITECOPY:
            _tprintf(_T("%s"), _T("E/W/COPY"));
            break;
        case PAGE_GUARD:
            _tprintf(_T("%s"), _T("GUARD "));
            break;
        case PAGE_NOACCESS:
            _tprintf(_T("%s"), _T("NOACCESS "));
            break;
        case PAGE_NOCACHE:
            _tprintf(_T("%s"), _T("NOCACHE "));
            break;
        default:
            _tprintf(_T("%s"), _T("--"));
            break;
        }
        _tprintf(_T("\r\n"));
        
        pAddress = ((PBYTE)mbi.BaseAddress + mbi.RegionSize);
    }
    
    return TRUE;
}

BOOL CDeBug::HandleCmd(CMD_INFO& CmdInfo, LPVOID lpAddr)          //执行命令
{
    BOOL bIsBreak = FALSE;
    switch(CmdInfo.dwState)
    {
        //单步步入
    case CMD_STEP:
        CmdSetOneStepInto(CmdInfo, lpAddr);
        bIsBreak = TRUE;
        break;
        
        //单步步过
    case CMD_STEPGO:
        CmdSetOneStepOver(CmdInfo, lpAddr);
        bIsBreak = TRUE;
        break;
        
        //运行
    case CMD_RUN:
        bIsBreak = TRUE;
        break;
        
        //跟踪
    case CMD_TRACE:
        break;
        
        //显示反汇编
    case CMD_DISPLAY_ASMCODE:
        CmdShowAsm(CmdInfo, lpAddr);
        break;
        
        //显示内存
    case CMD_DISPLAY_DATA:
        CmdShowMem(CmdInfo, lpAddr);
        break;
        
        //寄存器
    case CMD_REGISTER:
        CmdShowReg(CmdInfo, lpAddr);
        break;
        
        //修改内存  
    case CMD_EDIT_DATA:
        break;
        
        //一般断点
    case CMD_BREAK_POINT:
        CmdSetNormalBp(CmdInfo, lpAddr);
        break;
        
        //一般断点列表
    case CMD_BP_LIST:
        CmdShowNormalBpLst(CmdInfo, lpAddr);
        break;
        
        //清除一般断点
    case CMD_CLEAR_NORMAL:
        CmdClearNormalBp(CmdInfo, lpAddr);
        break;
        
        //硬件断点
    case CMD_BP_HARD:
        break;
        
        //硬件断点列表
    case CMD_BP_HARD_LIST:
        break;
        
        //清除硬件断点列表
    case CMD_CLEAR_BP_HARD:
        break;
        
        //内存断点
    case CMD_BP_MEMORY:
        break;
        
        //内存断点列表
    case CMD_BP_MEMORY_LIST:
        
        break;
        
        //内存分页断点列表
    case CMD_BP_PAGE_LIST:
        break;
        
        //清除内存断点
    case CMD_CLEAR_BP_MEMORY:
        break;
        
        //加载脚本
    case CMD_LOAD_SCRIPT:
        break;
        
        //导出脚本
    case CMD_EXPORT_SCRIPT:
        break;
        
        //退出程序
    case CMD_QUIT:
        tcout << TEXT("谢谢使用！") << endl;
        system("pause");
        ExitProcess(0);
        break;
        
        //模块列表
    case CMD_MODULE_LIST:
        ShowDllLst();
        break;
        
        //内存列表
    case CMD_MEM_INFO_LIST:
        ShowMemLst(CmdInfo, lpAddr);
        break;
        
        //默认与无效
    case CMD_INVALID:
    default:
        break;
    }
    
    CmdInfo.bIsBreakInputLoop = bIsBreak;
    return TRUE;
}

// ResolveCMD.cpp: implementation of the CResolveCMD class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "MyDebug.h"
#include "ResolveCMD.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CResolveCMD::CResolveCMD()
{

}

CResolveCMD::~CResolveCMD()
{

}


BOOL CResolveCMD::Resolve(CMD_INFO& CmdInfo)
{
    BOOL bRet = TRUE;
    BOOL bIsSupport = TRUE;
    DWORD dwStrLen = CmdInfo.strCMD.GetLength();

    //截取命令和操作数
    int nPos = CmdInfo.strCMD.Find(TEXT(' '));
    if(nPos != -1)
    {
        //获取命令
        CString strOrder = CmdInfo.strCMD.Left(nPos);
        
        //获取操作数
        CString strOperand = CmdInfo.strCMD.Right(dwStrLen - nPos);
        
        //一般断点
        if(strOrder == TEXT("bp"))
        {
            CmdInfo.dwState = CMD_BREAK_POINT;
        }
        //硬件断点
        else if(strOrder == TEXT("bh"))
        {
            
        }
        //内存断点
        else if(strOrder == TEXT("bm"))
        {
            
        }
        //查看内存
        else if(strOrder == TEXT("d"))
        {
            
        }
        //查看反汇编
        else if(strOrder == TEXT("u"))
        {
            CmdInfo.dwState = CMD_DISPLAY_ASMCODE;
        }
        //
        else if(strOrder == TEXT("d"))
        {
            
        }
        //修改内存数据
        else if(strOrder == TEXT("e"))
        {
            
        }
        //
        else if(strOrder == TEXT("bpc"))
        {
            
        }
        //
        else if(strOrder == TEXT("trace"))
        {
            
        }
        else
        {
            //未知命令
            bIsSupport = FALSE;
        }

        if(bIsSupport)
            CmdInfo.strCMD = strOperand;
    }
    //单命令
    else
    {
        if(CmdInfo.strCMD == TEXT("q"))
        {
            CmdInfo.dwState = CMD_QUIT;
        }
        else
        {
            //未知命令
            bIsSupport = FALSE;
        }
    }


    //未知命令
    if(!bIsSupport)
        tcout << TEXT("暂未支持此命令") << endl;

    
    return bRet;
}

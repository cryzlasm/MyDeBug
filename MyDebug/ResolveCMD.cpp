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

    //��ȡ����Ͳ�����
    int nPos = CmdInfo.strCMD.Find(TEXT(' '));
    if(nPos != -1)
    {
        //��ȡ����
        CString strOrder = CmdInfo.strCMD.Left(nPos);
        
        //��ȡ������
        CString strOperand = CmdInfo.strCMD.Right(dwStrLen - nPos);
        
        //һ��ϵ�
        if(strOrder == TEXT("bp"))
        {
            CmdInfo.dwState = CMD_BREAK_POINT;
        }
        //Ӳ���ϵ�
        else if(strOrder == TEXT("bh"))
        {
            
        }
        //�ڴ�ϵ�
        else if(strOrder == TEXT("bm"))
        {
            
        }
        //�鿴�ڴ�
        else if(strOrder == TEXT("d"))
        {
            
        }
        //�鿴�����
        else if(strOrder == TEXT("u"))
        {
            CmdInfo.dwState = CMD_DISPLAY_ASMCODE;
        }
        //
        else if(strOrder == TEXT("d"))
        {
            
        }
        //�޸��ڴ�����
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
            //δ֪����
            bIsSupport = FALSE;
        }

        if(bIsSupport)
            CmdInfo.strCMD = strOperand;
    }
    //������
    else
    {
        if(CmdInfo.strCMD == TEXT("q"))
        {
            CmdInfo.dwState = CMD_QUIT;
        }
        else
        {
            //δ֪����
            bIsSupport = FALSE;
        }
    }


    //δ֪����
    if(!bIsSupport)
        tcout << TEXT("��δ֧�ִ�����") << endl;

    
    return bRet;
}

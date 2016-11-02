#if !defined(TAG_DEAL_H__CCFCD8C7_A313_4B5F_9343_626594F87C8E__INCLUDED_)
#define TAG_DEAL_H__CCFCD8C7_A313_4B5F_9343_626594F87C8E__INCLUDED_


//ģ���б�
typedef struct _tagModLst
{
    DWORD dwBaseAddr;       //ģ���ַ
    //DWORD dwSize;           //ģ���С
    //DWORD dwEntryPoint;     //ģ����ڵ�
    //LPTSTR strName;      //ģ������
    CString strPath;      //ģ��·��
}MODLST, *PMODLST;

enum enumBreakPoint
{
    BP_SYS,             //ϵͳ�ϵ㣬���ڶ�����ڵ�
    BP_ONCE,            //һ���Զϵ�
    BP_NORMAL,          //һ��ϵ�
    BP_HARDWARE,        //Ӳ���ϵ�
    BP_MEM              //�ڴ�ϵ�
};

#define NORMAL_CC     0xcc  //һ��ϵ�
enum enumCmd
{
    CMD_INVALID,
    CMD_SHOWONCE,            //��ʾһ����Ϣ
    CMD_SHOWALLDBG,          //��ʾ��ǰ������Ϣ
    CMD_STEP,                //��������         t     
    CMD_STEPGO,              //��������         p     
    CMD_RUN,                 //����             g     
    CMD__TRACE,              //�Զ����ټ�¼     trace
    CMD_DISPLAY_ASMCODE,     //�����           u
    CMD_DISPLAY_DATA,        //��ʾ�ڴ�����     d 
    CMD_REGISTER,            //�Ĵ���           r
    CMD_EDIT_DATA,           //�޸��ڴ�����     e
    CMD_BREAK_POINT,         //һ��ϵ�         bp
    CMD_BP_LIST,             //һ��ϵ��б�     bpl
    CMD_CLEAR_UP,            //ɾ��һ��ϵ�     bpc
    CMD_BP_HARD,             //Ӳ���ϵ�         bh
    CMD_BP_HARD_LIST,        //Ӳ���ϵ��б�     bhl
    CMD_CLEAR_BP_HARD,       //ɾ��Ӳ���ϵ�     bhc
    CMD_BP_MEMORY,           //�ڴ�ϵ�         bm
    CMD_BP_MEMORY_LIST,      //�ڴ�ϵ��б�     bml
    CMD_BP_PAGE_LIST,        //��ҳ�ϵ��б�     bmpl
    CMD_CLEAR_BP_MEMORY,     //ɾ���ڴ�ϵ�     bmc
    CMD_LOAD_SCRIPT,         //����ű�         ls
    CMD_EXPORT_SCRIPT,       //�����ű�         es
    CMD_QUIT,                //�˳�����         q
    CMD_MODULE_LIST          //�鿴ģ��         ML
};


//�ϵ���Ϣ
typedef struct _tagBreakPoint
{
    DWORD   dwState;        //�ϵ�״̬
    LPVOID  lpAddr;         //�ϵ��ַ
    DWORD   dwOldOrder;     //ԭָ��
    DWORD   dwCurOrder;     //���ڵ�ָ��
    BOOL    bIsSingleStep;  //�Ƿ����õ���

}MYBREAK_POINT, *PMYBREAK_POINT;

//ת��CMD��Ϣʱ����Ҫ����Ϣ
typedef struct _tagCmdInfo
{
    DWORD dwState;
    CString strCMD;
}CMD_INFO, *PCMD_INFO;

//��־�Ĵ���
typedef struct _tagEFlags
{
    DWORD UnUse:    20; //20    12
    DWORD dwOF:     1;  //21    11
    DWORD dwDF:     1;  //22    10
    DWORD dwIF:     1;  //23    9
    DWORD dwTF:     1;  //24    8
    DWORD dwSF:     1;  //25    7
    DWORD dwZF:     1;  //26    6
    DWORD UnUse1:   1;  //27    5
    DWORD dwAF:     1;  //28    4
    DWORD UnUse2:   1;  //29    3
    DWORD dwPF:     1;  //30    2
    DWORD UnUse3:   1;  //31    1
    DWORD dwCF:     1;  //32    0

}EFLAGS, *PEFLAGS;
#endif
#if !defined(TAG_DEAL_H__CCFCD8C7_A313_4B5F_9343_626594F87C8E__INCLUDED_)
#define TAG_DEAL_H__CCFCD8C7_A313_4B5F_9343_626594F87C8E__INCLUDED_


//模块列表
typedef struct _tagModLst
{
    DWORD dwBaseAddr;       //模块基址
    //DWORD dwSize;           //模块大小
    //DWORD dwEntryPoint;     //模块入口点
    //LPTSTR strName;      //模块名称
    CString strPath;      //模块路径
}MODLST, *PMODLST;

enum enumBreakPoint
{
    BP_SYS,             //系统断点，用于断在入口点
    BP_ONCE,            //一次性断点
    BP_NORMAL,          //一般断点
    BP_HARDWARE,        //硬件断点
    BP_MEM              //内存断点
};

#define NORMAL_CC     0xcc  //一般断点
enum enumCmd
{
    CMD_INVALID,
    CMD_SHOWONCE,            //显示一条信息
    CMD_SHOWALLDBG,          //显示当前所有信息
    CMD_STEP,                //单步步入         t     
    CMD_STEPGO,              //单步步过         p     
    CMD_RUN,                 //运行             g     
    CMD__TRACE,              //自动跟踪记录     trace
    CMD_DISPLAY_ASMCODE,     //反汇编           u
    CMD_DISPLAY_DATA,        //显示内存数据     d 
    CMD_REGISTER,            //寄存器           r
    CMD_EDIT_DATA,           //修改内存数据     e
    CMD_BREAK_POINT,         //一般断点         bp
    CMD_BP_LIST,             //一般断点列表     bpl
    CMD_CLEAR_UP,            //删除一般断点     bpc
    CMD_BP_HARD,             //硬件断点         bh
    CMD_BP_HARD_LIST,        //硬件断点列表     bhl
    CMD_CLEAR_BP_HARD,       //删除硬件断点     bhc
    CMD_BP_MEMORY,           //内存断点         bm
    CMD_BP_MEMORY_LIST,      //内存断点列表     bml
    CMD_BP_PAGE_LIST,        //分页断点列表     bmpl
    CMD_CLEAR_BP_MEMORY,     //删除内存断点     bmc
    CMD_LOAD_SCRIPT,         //导入脚本         ls
    CMD_EXPORT_SCRIPT,       //导出脚本         es
    CMD_QUIT,                //退出程序         q
    CMD_MODULE_LIST          //查看模块         ML
};


//断点信息
typedef struct _tagBreakPoint
{
    DWORD   dwState;        //断点状态
    LPVOID  lpAddr;         //断点地址
    DWORD   dwOldOrder;     //原指令
    DWORD   dwCurOrder;     //现在的指令
    BOOL    bIsSingleStep;  //是否设置单步

}MYBREAK_POINT, *PMYBREAK_POINT;

//转换CMD信息时所需要的信息
typedef struct _tagCmdInfo
{
    DWORD dwState;
    CString strCMD;
}CMD_INFO, *PCMD_INFO;

//标志寄存器
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
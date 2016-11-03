#if !defined(TAG_DEAL_H__CCFCD8C7_A313_4B5F_9343_626594F87C8E__INCLUDED_)
#define TAG_DEAL_H__CCFCD8C7_A313_4B5F_9343_626594F87C8E__INCLUDED_


#define TF  0x100           //TF标志位
#define NORMAL_CC     0xcc  //一般断点

//硬件断点编号
#define    DR0    0
#define    DR1    1
#define    DR2    2
#define    DR3    3

//硬件断点属性
#define    INSTRUCTION_EXECUT    0    //00
#define    DATAS_WRITES          1    //01
#define    DATAS_READS_WRITES    3    //11 没产生取指令行为  


//模块列表
typedef struct _tagModLst
{
    DWORD dwBaseAddr;       //模块基址
    //DWORD dwSize;           //模块大小
    //DWORD dwEntryPoint;     //模块入口点
    //LPTSTR strName;      //模块名称
    CString strPath;      //模块路径
}MODLST, *PMODLST;

enum _enumBreakPoint
{
    BP_SYS,             //系统断点，用于断在入口点
    BP_ONCE,            //一次性断点
    BP_NORMAL,          //一般断点
    BP_HARDWARE,        //硬件断点
    BP_MEM              //内存断点
};

enum _enumCmd
{
    CMD_INVALID,
    CMD_SHOWONCE,            //显示一条信息
    CMD_SHOWFIVE,            //显示五条信息
    CMD_SHOWALLDBG,          //显示当前所有信息
    CMD_STEP,                //单步步入         t     
    CMD_STEPGO,              //单步步过         p     
    CMD_RUN,                 //运行             g     
    CMD_TRACE,               //自动跟踪记录     trace
    CMD_DISPLAY_ASMCODE,     //反汇编           u
    CMD_DISPLAY_DATA,        //显示内存数据     d 
    CMD_REGISTER,            //寄存器           r
    CMD_EDIT_DATA,           //修改内存数据     e
    CMD_BREAK_POINT,         //一般断点         bp
    CMD_BP_LIST,             //一般断点列表     bpl
    CMD_CLEAR_NORMAL,        //删除一般断点     bpc
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
    CMD_MODULE_LIST,         //查看模块         ML
    CMD_MEM_INFO_LIST        //内存信息列表     mil
};


//断点信息
typedef struct _tagBreakPoint
{
    _enumBreakPoint     dwState;        //断点状态
    LPVOID              lpAddr;         //断点地址
    DWORD               dwOldOrder;     //原指令
    DWORD               dwCurOrder;     //现在的指令
    BOOL                bIsSingleStep;  //是否设置单步

}MYBREAK_POINT, *PMYBREAK_POINT;

//转换CMD信息时所需要的信息
typedef struct _tagCmdInfo
{
    BOOL            bIsBreakInputLoop;      //是否结束交互
    DWORD           dwPreAddr;              //上一个Addr的位置
    _enumCmd        dwState;                //CMD命令码
    CString         strCMD;                 //CMD命令操作数
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

typedef struct _tag_DR7 
{
    unsigned int L0:1;  
    unsigned int G0:1;
    unsigned int L1:1;
    unsigned int G1:1;
    unsigned int L2:1;
    unsigned int G2:1;
    unsigned int L3:1;
    unsigned int G3:1;
    unsigned int LE:1;
    unsigned int GE:1;
    unsigned int RESERVED0:3;
    unsigned int GD:1;
    unsigned int RESERVED1:2;
    unsigned int RW0:2;
    unsigned int LEN0:2;
    unsigned int RW1:2;
    unsigned int LEN1:2;
    unsigned int RW2:2;
    unsigned int LEN2:2;
    unsigned int RW3:2;
    unsigned int LEN3:2;
}MYDR7, *PMYDR7;

typedef struct _tag_DR6 
{
    unsigned int B0:1;  
    unsigned int B1:1;  
    unsigned int B2:1;  
    unsigned int B3:1;   
    unsigned int RESERVED0:9;
    unsigned int BD:1;
    unsigned int BS:1;
    unsigned int BT:1;
    unsigned int RESERVED1:16;
}MYDR6, *PMYDR6;
#endif
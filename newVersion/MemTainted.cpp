/* ================================================================== */
/* Preprocessors */
/* ================================================================== */
#pragma once
#include "resources.hpp"
#include "MemTainted.hpp"

#if 1
/* ================================================================== */
// Global Variables
/* ================================================================== */
list<REG>			RegTainted;			/* 레지스트리 오염 리스트 */
list<UINT>		addressTainted;		/* 주소 오염 리스트 */
list<mallocArea>	mallocAreaList;		/* 할당 영역 리스트 */
list<UINT>		targetFileHandles;	/* 타겟 파일 핸들 */
list<Range>			byteTainted;

StackAllocated stack_allocated;
std::list<HeapAllocated> heap_allocated;
std::list<SectionBoundaries> section_boundaries;
std::list<UINT32> byte_tainted_addr;
std::list<REG> regsTainted;
std::list<ADDRINT> addr_list;
std::list<string> func_names;
std::list<RoutineAccessList> rtns_list;
std::list<RoutineArgs> rtns_args_list;
RoutineAccessList rtn_current;


UINT lockTaint	= LOCKED;
UINT lastSize		= 0;


BOOL bFileDetected = false;
BOOL TAINTING = false;
/* ================================================================== */
// Algorithms...
/* ================================================================== */
BOOL checkAlreadyRegisterTainted(REG reg)
{
	// 레지스터가 이미 Taint 되어있는지를 검사
	list<REG>::iterator i;

	for ( i = RegTainted.begin(); i != RegTainted.end(); i++ )
	{
		if ( *i == reg )
			return true;
		
	}

	return false;
}

VOID removeMemTainted(UINT addr)
{
	addressTainted.remove(addr);
	fprintf( pLOG_FILE, "[-] [FREED] 0x%X is now freed\n", addr );
}

VOID addMemTainted(UINT addr)
{
	addressTainted.push_back(addr);
	fprintf( pLOG_FILE, "[-] [NEW] 0x%X is now tainted\n", addr );
}

BOOL taintReg(REG reg)	// 오염함
{
	if ( checkAlreadyRegisterTainted(reg) == true )
	{
		fprintf( pLOG_FILE, "\t%s is already tainted\n", REG_StringShort( reg ).c_str() );
		return false;
	}

	switch (reg)
	{
		case REG_EAX:	RegTainted.push_front(REG_EAX);
		case REG_AX:	RegTainted.push_front(REG_AX);
		case REG_AH:	RegTainted.push_front(REG_AH);
		case REG_AL:	RegTainted.push_front(REG_AL);
			break;

		case REG_EBX:	RegTainted.push_front(REG_EBX);
		case REG_BX:	RegTainted.push_front(REG_BX);
		case REG_BH:	RegTainted.push_front(REG_BH);
		case REG_BL:	RegTainted.push_front(REG_BL);
			break;

		case REG_ECX:	RegTainted.push_front(REG_ECX);
		case REG_CX:	RegTainted.push_front(REG_CX);
		case REG_CH:	RegTainted.push_front(REG_CH);
		case REG_CL:	RegTainted.push_front(REG_CL);
			break;

		case REG_EDX:	RegTainted.push_front(REG_EDX);
		case REG_DX:	RegTainted.push_front(REG_DX);
		case REG_DH:	RegTainted.push_front(REG_DH);
		case REG_DL:	RegTainted.push_front(REG_DL);
			break;
		
		case REG_EDI:	RegTainted.push_front(REG_EDI);
		case REG_DI:	RegTainted.push_front(REG_DI);
			break;

		case REG_ESI:	RegTainted.push_front(REG_ESI);
		case REG_SI:	RegTainted.push_front(REG_SI);
			break;
		
		default:
			fprintf( pLOG_FILE, "\t%s can't be taintd\n", REG_StringShort( reg ).c_str() );
			return false;	// can't be tainted
	}
	fprintf( pLOG_FILE, "[-] [NEW TAINT OBJECT] %s is now tainted\n", REG_StringShort( reg ).c_str() );
	return true;
}

BOOL removeRegTainted(REG reg)	// free 함
{
	switch (reg)
	{
		case REG_EAX:	RegTainted.remove(REG_EAX);
		case REG_AX:	RegTainted.remove(REG_AX);
		case REG_AH:	RegTainted.remove(REG_AH);
		case REG_AL:	RegTainted.remove(REG_AL);
			break;

		case REG_EBX:	RegTainted.remove(REG_EBX);
		case REG_BX:	RegTainted.remove(REG_BX);
		case REG_BH:	RegTainted.remove(REG_BH);
		case REG_BL:	RegTainted.remove(REG_BL);
			break;

		case REG_ECX:	RegTainted.remove(REG_ECX);
		case REG_CX:	RegTainted.remove(REG_CX);
		case REG_CH:	RegTainted.remove(REG_CH);
		case REG_CL:	RegTainted.remove(REG_CL);
			break;

		case REG_EDX:	RegTainted.remove(REG_EDX);
		case REG_DX:	RegTainted.remove(REG_DX);
		case REG_DH:	RegTainted.remove(REG_DH);
		case REG_DL:	RegTainted.remove(REG_DL);
			break;

		case REG_EDI:	RegTainted.remove(REG_EDI);
		case REG_DI:	RegTainted.remove(REG_DI);
			break;

		case REG_ESI:	RegTainted.remove(REG_ESI);
		case REG_SI:	RegTainted.remove(REG_SI);
			break;

		default:
			return false;	// not yet, freed
	}
	fprintf( pLOG_FILE, "[-] [TAINTED OBJECT FREED] %s is now freed\n", REG_StringShort( reg ).c_str() );
	return true;
}

VOID ReadMem(UINT insAddr, char* insDis, UINT OpCount, REG reg_r, UINT memOp, UINT sp)
{
	list<UINT>::iterator i;
	list<mallocArea>::iterator i2;	/* Not ready */
	UINT addr = memOp;

	
	for ( i = addressTainted.begin(); i != addressTainted.end(); i++ )
	{	// 검사 후, 오염이 기존에 안됬을 경우, 오염시작
		if ( addr == *i )
		{
			fprintf( pLOG_FILE, "[-] [HIT:READ] addr 0x%x in IP(0x%X): %s \n", addr, insAddr, insDis );
			taintReg(reg_r);
#if 1
			if (!check_tainted_boundaries(addr))
				fprintf( pLOG_FILE, "[VULN read in %X at %X\n", addr , insAddr);
#endif
			return;
		}
	}


	
	if ( checkAlreadyRegisterTainted(reg_r) )
	{
		fprintf( pLOG_FILE, "[-] [HIT:READ] addr 0x%x in IP(0x%X): %s \n", addr, insAddr, insDis );
		removeRegTainted(reg_r);
	}
	
}

VOID WriteMem(UINT insAddr, char* insDis, UINT OpCount, REG reg_r, UINT memOp, UINT sp)
{
	list<UINT>::iterator i;
	list<mallocArea>::iterator i2;	/* Not Ready */
	UINT addr = memOp;
	
	for ( i = addressTainted.begin(); i != addressTainted.end(); i++ )
	{
		if ( addr == *i )
		{
			fprintf( pLOG_FILE, "[-] [HIT:WRITE] addr 0x%X in IP(0x%X): %s \n", addr, insAddr, insDis );

#if 1
			if (!check_tainted_boundaries(addr))
            fprintf( pLOG_FILE, "[VULN write in %X at %X\n", addr , insAddr);
#endif


			if ( !REG_valid(reg_r) || !checkAlreadyRegisterTainted(reg_r) )
				removeMemTainted(addr);

			return;
		}
	}

	if ( checkAlreadyRegisterTainted(reg_r) )
	{
		fprintf( pLOG_FILE, "[-] [HIT:WRITE] addr 0x%X in IP(0x%X): %s \n", addr, insAddr, insDis );
		addMemTainted(addr);
	}
}


VOID callbackBeforeMalloc(ADDRINT size)
{
	lastSize = size;
}

VOID callbackBeforeFree(ADDRINT addr)
{
	if ( bFileDetected == false )
		return ;

	list<mallocArea>::iterator i;

	//fprintf( pLOG_FILE, "[*] [INFO] malloc (\" 0x%X \")\n", addr);

	for ( i = mallocAreaList.begin(); i != mallocAreaList.end(); i++ )
	{
		if ( addr == i->base )
		{
			i->status = FREE;
			break;
		}
	}
}

VOID callbackAfterMalloc(ADDRINT ret)
{
	if ( bFileDetected == false )
		return ;

	list<mallocArea>::iterator i;
	mallocArea elem;
	
	//fprintf( pLOG_FILE, "[*] [INFO] free (\" 0x%X \") = 0x%X\n", lastSize, ret);
	
	if ( ret )
	{
		for ( i = mallocAreaList.begin(); i != mallocAreaList.end(); i++ )
		{
			if ( ret == i->base )
			{
				i->status = ALLOCATE;
				i->size = lastSize;
				return;
			}
		}
		elem.base = ret;
		elem.size = lastSize;
		elem.status = ALLOCATE;

		mallocAreaList.push_front(elem);
	}
}

VOID followData(UINT insAddr, char* insDis, REG reg)
{
	if ( !REG_valid(reg) )
		return;

	if ( checkAlreadyRegisterTainted(reg) )
		fprintf(pLOG_FILE, "[FOLLOW]\t\t 0x%X %s\n" ,insAddr, insDis);
}

VOID spreadRegTaint(UINT insAddr, char* insDis, UINT OpCount, REG reg_r, REG reg_w)
{
	if ( REG_valid(reg_w) ) 
	{
		if ( checkAlreadyRegisterTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegisterTainted(reg_r)))
		{
			fprintf( pLOG_FILE, "[-] [SPREAD] 0x%X : %s\n", insAddr, insDis );
			//cout << "\t\t\toutput: "<< REG_StringShort(reg_w).c_str() << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r).c_str() : "constant") << endl;
			removeMemTainted(reg_w);
		}
		else if ( !checkAlreadyRegisterTainted(reg_w) && checkAlreadyRegisterTainted(reg_r) )
		{
			fprintf( pLOG_FILE, "[-] [SPREAD] 0x%X : %s\n", insAddr, insDis );
			//cout << "\t\t\toutput: " << REG_StringShort(reg_w).c_str() << " | input: "<< REG_StringShort(reg_r).c_str() << endl;
			taintReg(reg_w);
		}
	}
}

VOID Image(IMG img, VOID *v)
{
#if 0
	RTN mallocRtn = RTN_FindByName(img, "malloc");
	RTN freeRtn = RTN_FindByName(img, "free");

	if ( RTN_Valid(mallocRtn) )
	{
		RTN_Open(mallocRtn);

		RTN_InsertCall( mallocRtn, IPOINT_BEFORE, (AFUNPTR)callbackBeforeMalloc,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_END );

		RTN_InsertCall( mallocRtn, IPOINT_BEFORE, (AFUNPTR)callbackAfterMalloc,
						IARG_FUNCRET_EXITPOINT_VALUE,
						IARG_END );
		RTN_Close(mallocRtn);
	}
	
	if ( RTN_Valid(freeRtn) )
	{
		RTN_Open(freeRtn);
		RTN_InsertCall( freeRtn, IPOINT_BEFORE, (AFUNPTR)callbackBeforeFree,
						IARG_FUNCRET_EXITPOINT_VALUE,
						IARG_END );
		RTN_Close(freeRtn);
	}
#endif
	RTN FuncRtn = RTN_FindByName(img, OPENFILE);
	if ( RTN_Valid( FuncRtn ) )
	{
		RTN_Open( FuncRtn );

		RTN_InsertCall( FuncRtn,
						IPOINT_BEFORE, (AFUNPTR)CreateFileWBefore,
						IARG_ADDRINT, OPENFILE,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_END );

		RTN_InsertCall( FuncRtn,
						IPOINT_BEFORE, (AFUNPTR)CreateFileWAfter,
						IARG_FUNCRET_EXITPOINT_VALUE,
						IARG_END );

		RTN_Close( FuncRtn );
	}

	RTN FuncRtn2 = RTN_FindByName(img, READFILE);
	if ( RTN_Valid( FuncRtn2 ) )
	{
		RTN_Open( FuncRtn2 );

		RTN_InsertCall( FuncRtn2,
						IPOINT_BEFORE, (AFUNPTR)ReadFileBefore,
						IARG_ADDRINT, READFILE,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_END );

		RTN_InsertCall( FuncRtn2,
						IPOINT_BEFORE, (AFUNPTR)ReadFileAfter,
						IARG_FUNCRET_EXITPOINT_VALUE,
						IARG_END );

		RTN_Close( FuncRtn2 );
	}
	/*
	RTN FuncRtn3 = RTN_FindByName(img, CLOSEHANDLE);
	if ( RTN_Valid( FuncRtn3 ) )
	{
		RTN_Open( FuncRtn3 );
		
		RTN_InsertCall( FuncRtn3,
						IPOINT_BEFORE, (AFUNPTR)CallbackAfterCloseHandle,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_END );

		RTN_Close( FuncRtn3 );
		
	}
	*/
	RTN mallocRtn = RTN_FindByName(img, "malloc");
	RTN freeRtn = RTN_FindByName(img, "free");

	if ( RTN_Valid( mallocRtn ) )
	{
		RTN_Open( mallocRtn );

		RTN_InsertCall( mallocRtn,
						IPOINT_BEFORE, (AFUNPTR)callbackBeforeMalloc,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_END );

		RTN_InsertCall( mallocRtn,
						IPOINT_BEFORE, (AFUNPTR)callbackAfterMalloc,
						IARG_FUNCRET_EXITPOINT_VALUE,
						IARG_END );

		RTN_Close( mallocRtn );

	}

	if ( RTN_Valid( freeRtn ) )
	{
		RTN_Open( freeRtn );

		RTN_InsertCall( freeRtn,
						IPOINT_BEFORE, (AFUNPTR)callbackBeforeFree,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_END );

		RTN_Close( freeRtn );


	}

}


VOID CreateFileWBefore(char* func_name, char* arg0)
{
	
	char filename[200];
	memset( filename, 0x00, 200 );
	

	sprintf( filename, "%ls", arg0 );
	if ( strcmp( filename, TARGET_FILENAME ) == 0 /*&& TAINTING == false*/ )
	{
		fprintf( pLOG_FILE, "[~] Catch!\n");
		fprintf( pLOG_FILE, "%s(%ls)\n", func_name, arg0 );
		bFileDetected = true;
	}
}

VOID CreateFileWAfter(UINT retval)
{
	
	//if ( bFileDetected == true /*&& TAINTING == false*/ )
		//fprintf( pLOG_FILE, "\treturn values : 0x%x\n", retval );

	if ( bFileDetected == true && retval != 0 /*&& TAINTING == false*/ )
	{
		fprintf( pLOG_FILE, "[TARGET FILE OPEN] TARGET_FILE_HANDLE : 0x%X\n", retval );
		targetFileHandles.push_back(retval);
		//TAINTING = true;
	} 
}
VOID ReadFileBefore(char* func_name, UINT handle, UINT buffer, UINT length )
{
	//fprintf( pLOG_FILE, "%s(0x%X, 0x%X, 0x%X)\n", func_name, handle, buffer, length );
	if ( bFileDetected == true )
	{
		addMemTainted( buffer );
		bFileDetected = false;
	}

}


VOID ReadFileAfter(ADDRINT retval, UINT length )
{
	//fprintf( pLOG_FILE, "\treturn values : 0x%X (Length : 0x%X)\n", retval, length );

}

VOID CallbackAfterCloseHandle(UINT retval)
{
	if ( bFileDetected == true && retval != 0 )
	{
		fprintf( pLOG_FILE, "[TARGET FILE CLOSE] TARGET_FILE_HANDLE : 0x%X\n", retval );
		targetFileHandles.remove(retval);
	}

}


#if 0
static unsigned int lock;
#define TRICKS(){ if (lock++ == 0 ) return; }
VOID SysCall_Entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	Range taint;

	if ( PIN_GetSyscallNumber(ctx, std) )
	{
		TRICKS();
		taint.start = static_cast<UINT>((PIN_GetSyscallArgument(ctx, std,1)));

		taint.end	= taint.start + static_cast<UINT>((PIN_GetSyscallArgument(ctx, std, 2)));
		byteTainted.push_back(taint);

		OutFile << "[TAINT]\t\t\tbytes tainted from " << hex << "0x" << taint.start << " to 0x" << taint.end << " (via read)" << endl;

	}

}
#endif

bool check_tainted_boundaries(UINT32 addr)
{
	list<UINT32>::iterator i;
	list<RoutineAccessList>::iterator m;
	list<UINT32>::iterator access_list_it;

	/* check stack access */
	if ( addr <= stack_allocated.stack_start && 
        addr >= stack_allocated.stack_end) {
        if (addr >= rtn_current.routine_stack_current &&
                addr < rtn_current.routine_stack_base) {
                    // OutFile << "correct access in routine stack frame (local vars)" << endl;
					fprintf(pLOG_FILE, " --[#] correct access in routine stack frame (local vars)\n");
                    return true; /* correct access in routine stack frame */
        } else if (rtn_current.has_stack_access == true) {
            for (m = rtns_list.begin(); m != rtns_list.end(); m++) {
                for (access_list_it = m->access_list.begin();
                        access_list_it != m->access_list.end(); access_list_it++) {
                            if (addr == *access_list_it) {
                                //OutFile << "correct access to routine arg" << endl;
								fprintf(pLOG_FILE, " --[#] correct access to routine arg\n");
                                return true; /* correct access to routine arg */
                            }
                }
            }
            //OutFile << "incorrect access to stack of prev. routines " << endl;
			fprintf(pLOG_FILE, " --[#] incorrect access to stack of prev. routines \n");
            return false; /* incorrect access to stack of previous routines */
        } else {
            //OutFile << "incorrect access to stack of prev. routines  or ret. addr" << endl;
			fprintf(pLOG_FILE, " --[#] incorrect access to stack of prev. routines or ret. addr \n");

			return false /* incorrect access to stack of previous routines */;
        }
    }

    /* check heap access */
    for (i = rtn_current.access_list.begin(); i != rtn_current.access_list.end(); i++) {
        if (addr == *i) {
            //OutFile << "correct access to heap" << endl;
			fprintf(pLOG_FILE, " --[#] correct access to heap\n");
            return true; /* correct access to heap */
        }
    }
    /* check heap access to some other routine */
    for (m = rtns_list.begin(); m != rtns_list.end(); m++) {
        for (access_list_it = m->access_list.begin();
                access_list_it != m->access_list.end(); access_list_it++) {
                    if (addr == *access_list_it) {
                        //OutFile << std::hex << "incorrect access to heap of routine: " << m->routine_addr << endl;
						fprintf(pLOG_FILE, " --[#] incorrect access to heap of routine: 0x%X\n", m->routine_addr); 
						return false; /* correct access to routine arg */
                    }
        }
    }
    //OutFile << "correct access to some mem. region" << endl;
	fprintf(pLOG_FILE, " --[#] correct access to some mem. region\n");
    return true;

}

VOID Instruction(INS ins, VOID *v)
{
	//OutFile.setf(ios::showbase);
	
	if ( ( INS_OperandCount(ins) != 2 ) || ( INS_Address(ins) == 0xffffffff ) )
		return;
		
	
	if ( INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0) )
	{
		INS_InsertCall( ins, 
						IPOINT_BEFORE, (AFUNPTR)ReadMem,
						IARG_ADDRINT, INS_Address(ins),
						IARG_PTR, INS_Disassemble(ins).c_str(),
						IARG_UINT32, INS_OperandCount(ins),
						IARG_UINT32, INS_OperandReg(ins, 0),
						IARG_MEMORYOP_EA, 0,
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_END );
	}		
	
	else if ( INS_MemoryOperandIsWritten(ins, 0) )
	{
		INS_InsertCall( ins, 
						IPOINT_BEFORE, (AFUNPTR)WriteMem,
						IARG_ADDRINT, INS_Address(ins),
						IARG_PTR, INS_Disassemble(ins).c_str(),
						IARG_UINT32, INS_OperandCount(ins),
						IARG_UINT32, INS_OperandReg(ins, 0),
						IARG_MEMORYOP_EA, 0,
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_END );
	}
	else if ( INS_OperandIsReg(ins, 0) )
	{
		INS_InsertCall( ins,
						IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
						IARG_ADDRINT, INS_Disassemble(ins).c_str(),
						IARG_UINT32, INS_OperandCount(ins),
						IARG_UINT32, INS_RegR(ins, 0),
						IARG_UINT32, INS_RegW(ins, 0),
						IARG_END );
	}
	
	
	if ( INS_OperandIsReg(ins, 0) )
	{
		INS_InsertCall( ins,
						IPOINT_BEFORE, (AFUNPTR)followData,
						IARG_ADDRINT, INS_Disassemble(ins).c_str(),
						IARG_UINT32, INS_RegR(ins, 0),
						IARG_END );
	}
}
#endif


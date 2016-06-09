
/***
*
* 2016.06.02
* korea.devsec@gmail.com
*
***/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <list>
#include <stdio.h>
using namespace std;

#define MALLOC "malloc"
#define FREE "free"
#define OPENFILE "CreateFileW"
#define READFILE "ReadFile"

#define LOG_FILENAME "c:\\output.txt"
FILE *LOG_FILE = NULL;

#define TARGET_FILENAME "C:\\input.hwp"
std::list<UINT> Target_File_Handle;
std::list<struct mallocArea>    mallocAreaList;

struct Range
{
	UINT start;
	UINT end;
};

struct mallocArea
{
	UINT  base;
	UINT  size;
	BOOL  status;
};


std::list<UINT> Tainted_Object;
std::list<REG> RegTainted;

// some global logical values
BOOL ANALIZING = 0;
BOOL FileName = 0;
static size_t lastSize;

bool checkAlreadyRegTainted(REG reg)
{
	list<REG>::iterator i;

	for(i = RegTainted.begin(); i != RegTainted.end(); i++){
		if (*i == reg){
			return true;
		}
	}
	return false;
}

VOID addMemTainted(UINT addr)
{
	//ANALIZING = 1;	// RUNNING
	Tainted_Object.push_back(addr);
	fprintf( LOG_FILE, "[-] [NEW] 0x%x is now tainted\n", addr );
}

VOID removeMemTainted(UINT addr)
{
	ANALIZING = 0;	// STOP
	Tainted_Object.remove(addr);
	fprintf( LOG_FILE, "[-] [FREED] 0x%x is now freed\n", addr );
}

VOID callbackBeforeMalloc(ADDRINT size)
{
	lastSize = size;
}

VOID callbackBeforeFree(ADDRINT addr)
{ 
	if( ANALIZING ){
		list<struct mallocArea>::iterator i;

		//std::cout << "[INFO]\t\tfree(" << std::hex << addr << ")" << std::endl;
		fprintf( LOG_FILE, "[*] [INFO] malloc (\" 0x%x \")\n", addr);
		for(i = mallocAreaList.begin(); i != mallocAreaList.end(); i++){
			if (addr == i->base){
				i->status = 0;	// FREE
				break;
			}
		}
	}
}

VOID callbackAfterMalloc(ADDRINT ret)
{
	if( ANALIZING ){
		list<struct mallocArea>::iterator i;
		struct mallocArea elem;

		//std::cout << "[INFO]\t\tmalloc (" << lastSize << ") = " << std::hex << ret << std::endl;
		fprintf( LOG_FILE, "[*] [INFO] malloc (\" 0x%x \") = 0x%x\n", lastSize, ret);
		if (ret){

			for(i = mallocAreaList.begin(); i != mallocAreaList.end(); i++){
				if (ret == i->base){
					i->status = 1;	// ALLOCATE
					i->size = lastSize;
					return;
				}
			}
			elem.base = ret;
			elem.size = lastSize;
			elem.status = 1;	// ALOCATE
			mallocAreaList.push_front(elem);
		}
	}
}

bool taintReg(REG reg)
{
	if (checkAlreadyRegTainted(reg) == true){
		fprintf( LOG_FILE, "\t%s is already tainted\n", REG_StringShort( reg ).c_str() );
		//std::cout << "\t\t\t" << REG_StringShort(reg) << " is already tainted" << std::endl;
		//ANALIZING = 1;	// ANALIZING ON
		return false;
	}

	switch(reg){

	case REG_EAX:  RegTainted.push_front(REG_EAX); 
	case REG_AX:   RegTainted.push_front(REG_AX); 
	case REG_AH:   RegTainted.push_front(REG_AH); 
	case REG_AL:   RegTainted.push_front(REG_AL); 
		break;

	case REG_EBX:  RegTainted.push_front(REG_EBX);
	case REG_BX:   RegTainted.push_front(REG_BX);
	case REG_BH:   RegTainted.push_front(REG_BH);
	case REG_BL:   RegTainted.push_front(REG_BL);
		break;

	case REG_ECX:  RegTainted.push_front(REG_ECX);
	case REG_CX:   RegTainted.push_front(REG_CX);
	case REG_CH:   RegTainted.push_front(REG_CH);
	case REG_CL:   RegTainted.push_front(REG_CL);
		break;

	case REG_EDX:  RegTainted.push_front(REG_EDX); 
	case REG_DX:   RegTainted.push_front(REG_DX); 
	case REG_DH:   RegTainted.push_front(REG_DH); 
	case REG_DL:   RegTainted.push_front(REG_DL); 
		break;

	case REG_EDI:  RegTainted.push_front(REG_EDI); 
	case REG_DI:   RegTainted.push_front(REG_DI); 
		break;

	case REG_ESI:  RegTainted.push_front(REG_ESI); 
	case REG_SI:   RegTainted.push_front(REG_SI);  
		break;

	default:
		fprintf( LOG_FILE, "\t%s can't be taintd\n", REG_StringShort( reg ).c_str() );

		// std::cout << "\t\t\t" << REG_StringShort(reg) << " can't be tainted" << std::endl;
		return false;
	}
	fprintf( LOG_FILE, "[-] [NEW TAINT OBJECT] %s is now tainted\n", REG_StringShort( reg ).c_str() );
	//ANALIZING = 1;	// ANALIZING ON

	//std::cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted" << std::endl;
	return true;
}

bool removeRegTainted(REG reg)
{
	switch(reg){

	case REG_EAX:  RegTainted.remove(REG_EAX);
	case REG_AX:   RegTainted.remove(REG_AX);
	case REG_AH:   RegTainted.remove(REG_AH);
	case REG_AL:   RegTainted.remove(REG_AL);
		break;

	case REG_EBX:  RegTainted.remove(REG_EBX);
	case REG_BX:   RegTainted.remove(REG_BX);
	case REG_BH:   RegTainted.remove(REG_BH);
	case REG_BL:   RegTainted.remove(REG_BL);
		break;

	case REG_ECX:  RegTainted.remove(REG_ECX);
	case REG_CX:   RegTainted.remove(REG_CX);
	case REG_CH:   RegTainted.remove(REG_CH);
	case REG_CL:   RegTainted.remove(REG_CL);
		break;

	case REG_EDX:  RegTainted.remove(REG_EDX); 
	case REG_DX:   RegTainted.remove(REG_DX); 
	case REG_DH:   RegTainted.remove(REG_DH); 
	case REG_DL:   RegTainted.remove(REG_DL); 
		break;

	case REG_EDI:  RegTainted.remove(REG_EDI); 
	case REG_DI:   RegTainted.remove(REG_DI); 
		break;

	case REG_ESI:  RegTainted.remove(REG_ESI); 
	case REG_SI:   RegTainted.remove(REG_SI);  
		break;

	default:
		return false;
	}
	fprintf( LOG_FILE, "[-] [TAINTED OBJECT FREED] %s is now freed\n", REG_StringShort( reg ).c_str() );
	ANALIZING = 0;	// STOP

	//std::cout << "\t\t\t" << REG_StringShort(reg) << " is now freed" << std::endl;
	return true;
}

// CreateFileW case for notepad
VOID CreateFileWBefore(CHAR * func_name, CHAR *arg0 )
{
	CHAR filename[200];
	memset( filename, 0x00, 200 );

	//fprintf( LOG_FILE, "[-] %s(%ls)\n", func_name, arg0 );

	sprintf( filename, "%ls", arg0 );
	if( strcmp( filename, TARGET_FILENAME ) == 0 )
	{
		FileName = 1;
	}

}

VOID CreateFileWAfter(ADDRINT retval )
{
	///fprintf( LOG_FILE, "\treturn values : 0x%x\n", retval );

	if( FileName == 1 && retval != 0 ) {
		fprintf( LOG_FILE, "[-] [TARGET FILE OPEN] TARGET_FILE_HANDLE : 0x%x\n", retval );
		Target_File_Handle.push_back( retval );
		//ANALIZING = 1;	// RUNNING
	}
}

VOID ReadFileBefore(CHAR *func_name, UINT handle, UINT buffer, UINT length )
{
	//fprintf( LOG_FILE, "[-] %s(0x%x, 0x%x, 0x%x)\n", func_name, handle, buffer, length );
	if( FileName == 1 ) {
		addMemTainted( buffer );
		FileName = 0;
	}
}

VOID ReadFileAfter(ADDRINT retval, UINT length )
{
	//fprintf( LOG_FILE, "\treturn values : 0x%x (%x)\n", retval, length );
}

VOID Image(IMG img, VOID *v)
{
	RTN FuncRtn = RTN_FindByName(img, OPENFILE);
	if( RTN_Valid( FuncRtn ) ) {
		RTN_Open( FuncRtn );

		RTN_InsertCall( FuncRtn, 
			IPOINT_BEFORE, (AFUNPTR)CreateFileWBefore,
			IARG_ADDRINT, OPENFILE,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END );

		RTN_InsertCall( FuncRtn, 
			IPOINT_AFTER, (AFUNPTR)CreateFileWAfter,
			IARG_FUNCRET_EXITPOINT_VALUE, 
			IARG_END );

		RTN_Close( FuncRtn );
	}

	RTN FuncRtn2 = RTN_FindByName(img, READFILE);
	if( RTN_Valid( FuncRtn2 ) ) {
		RTN_Open( FuncRtn2 );

		RTN_InsertCall( FuncRtn2, 
			IPOINT_BEFORE, (AFUNPTR)ReadFileBefore,
			IARG_ADDRINT, READFILE,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END );

		RTN_InsertCall( FuncRtn2, 
			IPOINT_AFTER, (AFUNPTR)ReadFileAfter,
			IARG_FUNCRET_EXITPOINT_VALUE, 
			IARG_END );

		RTN_Close( FuncRtn2 );
	}

	RTN mallocRtn = RTN_FindByName(img, "malloc");
	RTN freeRtn = RTN_FindByName(img, "free");

	if (RTN_Valid(mallocRtn)){
		RTN_Open(mallocRtn);

		RTN_InsertCall(
			mallocRtn, 
			IPOINT_BEFORE, (AFUNPTR)callbackBeforeMalloc,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_InsertCall(
			mallocRtn, 
			IPOINT_AFTER, (AFUNPTR)callbackAfterMalloc,
			IARG_FUNCRET_EXITPOINT_VALUE, 
			IARG_END);

		RTN_Close(mallocRtn);
	}

	if (RTN_Valid(freeRtn)){
		RTN_Open(freeRtn);
		RTN_InsertCall(
			freeRtn, 
			IPOINT_BEFORE, (AFUNPTR)callbackBeforeFree,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

		RTN_Close(freeRtn);
	}
}


VOID ReadMem( ADDRINT Ret_INS, UINT memOp, char* pStr, REG reg_r, UINT sp)
{

	list<UINT>::iterator i;
	list<struct mallocArea>::iterator i2;
	UINT addr = memOp;

	if( ANALIZING ){
		for(i2 = mallocAreaList.begin(); i2 != mallocAreaList.end(); i2++){
			if (addr >= i2->base && addr < (i2->base + i2->size) && i2->status == 0){
				fprintf( LOG_FILE, "[!] [UAF in 0x%x] in IP(0x%x) : %s \n", addr, Ret_INS, pStr);
				//std::cout << std::hex << "[UAF in " << addr << "]\t" << Ret_INS << ": " << pStr << std::endl;
				return;
			}
		}
	}

	for( i = Tainted_Object.begin(); i != Tainted_Object.end(); i ++ ) {

		if( addr == *i )
		{
			//printf("[+] READ addr 0x%x, IP: 0x%d\n", addr, Ret_INS);
			fprintf( LOG_FILE, "[-] [HIT:READ] addr 0x%x in IP(0x%x): %s \n", addr, Ret_INS, pStr );
			fprintf( LOG_FILE, "[-] %s\n", pStr );
			/*
			if( ANALIZING ){
			if (sp > addr && addr > 0x70000000 )
			fprintf( LOG_FILE, "[!] [UAF in 0x%x] in IP(0x%x) : %s \n", addr, Ret_INS, pStr);
			}
			*/
			taintReg( reg_r );
			return;

		}
	}

	/* if mem != tainted and reg == taint => free */
	if ( checkAlreadyRegTainted( reg_r ) ) {
		//printf("[+] READ addr 0x%x, IP: 0x%d\n", addr, Ret_INS);
		fprintf( LOG_FILE, "[-] [HIT:READ] addr 0x%x in IP(0x%x): %s \n", addr, Ret_INS, pStr );
		fprintf( LOG_FILE, "[-] %s\n", pStr );
		//std::cout << std::hex << "[READ in " << addr << "]\t" << Ret << ": " << INS_Disassemble(ins) << std::endl;
		removeRegTainted( reg_r );
	}

}

VOID WriteMem( ADDRINT Ret_INS, UINT memOp, char* pStr, REG reg_r, UINT sp )
{
	list<UINT>::iterator i;
	list<struct mallocArea>::iterator i2;
	UINT addr = memOp;

	if( ANALIZING ){
		for(i2 = mallocAreaList.begin(); i2 != mallocAreaList.end(); i2++){
			if (addr >= i2->base && addr < (i2->base + i2->size) && i2->status == 0){
				fprintf( LOG_FILE, "[!] [UAF in 0x%x] in IP(0x%x) : %s \n", addr, Ret_INS, pStr);
				//std::cout << std::hex << "[UAF in " << addr << "]\t" << Ret_INS << ": " << pStr << std::endl;
				return;
			}
		}
	}

	for( i = Tainted_Object.begin(); i != Tainted_Object.end(); i++ ) {
		if ( addr == *i ) {
			//printf("[+] WRITE addr 0x%x, IP: 0x%d\n", addr, Ret_INS);
			fprintf( LOG_FILE, "[-] [HIT:WRITE] addr 0x%x in IP(0x%x): %s\n", addr, Ret_INS, pStr );
			fprintf( LOG_FILE, "[-] %s\n", pStr );
			//std::cout << std::hex << "[WRITE in " << addr << "]\t" << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;
			if ( !REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r) )
				removeMemTainted( addr );
			/*
			if( ANALIZING ){
			if (sp > addr && addr > 0x70000000)
			fprintf( LOG_FILE, "[!] [UAF in 0x%x] in IP(0x%x) : %s \n", addr, Ret_INS, pStr);
			//std::cout << std::hex << "[UAF in " << addr << "]\t" << Ret_INS << ": " << pStr << std::endl;

			}
			*/
			return ;
		}
	}

	if (checkAlreadyRegTainted(reg_r)){
		//printf("[+] WRITE addr 0x%x, IP: 0x%d\n", addr, Ret_INS);
		fprintf( LOG_FILE, "[-] [HIT:WRITE] addr 0x%x in IP(0x%x): %s\n", addr, Ret_INS, pStr );
		fprintf( LOG_FILE, "[-] %s\n", pStr );
		//std::cout << std::hex << "[WRITE in " << addr << "]\t" << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;
		addMemTainted(addr);
	}

}

VOID spreadRegTaint( ADDRINT Ret_INS, REG reg_r , REG reg_w, char* pStr )
{

	if (REG_valid(reg_w)){
		if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))){
			fprintf( LOG_FILE, "[-] [SPREAD] 0x%x : %s\n", Ret_INS, pStr);
			//std::cout << "[SPREAD]\t\t" << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;
			//std::cout << "\t\t\toutput: "<< REG_StringShort(reg_w) << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
			removeRegTainted(reg_w);
		}
		else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)){
			fprintf( LOG_FILE, "[-] [SPREAD] 0x%x : %s\n", Ret_INS, pStr);
			//std::cout << "[SPREAD]\t\t" << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;
			//std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: "<< REG_StringShort(reg_r) << std::endl;
			taintReg(reg_w);
		}
	}
}

VOID Instruction(INS ins, VOID *v)
{

	if ( ( INS_OperandCount(ins) != 2 ) ||  ( INS_Address( ins ) == 0xffffffff ) )
		return ;

	if( INS_MemoryOperandIsRead( ins, 0 ) && INS_OperandIsReg( ins, 0 ) ) {


		INS_InsertCall( ins,
			IPOINT_BEFORE, (AFUNPTR)ReadMem, 
			IARG_ADDRINT, INS_Address(ins),
			IARG_MEMORYOP_EA, 0,
			IARG_PTR, INS_Disassemble( ins ).c_str(),
			IARG_UINT32 , INS_OperandReg( ins, 0 ),
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END );

	} 

	else if( INS_MemoryOperandIsWritten( ins, 0 ) ) {

		INS_InsertCall( ins,
			IPOINT_BEFORE, (AFUNPTR)WriteMem, 
			IARG_ADDRINT, INS_Address(ins),
			IARG_MEMORYOP_EA, 0,
			IARG_PTR, INS_Disassemble( ins ).c_str(),
			IARG_UINT32 , INS_OperandReg( ins, 1 ),
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END );

	}

	else if( INS_OperandIsReg(ins, 0 ) ) {

		INS_InsertCall( ins,
			IPOINT_BEFORE, (AFUNPTR)spreadRegTaint, 
			IARG_ADDRINT, INS_Address(ins),
			IARG_UINT32, INS_RegR(ins, 0),
			IARG_UINT32, INS_RegW(ins, 0),
			IARG_PTR, INS_Disassemble( ins ).c_str(),
			IARG_END );

	}


}

VOID Fini(INT32 code, VOID *v)
{
	fprintf( LOG_FILE, "[*] =====================================\n" );
	fprintf( LOG_FILE, "[#] End of File.\n" );
	fprintf( LOG_FILE, "[*] =====================================\n" );
	fprintf( LOG_FILE, "[-] Result : \"%s\" saved.\n", LOG_FILENAME );
	fprintf( LOG_FILE, "[*] =====================================\n" );
	fclose( LOG_FILE );

}


INT32 Usage()
{
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

int main(int argc, char *argv[])
{
	//fprintf(LOG_FILE, "Test\n");

	PIN_InitSymbols();
	if( PIN_Init(argc,argv) )
	{
		return Usage();
	}

	LOG_FILE = fopen( LOG_FILENAME, "w" );
	if( LOG_FILE == NULL )
		return -1;


	fprintf(LOG_FILE, "[*] =====================================\n");
	fprintf(LOG_FILE, "[*] Simple Taint Analysis Tool\n");
	fprintf(LOG_FILE, "[*] korea.devsec@gmail.com\n");
	fprintf(LOG_FILE, "[*] =====================================\n");
	fprintf(LOG_FILE, "[+] \"%s\" Tracing...\n", TARGET_FILENAME);
	fprintf(LOG_FILE, "[*] =====================================\n");	

	IMG_AddInstrumentFunction( Image, 0);

	INS_AddInstrumentFunction( Instruction, 0 );

	PIN_AddFiniFunction( Fini, 0);

	//std::cout << "test" << endl;
	PIN_StartProgram();




	return 0;
}
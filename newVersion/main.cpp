/* ================================================================== */
//
//	Created By Lim Dongho (korea.devsec@gmail.com)
//
//	2016 Kangnam University Graduation Works
//	Copyleft(c), reference for : http://github.com/krdevsec
//
/* ================================================================== */

#include "resources.hpp"
FILE* pLOG_FILE		=	NULL;
/* ================================================================== */
// Destructor of Main Function
/* ================================================================== */
VOID Fini(INT32 code, VOID *v)
{
	fprintf( pLOG_FILE, "[*] =====================================\n" );
	fprintf( pLOG_FILE, "[#] End of File.\n" );
	fprintf( pLOG_FILE, "[*] =====================================\n" );
	fprintf( pLOG_FILE, "[-] Result : \"%s\" saved.\n", LOG_FILE );
	fprintf( pLOG_FILE, "[*] =====================================\n" );
	fclose(pLOG_FILE);
}

/* ================================================================== */
// if Exception Error -> Usage Function Call
/* ================================================================== */
int Usage()
{
	return -1;
}
/* ================================================================== */
// Main Function
/* ================================================================== */
int main(int argc, char *argv[])
{
	PIN_InitSymbols();
    if( PIN_Init(argc, argv) )
    {
        return -1;
	}
	
	pLOG_FILE = fopen( LOG_FILE, "w" );
	if ( !pLOG_FILE )
	{
		printf("[*] File Open Error!\n");
		return -1;
	}

	fprintf(pLOG_FILE, "[*] =====================================\n");
	fprintf(pLOG_FILE, "[*] Simple Taint Analysis Tool\n");
	fprintf(pLOG_FILE, "[*] korea.devsec@gmail.com\n");
	fprintf(pLOG_FILE, "[*] =====================================\n");
	fprintf(pLOG_FILE, "[+] \"%s\" Tracing...\n", TARGET_FILENAME);
	fprintf(pLOG_FILE, "[*] =====================================\n");

	PIN_SetSyntaxIntel();
	//PIN_AddSyscallEntryFunction(SysCall_Entry, 0 );
	IMG_AddInstrumentFunction( Image , 0 );
	INS_AddInstrumentFunction( Instruction, 0 );
	PIN_AddFiniFunction( Fini, 0 );

    PIN_StartProgram();
    
    return 0;
}

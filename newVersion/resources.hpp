/* ================================================================== */
//
//	Created By Lim Dongho (korea.devsec@gmail.com)
//
//	2016 Kangnam University Graduation Works
//	Copyleft(c), reference for : http://github.com/krdevsec
//
/* ================================================================== */
#pragma once
#pragma warning(disable:4091)


/* ================================================================== */
// Preprocessors
/* ================================================================== */
#include "pin.H"
#include <iostream>
#include <fstream>
#include <list>
#include "definedRTN.h"
#include "main.hpp"
#include "MemTainted.hpp"
using namespace std;

/* ================================================================== */
// Macro Constants
/* ================================================================== */
#define LOCKED		1
#define UNLOCKED	!LOCKED

#define ALLOCATE	1
#define FREE		!ALLOCATE

extern FILE* pLOG_FILE;


#if 0 /* TARGET MODE 1: x32, 2: x64 */
#define UPPER_BOUND 0xb0000000
#else
#define UPPER_BOUND 0x700000000000
#endif

/* ================================================================== */
// Custom Structures
/* ================================================================== */
typedef struct Range
{
	UINT	start;
	UINT	end;
};
typedef struct mallocArea
{
	UINT	base;
	UINT	size;
	BOOL	status;
};

typedef struct RoutineAccessList
{
	ADDRINT routine_addr;
	list<UINT32> access_list;
	ADDRINT routine_stack_base;
	ADDRINT routine_stack_current;
	bool has_stack_access;
};
typedef struct SectionBoundaries
{
	ADDRINT section_start;
	ADDRINT section_end;
};
typedef struct HeapAllocated
{
	ADDRINT heap_start;
	ADDRINT heap_end;
};
typedef struct StackAllocated
{
	ADDRINT stack_start;
	ADDRINT stack_end;
};
typedef struct RoutineArgs
{
	ADDRINT routine_addr;
	UINT32 arg_number;
};


/*
 * Copyright 2002-2019 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

#include <iostream>
#include <fstream>
#include <map>
#include "itree.h"
#include "pin.H"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;

#define DEBUG_INSTRUMENTATION   0   // for predicated instrumentation

/**
* Command line option to specify the name of the output file.
* Default is shellcode.out.
**/
KNOB<std::string> outputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "trace.out", "specify trace file name");

// custom types
typedef std::map<ADDRINT, uint32_t> targetMap; // <addr, cnt>
typedef std::map<ADDRINT, targetMap> instrMap; // <eip, <addr, cnt>-map>

// global storage
static instrMap takenReadsMap, notTakenReadsMap;
static instrMap takenWritesMap, notTakenWritesMap;
#if DEBUG_INSTRUMENTATION
static UINT64 predWrites = 0, predReads = 0;
#endif

itreenode_t* modRangeTree = NULL;

// runtime help
static PIN_MUTEX mutex;
static int currentPid;
std::ofstream logFile;

inline void updateMap(ADDRINT eip, ADDRINT addr, instrMap &map) {
    PIN_MutexLock(&mutex);
    instrMap::iterator it = map.find(eip);
    if (it == map.end()) {
        map[eip] = targetMap();
        map[eip][addr] = 1;
    } else {
        targetMap &tMap = it->second;
        targetMap::iterator it2 = tMap.find(addr);
        if (it2 == tMap.end()) {
            tMap[addr] = 1;
        } else {
            it2->second++;
        }
    }
    PIN_MutexUnlock(&mutex);
}


#if DEBUG_INSTRUMENTATION
static VOID PIN_FAST_ANALYSIS_CALL DebugInstrumentation(ADDRINT* counter) {
    (*counter)++;
}
#endif

// slow path only for CMOV and REP instructions
VOID RecordPredicated(ADDRINT eip, ADDRINT addr, VOID* mapTaken, VOID* mapNotTaken, BOOL taken) {
    //fprintf(trace,"%p: R %p\n", (void*)eip, (void*)src);
    if (taken) {
        updateMap(eip, addr, *((instrMap*)mapTaken));
    } else {
        updateMap(eip, addr, *((instrMap*)mapNotTaken));
    }
}

// fast path for non-predicated accesses
VOID RecordMemoryAccess(ADDRINT addr, VOID* mapEntry) {
    PIN_MutexLock(&mutex);
    targetMap *tMap = (targetMap*)mapEntry;
    targetMap::iterator it2 = tMap->find(addr);
    if (it2 == tMap->end()) {
        (*tMap)[addr] = 1;
    } else {
        it2->second++;
    }
    PIN_MutexUnlock(&mutex);
}

// INS instrumentation     
VOID Instruction(INS ins, VOID *v) {
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        // in some cases the same operand can be both read and written
        // we can log both or add an else here? (credits: Pin docs)
        if (INS_MemoryOperandIsRead(ins, memOp)) {
            #if DEBUG_INSTRUMENTATION
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)DebugInstrumentation,
                IARG_FAST_ANALYSIS_CALL,
                IARG_PTR, &predReads,
                IARG_END);
            #endif
            if (INS_IsPredicated(ins)) {
                // slow path for CMOV and REP
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)RecordPredicated,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_PTR, &takenReadsMap,
                    IARG_PTR, &notTakenReadsMap,
                    IARG_EXECUTING,
                    IARG_END);
            } else {
                // fast path: preload map with entry and pass its address
                ADDRINT eip = INS_Address(ins);
                instrMap::iterator it = takenReadsMap.find(eip);
                if (it == takenReadsMap.end()) {
                    takenReadsMap[eip] = targetMap();
                }
                targetMap* tMap = &takenReadsMap[eip];
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)RecordMemoryAccess,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_PTR, tMap,
                    IARG_END);
            }
        }

        if (INS_MemoryOperandIsWritten(ins, memOp)) {
            #if DEBUG_INSTRUMENTATION
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)DebugInstrumentation,
                IARG_FAST_ANALYSIS_CALL,
                IARG_PTR, &predWrites,
                IARG_END);
            #endif
            if (INS_IsPredicated(ins)) {
                // slow path for CMOV and REP
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)RecordPredicated,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_PTR, &takenWritesMap,
                    IARG_PTR, &notTakenWritesMap,
                    IARG_EXECUTING,
                    IARG_END);
            } else {
                // fast path: preload map with entry and pass its address
                ADDRINT eip = INS_Address(ins);
                instrMap::iterator it = takenWritesMap.find(eip);
                if (it == takenWritesMap.end()) {
                    takenWritesMap[eip] = targetMap();
                }
                targetMap* tMap = &takenWritesMap[eip];
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)RecordMemoryAccess,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_PTR, tMap,
                    IARG_END);
            }
        }
    }

}

void dumpMap(ofstream &file, instrMap &map, const char* msg) {
    file << endl << "<< MAP for " << msg << " >>" << endl;

    itreenode_t *node = NULL;
    for (instrMap::iterator it = map.begin(), end = map.end(); it != end; ++it) {
        // skip dynamically dead instructions
        if (it->second.empty()) continue;

        // let's go by intervals: map is already sorted with operator< on the key
        ADDRINT addr = it->first;
        if (node == NULL || !(addr >= node->start_addr && addr <= node->end_addr)) {
            node = itree_search(modRangeTree, addr);
            if (node == NULL) {
                file << "[Unknown module]" << endl;
            } else {
                file << "[" << (char*) node->data << "] @ 0x" << std::hex << node->start_addr << endl;
            }
        }
        // dump instruction data
        file << "Instruction at: " << std::hex << it->first << endl;
        for (targetMap::iterator it2 = it->second.begin(), end2 = it->second.end(); it2 != end2 ; ++it2)
            file << std::hex << it->first << " -> " << it2->first << " [" << std::dec << it2->second << "]" << endl;
    }
}

inline UINT64 countEntries(instrMap &map) {
    UINT64 ret = 0;
    for (instrMap::iterator it = map.begin(), end = map.end(); it != end; ++it)
        for (targetMap::iterator it2 = it->second.begin(), end2 = it->second.end(); it2 != end2 ; ++it2)
            ret += it2->second;
    return ret;
}


VOID Fini(INT32 code, VOID *v) {
    #if DEBUG_INSTRUMENTATION
    logFile << "predWrites:     " << std::dec << predWrites << endl;
    logFile << "predReads:      " << std::dec << predReads << endl;
    #endif
    logFile << "takenWrites:    " << std::dec << countEntries(takenWritesMap) << endl;
    logFile << "notTakenWrites: " << std::dec << countEntries(notTakenWritesMap) << endl;
    logFile << "takenReads:     " << std::dec << countEntries(takenReadsMap) << endl;
    logFile << "notTakenReads:  " << std::dec << countEntries(notTakenReadsMap) << endl;

    dumpMap(logFile, takenWritesMap, "taken writes");
    dumpMap(logFile, notTakenWritesMap, "non-taken writes");

    dumpMap(logFile, takenReadsMap, "taken reads");
    dumpMap(logFile, notTakenReadsMap, "non-taken reads");
 
    logFile.close();
}


inline void clearMap(instrMap &map) {
    for (instrMap::iterator it = map.begin(), end = map.end(); it != end; ++it) {
        it->second.clear();
    }
    // map.clear(); // disabled for fast variant as we may share instrumented code... see &entry
}

VOID AfterForkInChild(THREADID threadid, const CONTEXT *ctxt, VOID *val) {
    currentPid = PIN_GetPid();
    logFile.close(); // belongs to (pintool instance for) parent process

    char fileName[64];
    sprintf(fileName, "stats-fast-%d.txt", currentPid);
    logFile.open(fileName);

    // clear global data structures
    #if DEBUG_INSTRUMENTATION
    predWrites = 0; predReads = 0;
    #endif
    clearMap(takenWritesMap);
    clearMap(notTakenWritesMap);
    clearMap(takenReadsMap);
    clearMap(notTakenReadsMap);
}

VOID Image(IMG img, VOID* v) {
    const char* imgName = IMG_Name(img).c_str();
	char* data = strdup(imgName);
	//size_t len = strlen(data) + 1;
	//while (len--) data[len] = tolower(data[len]);
    ADDRINT imgStart = IMG_LowAddress(img);
	ADDRINT imgEnd = IMG_HighAddress(img);

    if (modRangeTree == NULL) {
		modRangeTree = itree_init(imgStart, imgEnd, (void*)data);
	} else {
		bool success = itree_insert(modRangeTree, imgStart, imgEnd, (void*)data);
		if (!success) {
			cerr << "==> Duplicate range insertion for module " << data << endl;
		}
	}

    #if DEBUG_INSTRUMENTATION
	if (!itree_verify(gs->dllRangeITree)) {
		itree_print(gs->dllRangeITree, 0);
		ASSERT(false, "Broken interval tree");
	}
    #endif

}

VOID ImageUnload(IMG img, VOID* v) {
    #if 0
    // we do logging on Fini() so for now we want to keep the intervals
    // (as long as Linux does not decide to reuse them across modules)
    ADDRINT imgStart = IMG_LowAddress(img);
	ADDRINT imgEnd = IMG_HighAddress(img);
    modRangeTree = itree_delete(modRangeTree, imgStart, imgEnd);
    #endif
}

INT32 Usage() {
    cerr << "Trace memory accesses performed during execution" << endl;
    cerr << "    -o filename              specify trace file name [default: trace.out]" << endl;
    return -1;
}


int main(int argc, char * argv[]) {
    if (PIN_Init(argc, argv)) return Usage();

    PIN_MutexInit(&mutex);

    currentPid = PIN_GetPid();
    logFile.open(outputFile.Value().c_str());

    INS_AddInstrumentFunction(Instruction, 0);

	IMG_AddInstrumentFunction(Image, NULL);
	IMG_AddUnloadFunction(ImageUnload, NULL);

    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    PIN_StartProgram();
    
    return 0;
}

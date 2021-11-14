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
#include "pin.H"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;

// custom types
typedef std::map<ADDRINT, uint32_t> targetMap; // <addr, cnt>
typedef std::map<ADDRINT, targetMap> instrMap; // <eip, <addr, cnt>-map>

// global storage
static instrMap predReadsMap, takenReadsMap, notTakenReadsMap;
static instrMap predWritesMap, takenWritesMap, notTakenWritesMap;

// redundant (initially for fast profiling)
static UINT64 predWrites = 0, predReads = 0;
static UINT64 takenWrites = 0, takenReads = 0;
static UINT64 notTakenWrites = 0, notTakenReads = 0;

// runtime help
static PIN_MUTEX mutex;
static int currentPid;
ofstream logFile;

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


VOID RecordPredMemRead(ADDRINT eip, ADDRINT src)
{
    //fprintf(trace,"%p: R %p\n", (void*)eip, (void*)src);
    predReads++;
    updateMap(eip, src, predReadsMap);
}

VOID RecordPredMemWrite(ADDRINT eip, ADDRINT dest)
{
    //fprintf(trace,"%p: W %p\n", (void*)eip, (void*)dest);
    predWrites++;
    updateMap(eip, dest, predWritesMap);
}

VOID RecordMemRead(ADDRINT eip, ADDRINT src, BOOL taken)
{
    //fprintf(trace,"%p: R %p\n", (void*)eip, (void*)src);
    if (taken) {
        takenReads++;
        updateMap(eip, src, takenReadsMap);
    } else {
        notTakenReads++;
        updateMap(eip, src, notTakenReadsMap);
    }
}

VOID RecordMemWrite(ADDRINT eip, ADDRINT dest, BOOL taken)
{
    //fprintf(trace,"%p: W %p\n", (void*)eip, (void*)dest);
    if (taken) {
        takenWrites++;
        updateMap(eip, dest, takenWritesMap);
    } else {
        notTakenWrites++;
        updateMap(eip, dest, notTakenWritesMap);
    }
}
    
// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        // in some cases the same operand can be both read and written
        // we can log both or add an else here? (credits: Pin docs)
        if (INS_MemoryOperandIsRead(ins, memOp)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordPredMemRead,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_EXECUTING,
                IARG_END);
        }

        if (INS_MemoryOperandIsWritten(ins, memOp)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordPredMemWrite,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_EXECUTING,
                IARG_END);
        }
    }

}

inline void dumpMap(ofstream &file, instrMap &map, const char* msg) {
    file << endl << "<< MAP for " << msg << " >>" << endl;
    for (instrMap::iterator it = map.begin(), end = map.end(); it != end; ++it) {
        file << "Instruction at: " << std::hex << it->first << endl;
        for (targetMap::iterator it2 = it->second.begin(), end2 = it->second.end(); it2 != end2 ; ++it2)
            file << "-> " << std::hex << it2->first << " [" << std::dec << it2->second << "]" << endl;
    }
}


VOID Fini(INT32 code, VOID *v)
{
    logFile << "predWrites:     " << std::dec << predWrites << endl;
    logFile << "takenWrites:    " << std::dec << takenWrites << endl;
    logFile << "notTakenWrites: " << std::dec << notTakenWrites << endl;
    logFile << "predReads:      " << std::dec << predReads << endl;
    logFile << "takenReads:     " << std::dec << takenReads << endl;
    logFile << "notTakenReads:  " << std::dec << notTakenReads << endl;

    dumpMap(logFile, predWritesMap, "predicated writes");
    dumpMap(logFile, takenWritesMap, "taken writes");
    dumpMap(logFile, notTakenWritesMap, "non-taken writes");

    dumpMap(logFile, predReadsMap, "predicated reads");
    dumpMap(logFile, takenReadsMap, "taken reads");
    dumpMap(logFile, notTakenReadsMap, "non-taken reads");
 
    logFile.close();
}


inline void clearMap(instrMap &map) {
    for (instrMap::iterator it = map.begin(), end = map.end(); it != end; ++it) {
        it->second.clear();
    }
    map.clear();
}

VOID AfterForkInChild(THREADID threadid, const CONTEXT *ctxt, VOID *val) {
    currentPid = PIN_GetPid();
    logFile.close(); // belongs to (pintool instance for) parent process

    char fileName[64];
    sprintf(fileName, "trace-%d.txt", currentPid);
    logFile.open(fileName);

    // clear global data structures
    predWrites = 0; predReads = 0;
    takenWrites = 0; takenReads = 0;
    notTakenWrites = 0; notTakenReads = 0;

    clearMap(predWritesMap);
    clearMap(takenWritesMap);
    clearMap(notTakenWritesMap);
    clearMap(predReadsMap);
    clearMap(takenReadsMap);
    clearMap(notTakenReadsMap);
}




INT32 Usage()
{
    cerr << "No time for that :-)" << endl;
    //cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}


int main(int argc, char * argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
    PIN_MutexInit(&mutex);

    currentPid = PIN_GetPid();
    char fileName[64];
    sprintf(fileName, "stats-%d.txt", currentPid);
    logFile.open(fileName);

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // TODO what do we need here? I guess this one below creates issues...
    //PIN_AddFollowChildProcessFunction(FollowChild, 0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);
    
    PIN_StartProgram();
    
    return 0;
}

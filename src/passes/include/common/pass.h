#ifndef _PASS_H
#define _PASS_H

#include <llvm/Pass.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Analysis/AliasAnalysis.h>

#include <llvm/Support/Debug.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/ADT/Statistic.h>

#include <llvm/Support/Regex.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Analysis/LoopInfo.h>

#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Scalar.h>

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/DebugInfoMetadata.h>

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

using namespace llvm;

static inline void passListRegexInit(std::vector<Regex*> &regexes, const std::vector<std::string> &strings)
{
    for (auto &s : strings)
        regexes.push_back(new Regex(s, 0));
}

static inline bool passListRegexMatch(const std::vector<Regex*> &regexes, const std::string &string)
{
    for (auto &regex : regexes) {
    	  if (regex->match(string))
    	  		  return true;
    }
    
    return false;
}

static inline Function* passGetCalledFunction(Instruction *I)
{
    CallSite CS(I);
    if (!CS.getInstruction())
    	  return NULL; // not a call
    return CS.getCalledFunction();
}

static inline CallInst* passCreateCallInstruction(Value *F, std::vector<Value*> &args, const Twine &NameStr, Instruction *InsertBefore) {
    ArrayRef<Value*> ref(args);
    return CallInst::Create(F, ref, NameStr, InsertBefore);
}

#endif /* _PASS_H */

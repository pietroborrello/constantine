#ifndef _MPC_PASS_H
#define _MPC_PASS_H

#include <pass.h>

#define MPC_INTRINSIC_PREFIX "mpc_"
#define MPC_PRIV_SRC_PREFIX  "mpc_get_priv_"
#define MPC_PRIV_SINK_PREFIX "mpc_open_priv_"

/* XXX: Only one implementation for now. */
#define MPC_INSTRINSIC_IMPL  "dummy"

enum MPCIType {
	MPC_PRIV_SRC,
	MPC_PRIV_SINK,
	MPC_GEN,
	MPC_NONE
};

static inline MPCIType passGetMPCIntrinsicType(Value *V) {
    if (Function *F = dyn_cast<Function>(V)) {
    	StringRef name = F->getName();
    	if (name.startswith(MPC_PRIV_SRC_PREFIX))
    		return MPC_PRIV_SRC;
    	if (name.startswith(MPC_PRIV_SINK_PREFIX))
    		return MPC_PRIV_SINK;
    	if (name.startswith(MPC_INTRINSIC_PREFIX))
    		return MPC_GEN;
    	return MPC_NONE;
    }
    Instruction *I = dyn_cast<Instruction>(V);
    if (!I)
    	return MPC_NONE;
    Function *Callee = passGetCalledFunction(I);
    if (Callee)
    	return passGetMPCIntrinsicType(Callee);
    return MPC_NONE;
}

static inline bool passIsMPCIntrinsicInst(Value *V) {
    if (!isa<Instruction>(V))
    	return false;
    return passGetMPCIntrinsicType(V) != MPC_NONE;
}

#endif /* _MPC_PASS_H */

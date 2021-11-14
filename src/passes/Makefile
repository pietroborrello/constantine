DIRS := dummy dbg flatten cfl cgc hook coverage-id icp taintglb loadtainted dumptaintedloops branch-extract loops-cfl dfl stack-vars-promotion remove-unreachable fix-scalarizer custom-structurizecfg unify-loop-exits fix-irreducible remove-selfloops remove-dup-lifetimes set-norecurse-ext forward-geps check-cfl list-tainted-funcs fix-callsite-attrs check-undefined find-instruction dump-implicit-deps insert-compares branch-enhance mark-induction-variables taint-stats func-stats remove-memfuncs custom-loop-idiom

all: $(patsubst %,build_%,$(DIRS))

$(patsubst %,build_%,$(DIRS)): DIR = $(subst build_,,$@)
$(patsubst %,build_%,$(DIRS)):
	@echo Building LLVM $(DIR)...
	$(MAKE) -C $(DIR) install

clean:
	$(foreach DIR, $(DIRS), $(MAKE) -C $(DIR) clean;)

install: all

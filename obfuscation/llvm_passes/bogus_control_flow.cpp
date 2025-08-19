#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/raw_ostream.h"
#include <random>
#include <vector>
#include <algorithm>

using namespace llvm;

namespace {
    struct BogusControlFlow : public FunctionPass {
        static char ID;
        std::random_device rd;
        std::mt19937 gen;
        std::uniform_int_distribution<> dis;
        
        BogusControlFlow() : FunctionPass(ID), gen(rd()), dis(0, 100) {}
        
        bool runOnFunction(Function &F) override {
            if (F.isDeclaration()) return false;
            
            bool modified = false;
            std::vector<BasicBlock*> originalBBs;
            
            // Collect original basic blocks
            for (BasicBlock &BB : F) {
                originalBBs.push_back(&BB);
            }
            
            // Add bogus control flow to each basic block
            for (BasicBlock *BB : originalBBs) {
                if (shouldObfuscate()) {
                    modified |= addBogusControlFlow(BB);
                }
            }
            
            return modified;
        }
        
    private:
        bool shouldObfuscate() {
            return dis(gen) < 40; // 40% chance to obfuscate each basic block
        }
        
        bool addBogusControlFlow(BasicBlock *BB) {
            if (BB->size() < 2) return false;
            
            // Find a suitable insertion point
            Instruction *insertPoint = nullptr;
            for (Instruction &I : *BB) {
                if (!isa<PHINode>(I) && !isa<LandingPadInst>(I)) {
                    insertPoint = &I;
                    break;
                }
            }
            
            if (!insertPoint) return false;
            
            // Create bogus condition
            IRBuilder<> builder(insertPoint);
            
            // Generate opaque predicate (always true)
            Value *opaqueCondition = createOpaquePredicate(builder);
            
            // Split the basic block
            BasicBlock *trueBB = BB->splitBasicBlock(insertPoint, "bogus_true");
            BasicBlock *falseBB = createBogusBB(BB->getParent(), "bogus_false");
            
            // Remove the unconditional branch created by splitBasicBlock
            BB->getTerminator()->eraseFromParent();
            
            // Create conditional branch with bogus condition
            builder.SetInsertPoint(BB);
            builder.CreateCondBr(opaqueCondition, trueBB, falseBB);
            
            // Make the false BB eventually branch to the true BB
            addBogusOperationsAndBranch(falseBB, trueBB);
            
            return true;
        }
        
        Value* createOpaquePredicate(IRBuilder<> &builder) {
            // Create various types of opaque predicates
            int predicateType = dis(gen) % 4;
            
            switch (predicateType) {
                case 0:
                    return createArithmeticOpaque(builder);
                case 1:
                    return createBitwiseOpaque(builder);
                case 2:
                    return createPointerOpaque(builder);
                default:
                    return createComplexOpaque(builder);
            }
        }
        
        Value* createArithmeticOpaque(IRBuilder<> &builder) {
            // (x * 2) % 2 == 0 (always true for any integer x)
            Type *intTy = builder.getInt32Ty();
            Value *x = builder.getInt32(dis(gen));
            Value *mul = builder.CreateMul(x, builder.getInt32(2));
            Value *mod = builder.CreateSRem(mul, builder.getInt32(2));
            return builder.CreateICmpEQ(mod, builder.getInt32(0));
        }
        
        Value* createBitwiseOpaque(IRBuilder<> &builder) {
            // (x ^ x) == 0 (always true)
            Value *x = builder.getInt32(dis(gen));
            Value *xor_result = builder.CreateXor(x, x);
            return builder.CreateICmpEQ(xor_result, builder.getInt32(0));
        }
        
        Value* createPointerOpaque(IRBuilder<> &builder) {
            // Create a global variable and compare its address with null
            Module *M = builder.GetInsertBlock()->getParent()->getParent();
            GlobalVariable *GV = new GlobalVariable(
                *M, builder.getInt32Ty(), false,
                GlobalValue::InternalLinkage,
                builder.getInt32(0),
                "bogus_global"
            );
            
            Value *ptr = builder.CreatePtrToInt(GV, builder.getInt64Ty());
            return builder.CreateICmpNE(ptr, builder.getInt64(0));
        }
        
        Value* createComplexOpaque(IRBuilder<> &builder) {
            // ((x * x) + x) % 2 == x % 2 (always true for odd x)
            Value *x = builder.getInt32(dis(gen) * 2 + 1); // Ensure odd number
            Value *x_squared = builder.CreateMul(x, x);
            Value *left_expr = builder.CreateAdd(x_squared, x);
            Value *left_mod = builder.CreateSRem(left_expr, builder.getInt32(2));
            Value *right_mod = builder.CreateSRem(x, builder.getInt32(2));
            return builder.CreateICmpEQ(left_mod, right_mod);
        }
        
        BasicBlock* createBogusBB(Function *F, const Twine &Name) {
            BasicBlock *bogusBB = BasicBlock::Create(F->getContext(), Name, F);
            return bogusBB;
        }
        
        void addBogusOperationsAndBranch(BasicBlock *bogusBB, BasicBlock *trueBB) {
            IRBuilder<> builder(bogusBB);
            
            // Add some bogus operations to make the false branch look legitimate
            int numOps = dis(gen) % 5 + 2; // 2-6 operations
            
            Value *accumulator = builder.getInt32(dis(gen));
            
            for (int i = 0; i < numOps; ++i) {
                int opType = dis(gen) % 6;
                Value *operand = builder.getInt32(dis(gen) % 100 + 1);
                
                switch (opType) {
                    case 0:
                        accumulator = builder.CreateAdd(accumulator, operand);
                        break;
                    case 1:
                        accumulator = builder.CreateSub(accumulator, operand);
                        break;
                    case 2:
                        accumulator = builder.CreateMul(accumulator, operand);
                        break;
                    case 3:
                        accumulator = builder.CreateXor(accumulator, operand);
                        break;
                    case 4:
                        accumulator = builder.CreateShl(accumulator, builder.getInt32(dis(gen) % 8));
                        break;
                    case 5:
                        accumulator = builder.CreateLShr(accumulator, builder.getInt32(dis(gen) % 8));
                        break;
                }
            }
            
            // Store the result in a global variable (dead code)
            Module *M = bogusBB->getParent()->getParent();
            GlobalVariable *deadStore = new GlobalVariable(
                *M, builder.getInt32Ty(), false,
                GlobalValue::InternalLinkage,
                builder.getInt32(0),
                "dead_store"
            );
            
            builder.CreateStore(accumulator, deadStore);
            
            // Branch to the true BB
            builder.CreateBr(trueBB);
        }
        
        void getAnalysisUsage(AnalysisUsage &AU) const override {
            // This pass modifies the CFG
        }
    };
}

char BogusControlFlow::ID = 0;
static RegisterPass<BogusControlFlow> X("bogus-cf", "Bogus Control Flow Obfuscation");

// Pass registration for new pass manager
namespace {
    struct BogusControlFlowNewPM : public PassInfoMixin<BogusControlFlowNewPM> {
        PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
            BogusControlFlow BCF;
            if (BCF.runOnFunction(F)) {
                return PreservedAnalyses::none();
            }
            return PreservedAnalyses::all();
        }
    };
}

// Plugin interface
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "BogusControlFlow", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "bogus-cf") {
                        FPM.addPass(BogusControlFlowNewPM{});
                        return true;
                    }
                    return false;
                });
        }};
}
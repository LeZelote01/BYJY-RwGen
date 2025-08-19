#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"
#include <vector>
#include <algorithm>
#include <random>

using namespace llvm;

namespace {
struct AdvancedControlFlowFlattening : public FunctionPass {
    static char ID;
    AdvancedControlFlowFlattening() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
        if (F.isDeclaration()) return false;

        LLVMContext &context = F.getContext();
        BasicBlock &entryBlock = F.getEntryBlock();
        
        // Create switch variable with opaque predicate
        IntegerType *intType = Type::getInt32Ty(context);
        AllocaInst *switchVar = new AllocaInst(intType, 0, "switchVar", &entryBlock.front());
        
        // Opaque constant: 7 * 3 - 21 = 0 (but hidden)
        Value* opaqueZero = createOpaqueZero(context, &entryBlock.front());
        new StoreInst(opaqueZero, switchVar, &entryBlock.front());
        
        std::vector<BasicBlock*> originalBlocks;
        for (BasicBlock &BB : F) {
            if (&BB != &entryBlock) originalBlocks.push_back(&BB);
        }
        
        // Shuffle blocks for randomness
        std::shuffle(originalBlocks.begin(), originalBlocks.end(), std::mt19937(std::random_device{}()));
        
        BasicBlock *loopBlock = BasicBlock::Create(context, "loopBlock", &F);
        LoadInst *loadSwitch = new LoadInst(intType, switchVar, "switchVar", loopBlock);
        
        // Encrypted switch values
        std::vector<ConstantInt*> encryptedCases;
        for (unsigned i = 0; i < originalBlocks.size(); i++) {
            encryptedCases.push_back(ConstantInt::get(intType, (i + 1) * 0x9E3779B9));
        }
        
        SwitchInst *switchInst = SwitchInst::Create(loadSwitch, loopBlock, originalBlocks.size(), loopBlock);
        
        // Create bogus exit blocks
        BasicBlock *bogusExit1 = createBogusExitBlock(context, F);
        BasicBlock *bogusExit2 = createBogusExitBlock(context, F);
        BasicBlock *realExit = BasicBlock::Create(context, "realExit", &F);
        ReturnInst::Create(context, realExit);
        
        switchInst->setDefaultDest(bogusExit1);
        
        BranchInst *entryBranch = BranchInst::Create(loopBlock);
        ReplaceInstWithInst(entryBlock.getTerminator(), entryBranch);
        
        // Create fake switch cases
        for (unsigned i = 0; i < 5; i++) {
            ConstantInt *fakeCase = ConstantInt::get(intType, 0xDEAD0000 + i);
            switchInst->addCase(fakeCase, bogusExit2);
        }
        
        // Real cases with decryption
        for (unsigned i = 0; i < originalBlocks.size(); i++) {
            BasicBlock *BB = originalBlocks[i];
            
            // Add opaque predicates to blocks
            injectOpaquePredicates(*BB, context);
            
            // Create decryption before branch
            IRBuilder<> builder(BB);
            Value *decryptedValue = builder.CreateUDiv(
                builder.CreateLoad(intType, switchVar),
                ConstantInt::get(intType, 0x9E3779B9)
            );
            builder.CreateStore(decryptedValue, switchVar);
            
            BranchInst *loopBranch = BranchInst::Create(loopBlock);
            ReplaceInstWithInst(BB->getTerminator(), loopBranch);
            
            new StoreInst(encryptedCases[i], switchVar, loopBranch);
            
            switchInst->addCase(encryptedCases[i], BB);
        }
        
        return true;
    }

private:
    Value* createOpaqueZero(LLVMContext &context, Instruction *insertPt) {
        IRBuilder<> builder(insertPt);
        Value *val = builder.CreateMul(ConstantInt::get(context, APInt(32, 7)), 
                                      ConstantInt::get(context, APInt(32, 3)));
        val = builder.CreateSub(val, ConstantInt::get(context, APInt(32, 21)));
        return builder.CreateAdd(val, ConstantInt::get(context, APInt(32, 0))); // Always zero
    }
    
    BasicBlock* createBogusExitBlock(LLVMContext &context, Function &F) {
        BasicBlock *bogusBlock = BasicBlock::Create(context, "bogusExit", &F);
        IRBuilder<> builder(bogusBlock);
        
        // Create meaningless calculations
        Value *val = builder.CreateAlloca(Type::getInt32Ty(context));
        builder.CreateStore(ConstantInt::get(context, APInt(32, 42)), val);
        Value *loaded = builder.CreateLoad(Type::getInt32Ty(context), val);
        loaded = builder.CreateAdd(loaded, ConstantInt::get(context, APInt(32, 1)));
        builder.CreateStore(loaded, val);
        
        // Always jump to real exit
        builder.CreateBr(&F.back());
        return bogusBlock;
    }
    
    void injectOpaquePredicates(BasicBlock &BB, LLVMContext &context) {
        if (BB.size() < 2) return;
        
        Instruction *insertPt = &*(++BB.begin());
        IRBuilder<> builder(insertPt);
        
        // Create opaque predicate: (x * 2) % 2 == 0 (always true)
        Value *x = builder.CreateAlloca(Type::getInt32Ty(context));
        builder.CreateStore(ConstantInt::get(context, APInt(32, 15)), x);
        Value *loaded = builder.CreateLoad(Type::getInt32Ty(context), x);
        Value *mul = builder.CreateMul(loaded, ConstantInt::get(context, APInt(32, 2)));
        Value *mod = builder.CreateURem(mul, ConstantInt::get(context, APInt(32, 2)));
        Value *cmp = builder.CreateICmpEQ(mod, ConstantInt::get(context, APInt(32, 0)));
        
        // Split block and create conditional branch
        BasicBlock *trueBlock = BB.splitBasicBlock(insertPt, "opaqueTrue");
        BasicBlock *falseBlock = BasicBlock::Create(context, "opaqueFalse", BB.getParent());
        
        // Create dummy instructions in false block
        IRBuilder<> falseBuilder(falseBlock);
        Value *dummy = falseBuilder.CreateAlloca(Type::getInt32Ty(context));
        falseBuilder.CreateStore(ConstantInt::get(context, APInt(32, 0)), dummy);
        falseBuilder.CreateBr(trueBlock);
        
        // Replace branch with conditional
        BB.getTerminator()->eraseFromParent();
        builder.SetInsertPoint(&BB);
        builder.CreateCondBr(cmp, trueBlock, falseBlock);
    }
};
} // namespace

char AdvancedControlFlowFlattening::ID = 0;
static RegisterPass<AdvancedControlFlowFlattening> X("adv_cff", "Advanced Control Flow Flattening", false, false);

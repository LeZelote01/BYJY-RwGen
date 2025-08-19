#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"
#include <random>
#include <vector>
#include <map>

using namespace llvm;

namespace {
    struct InstructionSubstitution : public FunctionPass {
        static char ID;
        std::random_device rd;
        std::mt19937 gen;
        std::uniform_int_distribution<> dis;
        
        InstructionSubstitution() : FunctionPass(ID), gen(rd()), dis(0, 100) {}
        
        bool runOnFunction(Function &F) override {
            if (F.isDeclaration()) return false;
            
            bool modified = false;
            std::vector<Instruction*> toSubstitute;
            
            // Collect instructions to substitute
            for (BasicBlock &BB : F) {
                for (Instruction &I : BB) {
                    if (shouldSubstitute(I)) {
                        toSubstitute.push_back(&I);
                    }
                }
            }
            
            // Perform substitutions
            for (Instruction *I : toSubstitute) {
                if (substituteInstruction(I)) {
                    modified = true;
                }
            }
            
            return modified;
        }
        
    private:
        bool shouldSubstitute(Instruction &I) {
            // Only substitute certain types of instructions
            return (isa<BinaryOperator>(I) || isa<ICmpInst>(I)) && 
                   dis(gen) < 30; // 30% chance
        }
        
        bool substituteInstruction(Instruction *I) {
            if (BinaryOperator *BO = dyn_cast<BinaryOperator>(I)) {
                return substituteBinaryOperator(BO);
            } else if (ICmpInst *ICI = dyn_cast<ICmpInst>(I)) {
                return substituteICmpInst(ICI);
            }
            return false;
        }
        
        bool substituteBinaryOperator(BinaryOperator *BO) {
            IRBuilder<> builder(BO);
            Value *replacement = nullptr;
            
            switch (BO->getOpcode()) {
                case Instruction::Add:
                    replacement = substituteAdd(builder, BO->getOperand(0), BO->getOperand(1));
                    break;
                case Instruction::Sub:
                    replacement = substituteSub(builder, BO->getOperand(0), BO->getOperand(1));
                    break;
                case Instruction::Mul:
                    replacement = substituteMul(builder, BO->getOperand(0), BO->getOperand(1));
                    break;
                case Instruction::Xor:
                    replacement = substituteXor(builder, BO->getOperand(0), BO->getOperand(1));
                    break;
                case Instruction::And:
                    replacement = substituteAnd(builder, BO->getOperand(0), BO->getOperand(1));
                    break;
                case Instruction::Or:
                    replacement = substituteOr(builder, BO->getOperand(0), BO->getOperand(1));
                    break;
                default:
                    return false;
            }
            
            if (replacement) {
                BO->replaceAllUsesWith(replacement);
                BO->eraseFromParent();
                return true;
            }
            
            return false;
        }
        
        Value* substituteAdd(IRBuilder<> &builder, Value *LHS, Value *RHS) {
            // Replace a + b with (a ^ b) + 2 * (a & b)
            // This is based on the identity: a + b = (a ⊕ b) + 2(a ∧ b)
            Value *xor_result = builder.CreateXor(LHS, RHS);
            Value *and_result = builder.CreateAnd(LHS, RHS);
            Value *shift_result = builder.CreateShl(and_result, builder.getInt32(1));
            return builder.CreateAdd(xor_result, shift_result);
        }
        
        Value* substituteSub(IRBuilder<> &builder, Value *LHS, Value *RHS) {
            // Replace a - b with a + (~b + 1)
            // This uses two's complement representation
            Value *not_rhs = builder.CreateNot(RHS);
            Value *one = ConstantInt::get(RHS->getType(), 1);
            Value *neg_rhs = builder.CreateAdd(not_rhs, one);
            return builder.CreateAdd(LHS, neg_rhs);
        }
        
        Value* substituteMul(IRBuilder<> &builder, Value *LHS, Value *RHS) {
            // For small constant multipliers, replace with shift and add
            if (ConstantInt *CI = dyn_cast<ConstantInt>(RHS)) {
                uint64_t value = CI->getZExtValue();
                
                // Handle powers of 2
                if (isPowerOfTwo(value)) {
                    unsigned shift = Log2_64(value);
                    return builder.CreateShl(LHS, builder.getInt32(shift));
                }
                
                // Handle small values with shift and add combinations
                if (value <= 16) {
                    return multiplyWithShiftAdd(builder, LHS, value);
                }
            }
            
            // For other cases, use complex substitution
            return complexMultiplySubstitution(builder, LHS, RHS);
        }
        
        Value* multiplyWithShiftAdd(IRBuilder<> &builder, Value *operand, uint64_t multiplier) {
            if (multiplier == 0) {
                return ConstantInt::get(operand->getType(), 0);
            }
            if (multiplier == 1) {
                return operand;
            }
            
            // Decompose multiplier into sum of powers of 2
            Value *result = nullptr;
            unsigned shift = 0;
            
            while (multiplier > 0) {
                if (multiplier & 1) {
                    Value *shifted = (shift > 0) ? 
                        builder.CreateShl(operand, builder.getInt32(shift)) : operand;
                    
                    result = result ? builder.CreateAdd(result, shifted) : shifted;
                }
                multiplier >>= 1;
                shift++;
            }
            
            return result;
        }
        
        Value* complexMultiplySubstitution(IRBuilder<> &builder, Value *LHS, Value *RHS) {
            // Replace multiplication with a more complex equivalent
            // Using the identity: a * b = ((a + b)² - a² - b²) / 2
            
            Value *sum = builder.CreateAdd(LHS, RHS);
            Value *sum_squared = builder.CreateMul(sum, sum);
            Value *lhs_squared = builder.CreateMul(LHS, LHS);
            Value *rhs_squared = builder.CreateMul(RHS, RHS);
            
            Value *diff1 = builder.CreateSub(sum_squared, lhs_squared);
            Value *diff2 = builder.CreateSub(diff1, rhs_squared);
            
            return builder.CreateLShr(diff2, builder.getInt32(1));
        }
        
        Value* substituteXor(IRBuilder<> &builder, Value *LHS, Value *RHS) {
            // Replace a ^ b with (a | b) - (a & b)
            Value *or_result = builder.CreateOr(LHS, RHS);
            Value *and_result = builder.CreateAnd(LHS, RHS);
            return builder.CreateSub(or_result, and_result);
        }
        
        Value* substituteAnd(IRBuilder<> &builder, Value *LHS, Value *RHS) {
            // Replace a & b with ~(~a | ~b) (De Morgan's law)
            Value *not_lhs = builder.CreateNot(LHS);
            Value *not_rhs = builder.CreateNot(RHS);
            Value *or_result = builder.CreateOr(not_lhs, not_rhs);
            return builder.CreateNot(or_result);
        }
        
        Value* substituteOr(IRBuilder<> &builder, Value *LHS, Value *RHS) {
            // Replace a | b with ~(~a & ~b) (De Morgan's law)
            Value *not_lhs = builder.CreateNot(LHS);
            Value *not_rhs = builder.CreateNot(RHS);
            Value *and_result = builder.CreateAnd(not_lhs, not_rhs);
            return builder.CreateNot(and_result);
        }
        
        bool substituteICmpInst(ICmpInst *ICI) {
            IRBuilder<> builder(ICI);
            Value *replacement = nullptr;
            
            Value *LHS = ICI->getOperand(0);
            Value *RHS = ICI->getOperand(1);
            
            switch (ICI->getPredicate()) {
                case ICmpInst::ICMP_EQ:
                    // a == b becomes (a ^ b) == 0
                    replacement = builder.CreateICmpEQ(
                        builder.CreateXor(LHS, RHS),
                        ConstantInt::get(LHS->getType(), 0)
                    );
                    break;
                    
                case ICmpInst::ICMP_NE:
                    // a != b becomes (a ^ b) != 0
                    replacement = builder.CreateICmpNE(
                        builder.CreateXor(LHS, RHS),
                        ConstantInt::get(LHS->getType(), 0)
                    );
                    break;
                    
                case ICmpInst::ICMP_ULT:
                    // a < b becomes (a - b) has high bit set (for unsigned)
                    replacement = substituteUnsignedLessThan(builder, LHS, RHS);
                    break;
                    
                case ICmpInst::ICMP_SLT:
                    // Signed less than substitution
                    replacement = substituteSignedLessThan(builder, LHS, RHS);
                    break;
                    
                default:
                    return false;
            }
            
            if (replacement) {
                ICI->replaceAllUsesWith(replacement);
                ICI->eraseFromParent();
                return true;
            }
            
            return false;
        }
        
        Value* substituteUnsignedLessThan(IRBuilder<> &builder, Value *LHS, Value *RHS) {
            // For unsigned: a < b equivalent to (a - b) > (max_int)
            Value *diff = builder.CreateSub(LHS, RHS);
            Type *intTy = LHS->getType();
            unsigned bitWidth = intTy->getIntegerBitWidth();
            Value *maxInt = ConstantInt::get(intTy, APInt::getSignedMaxValue(bitWidth));
            return builder.CreateICmpUGT(diff, maxInt);
        }
        
        Value* substituteSignedLessThan(IRBuilder<> &builder, Value *LHS, Value *RHS) {
            // Use bitwise operations to check sign of (LHS - RHS)
            Value *diff = builder.CreateSub(LHS, RHS);
            Type *intTy = LHS->getType();
            unsigned bitWidth = intTy->getIntegerBitWidth();
            Value *signBit = ConstantInt::get(intTy, APInt::getSignBit(bitWidth));
            Value *signResult = builder.CreateAnd(diff, signBit);
            return builder.CreateICmpNE(signResult, ConstantInt::get(intTy, 0));
        }
        
        bool isPowerOfTwo(uint64_t n) {
            return n > 0 && (n & (n - 1)) == 0;
        }
        
        unsigned Log2_64(uint64_t n) {
            unsigned result = 0;
            while (n >>= 1) result++;
            return result;
        }
    };
}

char InstructionSubstitution::ID = 0;
static RegisterPass<InstructionSubstitution> Y("inst-sub", "Instruction Substitution Obfuscation");

// New pass manager support
namespace {
    struct InstructionSubstitutionNewPM : public PassInfoMixin<InstructionSubstitutionNewPM> {
        PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
            InstructionSubstitution IS;
            if (IS.runOnFunction(F)) {
                return PreservedAnalyses::none();
            }
            return PreservedAnalyses::all();
        }
    };
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "InstructionSubstitution", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "inst-sub") {
                        FPM.addPass(InstructionSubstitutionNewPM{});
                        return true;
                    }
                    return false;
                });
        }};
}
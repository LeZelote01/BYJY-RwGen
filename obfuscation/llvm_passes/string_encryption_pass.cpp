#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include <vector>
#include <cstdlib>
#include <algorithm>
#include <openssl/evp.h>

using namespace llvm;

namespace {
struct AdvancedStringEncryptionPass : public ModulePass {
    static char ID;
    AdvancedStringEncryptionPass() : ModulePass(ID) {}

    bool runOnModule(Module &M) override {
        // Generate unique key per module
        std::string moduleKey = generateKey(16);
        GlobalVariable *keyGV = createKeyGlobal(M, moduleKey);
        
        // Create polymorphic decryptor
        Function *decryptFunc = createPolymorphicDecryptor(M);
        
        for (GlobalVariable &GV : M.globals()) {
            if (isTargetString(GV)) {
                encryptGlobalString(GV, M, decryptFunc, keyGV);
            }
        }
        
        return true;
    }

private:
    bool isTargetString(GlobalVariable &GV) {
        return GV.hasInitializer() && GV.isConstant() && 
               GV.getInitializer()->getType()->isArrayTy() &&
               GV.getInitializer()->getType()->getArrayElementType()->isIntegerTy(8) &&
               !GV.getName().startswith("decrypt_");
    }
    
    std::string generateKey(size_t length) {
        std::string key;
        for (size_t i = 0; i < length; ++i) {
            key += static_cast<char>(rand() % 256);
        }
        return key;
    }
    
    GlobalVariable* createKeyGlobal(Module &M, const std::string &key) {
        LLVMContext &context = M.getContext();
        
        // Create key array
        Constant *keyData = ConstantDataArray::getString(context, key, true);
        GlobalVariable *keyGV = new GlobalVariable(
            M, keyData->getType(), true,
            GlobalValue::PrivateLinkage, keyData, "decrypt_key"
        );
        keyGV->setAlignment(MaybeAlign(1));
        
        // Obfuscate key with XOR
        std::string xorKey = generateKey(key.size());
        Constant *xorData = ConstantDataArray::getString(context, xorKey, true);
        GlobalVariable *xorGV = new GlobalVariable(
            M, xorData->getType(), true,
            GlobalValue::PrivateLinkage, xorData, "xor_key"
        );
        xorGV->setAlignment(MaybeAlign(1));
        
        return keyGV;
    }
    
    void encryptGlobalString(GlobalVariable &GV, Module &M, Function *decryptFunc, GlobalVariable *keyGV) {
        ConstantDataArray *cda = cast<ConstantDataArray>(GV.getInitializer());
        std::string str = cda->getAsString().str();
        
        // Encrypt with AES-256-CBC
        unsigned char iv[16];
        RAND_bytes(iv, sizeof(iv));
        std::string encrypted = aesEncrypt(str, reinterpret_cast<const unsigned char*>(keyGV->getInitializer()->getAggregateElement(0)), iv);
        
        // Create IV global
        LLVMContext &context = M.getContext();
        Constant *ivData = ConstantDataArray::getRaw(StringRef(reinterpret_cast<const char*>(iv), 16, Type::getInt8Ty(context));
        GlobalVariable *ivGV = new GlobalVariable(
            M, ivData->getType(), true,
            GlobalValue::PrivateLinkage, ivData, GV.getName() + ".iv"
        );
        ivGV->setAlignment(MaybeAlign(1));
        
        // Create encrypted global
        Constant *encryptedData = ConstantDataArray::getString(context, encrypted, true);
        GlobalVariable *encryptedGV = new GlobalVariable(
            M, encryptedData->getType(), true,
            GlobalValue::PrivateLinkage, encryptedData, GV.getName() + ".enc"
        );
        encryptedGV->setAlignment(MaybeAlign(1));
        
        // Replace uses with decryptor call
        IRBuilder<> builder(M.getContext());
        for (User *U : make_early_inc_range(GV.users())) {
            if (Instruction *I = dyn_cast<Instruction>(U)) {
                builder.SetInsertPoint(I);
                Value *args[] = {
                    builder.CreateBitCast(encryptedGV, builder.getInt8PtrTy()),
                    builder.CreateBitCast(ivGV, builder.getInt8PtrTy()),
                    builder.CreateBitCast(keyGV, builder.getInt8PtrTy()),
                    ConstantInt::get(builder.getInt32Ty(), encrypted.size())
                };
                Value *decrypted = builder.CreateCall(decryptFunc, args);
                Value *casted = builder.CreateBitCast(decrypted, GV.getType());
                U->replaceAllUsesWith(casted);
            }
        }
    }
    
    std::string aesEncrypt(const std::string &plaintext, const unsigned char *key, const unsigned char *iv) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        
        int out_len = plaintext.length() + EVP_CIPHER_CTX_block_size(ctx);
        unsigned char *out = new unsigned char[out_len];
        
        int final_len;
        EVP_EncryptUpdate(ctx, out, &out_len, 
                         reinterpret_cast<const unsigned char*>(plaintext.data()), 
                         plaintext.length());
        EVP_EncryptFinal_ex(ctx, out + out_len, &final_len);
        
        std::string result(reinterpret_cast<const char*>(out), out_len + final_len);
        
        delete[] out;
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    Function* createPolymorphicDecryptor(Module &M) {
        LLVMContext &context = M.getContext();
        FunctionType *funcType = FunctionType::get(
            Type::getInt8PtrTy(context),
            {Type::getInt8PtrTy(context), Type::getInt8PtrTy(context), Type::getInt8PtrTy(context), Type::getInt32Ty(context)},
            false
        );
        Function *func = Function::Create(
            funcType,
            GlobalValue::PrivateLinkage,
            "polymorphic_decrypt",
            &M
        );
        
        // Create multiple implementation variants
        BasicBlock *entry = BasicBlock::Create(context, "entry", func);
        BasicBlock *variant1 = BasicBlock::Create(context, "variant1", func);
        BasicBlock *variant2 = BasicBlock::Create(context, "variant2", func);
        BasicBlock *merge = BasicBlock::Create(context, "merge", func);
        
        // Argument-based dispatch
        Argument *dataArg = &*func->arg_begin();
        IRBuilder<> builder(entry);
        Value *firstByte = builder.CreateLoad(builder.getInt8Ty(), dataArg);
        Value *cmp = builder.CreateICmpUGT(firstByte, builder.getInt8(128));
        builder.CreateCondBr(cmp, variant1, variant2);
        
        // Create polymorphic variants
        createDecryptorVariant(variant1, func, M);
        createDecryptorVariant(variant2, func, M);
        
        // Merge point
        builder.SetInsertPoint(merge);
        PHINode *result = builder.CreatePHI(Type::getInt8PtrTy(context), 2);
        result->addIncoming(variant1->getTerminator()->getOperand(0), variant1);
        result->addIncoming(variant2->getTerminator()->getOperand(0), variant2);
        builder.CreateRet(result);
        
        return func;
    }
    
    void createDecryptorVariant(BasicBlock *block, Function *func, Module &M) {
        LLVMContext &context = M.getContext();
        IRBuilder<> builder(block);
        
        // Get arguments
        auto argIt = func->arg_begin();
        Value *data = argIt++;
        Value *iv = argIt++;
        Value *key = argIt++;
        Value *size = argIt;
        
        // Allocate memory
        Value *mem = builder.CreateCall(
            M.getOrInsertFunction("malloc", func->getReturnType(), size->getType()).getCallee(),
            {builder.CreateAdd(size, ConstantInt::get(size->getType(), 32))} // Extra space
        );
        
        // Call actual decryption
        FunctionType *aesType = FunctionType::get(builder.getVoidTy(), 
            {mem->getType(), data->getType(), size->getType(), key->getType(), iv->getType()}, false);
        Function *aesFunc = Function::Create(aesType, GlobalValue::PrivateLinkage, "aes_decrypt_impl", &M);
        builder.CreateCall(aesFunc, {mem, data, size, key, iv});
        
        builder.CreateRet(mem);
        
        // Create AES implementation with different variants
        createAESImplementation(aesFunc, block == &func->front());
    }
    
    void createAESImplementation(Function *func, bool variant) {
        BasicBlock *entry = BasicBlock::Create(func->getContext(), "entry", func);
        IRBuilder<> builder(entry);
        
        // Dummy implementation - real AES would go here
        if (variant) {
            // Variant 1: simple copy
            auto argIt = func->arg_begin();
            Value *dest = argIt++;
            Value *src = argIt++;
            Value *size = argIt;
            
            builder.CreateMemCpy(dest, 1, src, 1, size);
        } else {
            // Variant 2: copy with XOR
            auto argIt = func->arg_begin();
            Value *dest = argIt++;
            Value *src = argIt++;
            Value *size = argIt;
            
            BasicBlock *loop = BasicBlock::Create(func->getContext(), "loop", func);
            BasicBlock *exit = BasicBlock::Create(func->getContext(), "exit", func);
            
            Value *i = builder.CreateAlloca(builder.getInt32Ty());
            builder.CreateStore(ConstantInt::get(builder.getInt32Ty(), 0), i);
            builder.CreateBr(loop);
            
            builder.SetInsertPoint(loop);
            PHINode *phi = builder.CreatePHI(builder.getInt32Ty(), 2);
            phi->addIncoming(ConstantInt::get(builder.getInt32Ty(), 0), entry);
            
            Value *srcPtr = builder.CreateGEP(builder.getInt8Ty(), src, phi);
            Value *val = builder.CreateLoad(builder.getInt8Ty(), srcPtr);
            Value *xored = builder.CreateXor(val, ConstantInt::get(builder.getInt8Ty(), 0xAA));
            Value *destPtr = builder.CreateGEP(builder.getInt8Ty(), dest, phi);
            builder.CreateStore(xored, destPtr);
            
            Value *next = builder.CreateAdd(phi, ConstantInt::get(builder.getInt32Ty(), 1));
            builder.CreateStore(next, i);
            
            Value *cmp = builder.CreateICmpULT(next, size);
            builder.CreateCondBr(cmp, loop, exit);
            
            phi->addIncoming(next, loop);
            
            builder.SetInsertPoint(exit);
        }
        
        builder.CreateRetVoid();
    }
};
} // namespace

char AdvancedStringEncryptionPass::ID = 0;
static RegisterPass<AdvancedStringEncryptionPass> Y("adv_strcrypt", "Advanced String Encryption", false, false);
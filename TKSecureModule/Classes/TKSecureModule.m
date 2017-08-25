//
//  TKSecureModule.m
//  TKSecureModule
//
//  Created by 云峰李 on 2017/8/24.
//  Copyright © 2017年 thinkWind. All rights reserved.
//

#import "TKSecureModule.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

static NSString *const kInitVector = @"16-tests--String";
// 填充模式
static const int32_t kTypeOfWrapPadding = kSecPaddingPKCS1;
@interface TKSecureModule ()

@property (nonatomic, assign) SecKeyRef publicKeyRef;            // 公钥引用
@property (nonatomic, assign) SecKeyRef privateKeyRef;           // 私钥引用

@end

@implementation TKSecureModule

#pragma mark - Base64

- (NSString *)base64StringFromString:(NSString *)string
{
    NSParameterAssert(string);
    NSData* base64Data = [string dataUsingEncoding:NSUTF8StringEncoding];
    return [self base64StringFromData:base64Data];
}

- (NSString *)base64StringFromData:(NSData *)signature
{
    NSParameterAssert(signature);
    NSString* retString = [signature base64EncodedStringWithOptions:0];
    return retString;
}

- (NSData *)base64DataFromString:(NSString *)string
{
    NSParameterAssert(string);
    return [[NSData alloc] initWithBase64EncodedString:string options:0];
}

- (NSString *)decodingStringFromBase64String:(NSString *)base64String
{
    NSParameterAssert(base64String);
    NSData* encodedString = [[NSData alloc] initWithBase64EncodedString:base64String options:0];
    return [[NSString alloc] initWithData:encodedString encoding:NSUTF8StringEncoding];
}

- (NSData *)decodingDataFromBase64String:(NSString *)base64String
{
    NSParameterAssert(base64String);
    return [[NSData alloc] initWithBase64EncodedString:base64String options:0];
}

#pragma mark - MD5

- (NSString *)md5:(NSString *)source
{
    const char* cStr = [source UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), digest);
    
    NSMutableString* output = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; ++i) {
        [output appendFormat:@"%02x",digest[i]];
    }
    return [output copy];
}

#pragma mark - DES

- (NSString *)encrypt:(NSString *)source operation:(CCOperation)operation key:(NSString *)key iv:(NSString *)iv
{
    const void* dataIn;
    size_t dataInLength;
    if(operation == kCCDecrypt)
    {
        NSData* decryptData = [self base64DataFromString:source];
        dataInLength = decryptData.length;
        dataIn = decryptData.bytes;
    }else{
        NSData* encryptData = [source dataUsingEncoding:NSUTF8StringEncoding];
        dataInLength = encryptData.length;
        dataIn = encryptData.bytes;
    }
    
    NSData* keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    CCCryptorStatus ccStatus;
    uint8_t* dataOut = NULL;
    size_t dataOutAvaliable = 0;
    size_t dataOutMoved = 0;
    
    dataOutAvaliable = (dataInLength + kCCBlockSizeDES) & ~(kCCBlockSizeDES - 1);
    dataOut = malloc(dataOutAvaliable * sizeof(uint8_t));
    memset((void *)dataOut, 0x0, dataOutAvaliable);
    
    const void* cIv = (const void *)iv.UTF8String;
    
    ccStatus = CCCrypt(operation,
                       kCCAlgorithmDES,
                       kCCOptionECBMode|kCCOptionPKCS7Padding,
                       keyData.bytes,
                       kCCKeySizeDES,
                       cIv,
                       dataIn,
                       dataInLength,
                       dataOut,
                       dataOutAvaliable,
                       &dataOutMoved);
    
    NSString* retString = nil;
    if(operation == kCCDecrypt){
        retString = [[NSString alloc] initWithData:[NSData dataWithBytes:(const void *)dataOut length:(NSUInteger)dataOutMoved] encoding:NSUTF8StringEncoding];
    }else{
        NSData *data = [NSData dataWithBytes:(const void *)dataOut length:(NSUInteger)dataOutMoved];
        retString = [data base64EncodedStringWithOptions:0];
    }
    
    free(dataOut);
    return retString;
}

- (NSString *)desEncoding:(NSString *)source key:(NSString *)key kvi:(NSString *)kvi
{
    return [self encrypt:source operation:kCCEncrypt key:key iv:kvi];
}

- (NSString *)desDecoding:(NSString *)source key:(NSString *)key kvi:(NSString *)kvi
{
    return [self encrypt:source operation:kCCDecrypt key:key iv:kvi];
}

#pragma mark - AES

- (NSString *)aesEncoding:(NSString *)source key:(NSString *)key
{
    NSData *contentData = [source dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = contentData.length;
    // 为结束符'\\0' +1
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    // 密文长度 <= 明文长度 + BlockSize
    size_t encryptSize = dataLength + kCCBlockSizeAES128;
    void *encryptedBytes = malloc(encryptSize);
    size_t actualOutSize = 0;
    NSData *initVector = [kInitVector dataUsingEncoding:NSUTF8StringEncoding];
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,  // 系统默认使用 CBC，然后指明使用 PKCS7Padding
                                          keyPtr,
                                          kCCKeySizeAES128,
                                          initVector.bytes,
                                          contentData.bytes,
                                          dataLength,
                                          encryptedBytes,
                                          encryptSize,
                                          &actualOutSize);
    if (cryptStatus == kCCSuccess) {
        // 对加密后的数据进行 base64 编码
        return [[NSData dataWithBytesNoCopy:encryptedBytes length:actualOutSize] base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    }
    free(encryptedBytes);
    return nil;
}

- (NSString *)aesDecoding:(NSString *)source key:(NSString *)key
{
    // 把 base64 String 转换成 Data
    NSData *contentData = [self base64DataFromString:source];
    NSUInteger dataLength = contentData.length;
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    size_t decryptSize = dataLength + kCCBlockSizeAES128;
    void *decryptedBytes = malloc(decryptSize);
    size_t actualOutSize = 0;
    NSData *initVector = [kInitVector dataUsingEncoding:NSUTF8StringEncoding];
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCKeySizeAES128,
                                          initVector.bytes,
                                          contentData.bytes,
                                          dataLength,
                                          decryptedBytes,
                                          decryptSize,
                                          &actualOutSize);
    if (cryptStatus == kCCSuccess) {
        return [[NSString alloc] initWithData:[NSData dataWithBytesNoCopy:decryptedBytes length:actualOutSize] encoding:NSUTF8StringEncoding];
    }
    free(decryptedBytes);
    return nil;
}

#pragma mark - RSA 加密/解密算法
- (void)loadPublicKeyWithFilePath:(NSString *)filePath;
{
    
    NSAssert(filePath.length != 0, @"公钥路径为空");
    
    // 删除当前公钥
    if (_publicKeyRef) CFRelease(_publicKeyRef);
    
    // 从一个 DER 表示的证书创建一个证书对象
    NSData *certificateData = [NSData dataWithContentsOfFile:filePath];
    SecCertificateRef certificateRef = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certificateData);
    NSAssert(certificateRef != NULL, @"公钥文件错误");
    
    // 返回一个默认 X509 策略的公钥对象，使用之后需要调用 CFRelease 释放
    SecPolicyRef policyRef = SecPolicyCreateBasicX509();
    // 包含信任管理信息的结构体
    SecTrustRef trustRef;
    
    // 基于证书和策略创建一个信任管理对象
    OSStatus status = SecTrustCreateWithCertificates(certificateRef, policyRef, &trustRef);
    NSAssert(status == errSecSuccess, @"创建信任管理对象失败");
    
    // 信任结果
    SecTrustResultType trustResult;
    // 评估指定证书和策略的信任管理是否有效
    status = SecTrustEvaluate(trustRef, &trustResult);
    NSAssert(status == errSecSuccess, @"信任评估失败");
    
    // 评估之后返回公钥子证书
    _publicKeyRef = SecTrustCopyPublicKey(trustRef);
    NSAssert(_publicKeyRef != NULL, @"公钥创建失败");
    
    if (certificateRef) CFRelease(certificateRef);
    if (policyRef) CFRelease(policyRef);
    if (trustRef) CFRelease(trustRef);
}

- (void)loadPrivateKeyWithFilePath:(NSString *)filePath password:(NSString *)password
{
    NSAssert(filePath.length != 0, @"私钥路径为空");
    // 删除当前私钥
    if (_privateKeyRef) CFRelease(_privateKeyRef);
    
    NSData *PKCS12Data = [NSData dataWithContentsOfFile:filePath];
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    CFStringRef passwordRef = (__bridge CFStringRef)password;
    
    // 从 PKCS #12 证书中提取标示和证书
    SecIdentityRef myIdentity = NULL;
    SecTrustRef myTrust;
    const void *keys[] = {kSecImportExportPassphrase};
    const void *values[] = {passwordRef};
    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    
    // 返回 PKCS #12 格式数据中的标示和证书
    OSStatus status = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);
    
    if (status == noErr) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
        myIdentity = (SecIdentityRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
        myTrust = (SecTrustRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
    }
    
    if (optionsDictionary) CFRelease(optionsDictionary);
    
    NSAssert(status == noErr, @"提取身份和信任失败");
    
    SecTrustResultType trustResult;
    // 评估指定证书和策略的信任管理是否有效
    status = SecTrustEvaluate(myTrust, &trustResult);
    NSAssert(status == errSecSuccess, @"信任评估失败");
    
    // 提取私钥
    status = SecIdentityCopyPrivateKey(myIdentity, &_privateKeyRef);
    NSAssert(status == errSecSuccess, @"私钥创建失败");
    CFRelease(items);
}

- (NSString *)RSAEncodingString:(NSString *)string
{
    NSData *cipher = [self RSAEncodingData:[string dataUsingEncoding:NSUTF8StringEncoding]];
    
    return [cipher base64EncodedStringWithOptions:0];
}

- (NSData *)RSAEncodingData:(NSData *)data
{
    OSStatus sanityCheck = noErr;
    size_t cipherBufferSize = 0;
    size_t keyBufferSize = 0;
    
    NSAssert(data, @"明文数据为空");
    NSAssert(_publicKeyRef, @"公钥为空");
    
    NSData *cipher = nil;
    uint8_t *cipherBuffer = NULL;
    
    // 计算缓冲区大小
    cipherBufferSize = SecKeyGetBlockSize(_publicKeyRef);
    keyBufferSize = data.length;
    
    if (kTypeOfWrapPadding == kSecPaddingNone) {
        NSAssert(keyBufferSize <= cipherBufferSize, @"加密内容太大");
    } else {
        NSAssert(keyBufferSize <= (cipherBufferSize - 11), @"加密内容太大");
    }
    
    // 分配缓冲区
    cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    memset((void *)cipherBuffer, 0x0, cipherBufferSize);
    
    // 使用公钥加密
    sanityCheck = SecKeyEncrypt(_publicKeyRef,
                                kTypeOfWrapPadding,
                                (const uint8_t *)data.bytes,
                                keyBufferSize,
                                cipherBuffer,
                                &cipherBufferSize
                                );
    
    NSAssert(sanityCheck == noErr, @"加密错误，OSStatus == %d", sanityCheck);
    
    // 生成密文数据
    cipher = [NSData dataWithBytes:(const void *)cipherBuffer length:(NSUInteger)cipherBufferSize];
    
    if (cipherBuffer) free(cipherBuffer);
    
    return cipher;
}

- (NSString *)RSADecodingString:(NSString *)string
{
    NSData *keyData = [self RSADecodingData:[[NSData alloc] initWithBase64EncodedString:string options:0]];
    
    return [[NSString alloc] initWithData:keyData encoding:NSUTF8StringEncoding];
}

- (NSData *)RSADecodingData:(NSData *)data
{
    OSStatus sanityCheck = noErr;
    size_t cipherBufferSize = 0;
    size_t keyBufferSize = 0;
    
    NSData *key = nil;
    uint8_t *keyBuffer = NULL;
    
    SecKeyRef privateKey = _privateKeyRef;
    NSAssert(privateKey != NULL, @"私钥不存在");
    
    // 计算缓冲区大小
    cipherBufferSize = SecKeyGetBlockSize(privateKey);
    keyBufferSize = data.length;
    
    NSAssert(keyBufferSize <= cipherBufferSize, @"解密内容太大");
    
    // 分配缓冲区
    keyBuffer = malloc(keyBufferSize * sizeof(uint8_t));
    memset((void *)keyBuffer, 0x0, keyBufferSize);
    
    // 使用私钥解密
    sanityCheck = SecKeyDecrypt(privateKey,
                                kTypeOfWrapPadding,
                                (const uint8_t *)data.bytes,
                                cipherBufferSize,
                                keyBuffer,
                                &keyBufferSize
                                );
    
    NSAssert1(sanityCheck == noErr, @"解密错误，OSStatus == %d", sanityCheck);
    
    // 生成明文数据
    key = [NSData dataWithBytes:(const void *)keyBuffer length:(NSUInteger)keyBufferSize];
    
    if (keyBuffer) free(keyBuffer);
    
    return key;
}


@end

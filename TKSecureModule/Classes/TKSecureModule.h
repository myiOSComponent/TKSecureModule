//
//  TKSecureModule.h
//  TKSecureModule
//
//  Created by 云峰李 on 2017/8/24.
//  Copyright © 2017年 thinkWind. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TKSecureModule : NSObject

#pragma mark - Base64
- (NSString *)base64StringFromString:(NSString *)string;

- (NSString *)base64StringFromData:(NSData *)signature;

- (NSData *) base64DataFromString:(NSString *)string;

- (NSString *)decodingStringFromBase64String:(NSString *)base64String;

- (NSData *)decodingDataFromBase64String:(NSString *)base64String;


#pragma mark - MD5

- (NSString *)md5:(NSString *)source;

#pragma mark - DES

- (NSString *)desEncoding:(NSString *)source key:(NSString *)key kvi:(NSString *)kiv;

- (NSString *)desDecoding:(NSString *)source key:(NSString *)key kvi:(NSString *)kiv;

#pragma mark - AES

- (NSString *)aesEncoding:(NSString *)source key:(NSString *)key;

- (NSString *)aesDecoding:(NSString *)source key:(NSString *)key;

#pragma mark - RSA
///  加载公钥
///
///  @param filePath DER 公钥文件路径
- (void)loadPublicKeyWithFilePath:(NSString *)filePath;

///  加载私钥
///
///  @param filePath P12 私钥文件路径
///  @param password P12 密码
- (void)loadPrivateKeyWithFilePath:(NSString *)filePath password:(NSString *)password;

///  RSA 加密数据
///
///  @param data 要加密的数据
///
///  @return 加密后的二进制数据
- (NSData *)RSAEncodingData:(NSData *)data;

///  RSA 加密字符串
///
///  @param string 要加密的字符串
///
///  @return 加密后的 BASE64 编码字符串
- (NSString *)RSAEncodingString:(NSString *)string;

///  RSA 解密数据
///
///  @param data 要解密的数据
///
///  @return 解密后的二进制数据
- (NSData *)RSADecodingData:(NSData *)data;

///  RSA 解密字符串
///
///  @param string 要解密的 BASE64 编码字符串
///
///  @return 解密后的字符串
- (NSString *)RSADecodingString:(NSString *)string;

@end

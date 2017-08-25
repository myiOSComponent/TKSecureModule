//
//  TKTargetSecure.m
//  TKSecureModule
//
//  Created by 云峰李 on 2017/8/24.
//  Copyright © 2017年 thinkWind. All rights reserved.
//

#import "TKTargetSecure.h"
#import "TKSecureModule.h"

static NSString* const kTKSecureContent = @"content";
static NSString* const kTKSecureKey = @"secureKey";
static NSString* const kTKSecureKiv = @"securKiv";

@interface TKTargetSecure ()

@property (nonatomic, strong) TKSecureModule* secureModule;

@end

@implementation TKTargetSecure

#pragma mark - Base64
- (NSString *)tkAction_base64StringFromString:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    return [self.secureModule base64StringFromString:content];
}

- (NSString *)tkAction_base64StringFromData:(NSDictionary *)params
{
    NSData* content = params[kTKSecureContent];
    return [self.secureModule base64StringFromData:content];
}

- (NSData *)tkAction_base64DataFromString:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    return [self.secureModule base64DataFromString:content];
}

- (NSString *)tkAction_decodingStringFromBase64String:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    return [self.secureModule decodingStringFromBase64String:content];
}

- (NSData *)tkAction_decodingDataFromBase64String:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    return [self.secureModule decodingDataFromBase64String:content];
}

#pragma mark - MD5

- (NSString *)tkAction_md5:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    return [self.secureModule md5:content];
}

#pragma mark - DES

- (NSString *)tkAction_desEncoding:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    NSString* key = params[kTKSecureKey];
    NSString* kiv = params[kTKSecureKiv];
    return [self.secureModule desEncoding:content key:key kvi:kiv];
}

- (NSString *)tkAction_desDecoding:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    NSString* key = params[kTKSecureKey];
    NSString* kvi = params[kTKSecureKiv];
    return [self.secureModule desDecoding:content key:key kvi:kvi];
}

#pragma mark - AES

- (NSString *)tkAction_aesEncoding:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    NSString* key = params[kTKSecureKey];
    return [self.secureModule aesEncoding:content key:key];
}

- (NSString *)tkAction_aesDecoding:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    NSString* key = params[kTKSecureKey];
    return [self.secureModule aesDecoding:content key:key];
}

#pragma mark - RSA

- (void)tkAction_loadPublicKeyWithFilePath:(NSDictionary *)params
{
    NSString* filePath = params[kTKSecureContent];
    [self.secureModule loadPublicKeyWithFilePath:filePath];
}

- (void)tkAction_loadPrivateKeyWithFilePath:(NSDictionary *)params
{
    NSString* filePath = params[kTKSecureContent];
    NSString* password = params[kTKSecureKey];
    [self.secureModule loadPrivateKeyWithFilePath:filePath password:password];
}

- (NSData *)tkAction_RSAEncodingData:(NSDictionary *)params
{
    NSData* content = params[kTKSecureContent];
    return [self.secureModule RSAEncodingData:content];
}

- (NSString *)tkAction_RSAEncodingString:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    return [self.secureModule RSAEncodingString:content];
}

- (NSData *)tkAction_RSADecodingData:(NSDictionary *)params
{
    NSData* content = params[kTKSecureContent];
    return [self.secureModule RSADecodingData:content];
}

- (NSString *)tkAction_RSADecodingString:(NSDictionary *)params
{
    NSString* content = params[kTKSecureContent];
    return [self.secureModule RSADecodingString:content];
}

#pragma mark - getter

- (TKSecureModule *)secureModule
{
    if (!_secureModule) {
        _secureModule = [TKSecureModule new];
    }
    return _secureModule;
}
@end

//
//  TKTargetSecure.h
//  TKSecureModule
//
//  Created by 云峰李 on 2017/8/24.
//  Copyright © 2017年 thinkWind. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TKTargetSecure : NSObject

#pragma mark - Base64
- (NSString *)tkAction_base64StringFromString:(NSDictionary *)params;

- (NSString *)tkAction_base64StringFromData:(NSDictionary *)params;

- (NSData *)tkAction_base64DataFromString:(NSDictionary *)params;

- (NSString *)tkAction_decodingStringFromBase64String:(NSDictionary *)params;

- (NSData *)tkAction_decodingDataFromBase64String:(NSDictionary *)params;

#pragma mark - MD5

- (NSString *)tkAction_md5:(NSDictionary *)params;

#pragma mark - DES

- (NSString *)tkAction_desEncoding:(NSDictionary *)params;

- (NSString *)tkAction_desDecoding:(NSDictionary *)params;

#pragma mark - AES

- (NSString *)tkAction_aesEncoding:(NSDictionary *)params;

- (NSString *)tkAction_aesDecoding:(NSDictionary *)params;

#pragma mark - RSA

- (void)tkAction_loadPublicKeyWithFilePath:(NSDictionary *)params;

- (void)tkAction_loadPrivateKeyWithFilePath:(NSDictionary *)params;

- (NSData *)tkAction_RSAEncodingData:(NSDictionary *)params;

- (NSString *)tkAction_RSAEncodingString:(NSDictionary *)params;

- (NSData *)tkAction_RSADecodingData:(NSDictionary *)params;

- (NSString *)tkAction_RSADecodingString:(NSDictionary *)params;

@end

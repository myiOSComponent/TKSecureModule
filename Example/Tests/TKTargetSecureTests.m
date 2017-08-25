//
//  TKSecureTests.m
//  TKSecureModule
//
//  Created by 云峰李 on 2017/8/24.
//  Copyright © 2017年 thinkWind. All rights reserved.
//

#import <Kiwi/Kiwi.h>
#import <TKSecureModule/TKTargetSecure.h>

static NSString* const kTKSecureContent = @"content";
static NSString* const kTKSecureKey = @"secureKey";
static NSString* const kTKSecureKiv = @"securKiv";

SPEC_BEGIN(SecureTargetTests)

describe(@"安全性性测试", ^{
    context(@"测试base64转码", ^{
        let(secure, ^id{
            return [TKTargetSecure new];
        });
        
        it(@"base64 加密和解密", ^{
            NSString* ret = [secure tkAction_base64StringFromString:@{kTKSecureContent:@"test"}];
            NSLog(@"加密后%@",ret);
            NSString* convertRet = [secure tkAction_decodingStringFromBase64String:@{kTKSecureContent:ret}];
             [[convertRet should] equal:@"test"];
        });
    });
    
    context(@"测试Md5码 加密", ^{
        it(@"md5 加密", ^{
            NSString* ret = [[TKTargetSecure new] tkAction_md5:@{kTKSecureContent:@"test"}];
            NSLog(@"加密后%@",ret);
        });
    });
    
    context(@"测试DES 加密", ^{
        let(secure, ^id{
            return [TKTargetSecure new];
        });
        
        it(@"DES 加密，解密", ^{
            NSString* ret = [secure tkAction_desEncoding:@{kTKSecureContent:@"mytest",
                                                           kTKSecureKey:@"12345",
                                                           kTKSecureKiv:@"234561"}];
            NSLog(@"des加密后的结果%@",ret);
            NSString* convertRet = [secure tkAction_desDecoding:@{kTKSecureContent:ret,
                                                                  kTKSecureKey:@"12345",
                                                                  kTKSecureKiv:@"234561"}];
            [[convertRet should] equal:@"mytest"];
        });
    });
    
    context(@"测试AES 加密", ^{
        let(secure, ^id{
            return [TKTargetSecure new];
        });
        
        it(@"测试AES 加解密", ^{
            NSString* ret = [secure tkAction_aesEncoding:@{kTKSecureContent:@"mytest",
                                                                kTKSecureKey:@"lajfaa"}];
            NSLog(@"aes 加密后的结果%@",ret);
            NSString* convertRet = [secure tkAction_aesDecoding:@{kTKSecureContent:ret,
                                                                  kTKSecureKey:@"lajfaa"}];
            [[convertRet should] equal:@"mytest"];
        });
    });
});

SPEC_END

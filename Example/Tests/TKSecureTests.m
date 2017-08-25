//
//  TKSecureTests.m
//  TKSecureModule
//
//  Created by 云峰李 on 2017/8/24.
//  Copyright © 2017年 thinkWind. All rights reserved.
//

#import <Kiwi/Kiwi.h>
#import <TKSecureModule/TKSecureModule.h>

SPEC_BEGIN(SecureTests)

describe(@"安全性性测试", ^{
    context(@"测试base64转码", ^{
        let(secure, ^id{
            return [TKSecureModule new];
        });
        
        it(@"base64 加密和解密", ^{
            NSString* ret = [secure base64StringFromString:@"test"];
            NSLog(@"加密后%@",ret);
            NSString* convertRet = [secure decodingStringFromBase64String:ret];
             [[convertRet should] equal:@"test"];
        });
    });
    
    context(@"测试Md5码 加密", ^{
        it(@"md5 加密", ^{
            NSString* ret = [[TKSecureModule new] md5:@"test"];
            NSLog(@"加密后%@",ret);
        });
    });
    
    context(@"测试DES 加密", ^{
        let(secure, ^id{
            return [TKSecureModule new];
        });
        
        it(@"DES 加密，解密", ^{
            NSString* ret = [secure desEncoding:@"mytest" key:@"12345" kvi:@"234561"];
            NSLog(@"des加密后的结果%@",ret);
            NSString* convertRet = [secure desDecoding:ret key:@"12345" kvi:@"234561"];
            [[convertRet should] equal:@"mytest"];
        });
    });
    
    context(@"测试AES 加密", ^{
        let(secure, ^id{
            return [TKSecureModule new];
        });
        
        it(@"测试AES 加解密", ^{
            NSString* ret = [secure aesEncoding:@"mytest" key:@"lajfaa"];
            NSLog(@"aes 加密后的结果%@",ret);
            NSString* convertRet = [secure aesDecoding:ret key:@"lajfaa"];
            [[convertRet should] equal:@"mytest"];
        });
    });
});

SPEC_END

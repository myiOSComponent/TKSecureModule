#ifdef __OBJC__
#import <UIKit/UIKit.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

#import "TKTargetSecure.h"
#import "TKSecureModule.h"

FOUNDATION_EXPORT double TKSecureModuleVersionNumber;
FOUNDATION_EXPORT const unsigned char TKSecureModuleVersionString[];


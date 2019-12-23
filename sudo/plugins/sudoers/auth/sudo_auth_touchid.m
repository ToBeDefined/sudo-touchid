//
//  sudo_auth_touchid.m
//  sudo
//
//  Created by TBD on 2019/12/23.
//  Copyright © 2019 TBD. All rights reserved.
//

#include "sudo_auth_touchid.h"
#include "sudo_auth.h"

#import <LocalAuthentication/LocalAuthentication.h>

typedef enum {
    kTouchIDResultNone,
    kTouchIDResultAllowed,
    kTouchIDResultFallback,
    kTouchIDResultCancel,
    kTouchIDResultFailed
} TouchIDResult;

static const LAPolicy kAuthPolicy = 0x3f0;
static const LAPolicy kAuthPolicyFallback = LAPolicyDeviceOwnerAuthentication;

int
touchid_setup(struct passwd *pw, char **prompt, sudo_auth *auth) {
    @try {
        LAContext *context = [[LAContext alloc] init];
        BOOL canAuthenticate =
            [context canEvaluatePolicy:kAuthPolicy error:nil] ||
            [context canEvaluatePolicy:kAuthPolicyFallback error:nil];
//        [context release];
        return canAuthenticate ? AUTH_SUCCESS : AUTH_FATAL;
    }
    @catch(NSException *) {
        // LAPolicyDeviceOwnerAuthenticationWithBiometrics may not be available on builds older than 10.12.1!
        sudo_printf(SUDO_CONV_INFO_MSG, "2");
        return AUTH_FATAL;
    }
    
}

int
touchid_verify(struct passwd *pw, char *pass, sudo_auth *auth, struct sudo_conv_callback *callback) {
    __block TouchIDResult result = kTouchIDResultNone;
    while (result == kTouchIDResultFallback || result == kTouchIDResultNone) {
        LAContext *context = [[LAContext alloc] init];
        // @"authenticate a privileged operation"
        [context evaluatePolicy:(result != kTouchIDResultFallback ? kAuthPolicy : kAuthPolicyFallback) localizedReason:@"验证密码进行特权操作" reply:^(BOOL success, NSError *error) {
            result = success ? kTouchIDResultAllowed : kTouchIDResultFailed;
            switch (error.code) {
                case LAErrorBiometryLockout:
                case LAErrorBiometryNotEnrolled:
                case LAErrorBiometryNotAvailable:
                case LAErrorUserFallback:
                case LAErrorAuthenticationFailed:
                    result = kTouchIDResultFallback;
                    break;
                case LAErrorSystemCancel:
                case LAErrorAppCancel:
                case LAErrorUserCancel:
                    result = kTouchIDResultCancel;
                    break;
            }
            CFRunLoopWakeUp(CFRunLoopGetCurrent());
        }];
        
        result = kTouchIDResultNone;

        while (result == kTouchIDResultNone) {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, true);
        }
        
//        [context release];
    }
    
    switch (result) {
        case kTouchIDResultCancel:
            return AUTH_FATAL;
        case kTouchIDResultAllowed:
            return AUTH_SUCCESS;
        default:
            return AUTH_FAILURE;
    }
}

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

#import "TOTPGenerator.h"
#import "MF_Base32Additions.h"

#import <Security/Security.h>
#import <AppKit/AppKit.h>


#ifdef DEBUG
#define NSLog(FORMAT, ...) fprintf(stderr,"%s\n",[[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String]);
#else
#define NSLog(FORMAT, ...) printf("%s\n",[[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String])
#endif

NSString * help = @"\nHelp:\n\t-l\t\t\t\tshow saved list\n\t-s code\t\t\tto save secret\n\t-g code\t\t\tto get the totp\n\t-d code\t\t\tdelete code\nVersion:\n\t0.0.3\n\thttps://github.com/xsdhy/mac-mfa";

// 保存secret到钥匙串
void savePassword(NSString *code, NSString *password) {
    NSDictionary *keychainItem = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"MacMFAService",
        (__bridge id)kSecAttrAccount: code,
        (__bridge id)kSecValueData: [password dataUsingEncoding:NSUTF8StringEncoding],
    };
    SecItemAdd((__bridge CFDictionaryRef)keychainItem, NULL);
}

// 从钥匙串获取secret
NSString* getPassword(NSString *code) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"MacMFAService",
        (__bridge id)kSecAttrAccount: code,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    NSData *data = (__bridge_transfer NSData *)result;
    if (data) {
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return nil;
}
// 列出所有保存的codes
void listCodes() {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"MacMFAService",
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
    };
    CFTypeRef result = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)query, &result) == errSecSuccess) {
        NSArray *items = (__bridge NSArray *)result;
        for (NSDictionary *item in items) {
            NSLog(@"Code: %@", item[(__bridge id)kSecAttrAccount]);
        }
    }
}

// 删除指定code的secret
void deletePassword(NSString *code) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"MacMFAService",
        (__bridge id)kSecAttrAccount: code,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

void generator(NSString *secret){
    NSData *secretData =  [NSData dataWithBase32String:secret];
    NSInteger digits = 6;
    NSInteger period = 30;

    NSDate *now = [NSDate date];
    long timestamp = (long)[now timeIntervalSince1970];
    if(timestamp % 30 != 0){
        timestamp -= timestamp % 30;
    }
    TOTPGenerator *generator = [[TOTPGenerator alloc] initWithSecret:secretData algorithm:kOTPGeneratorSHA1Algorithm digits:digits period:period];

    NSString *pin = [generator generateOTPForDate:[NSDate dateWithTimeIntervalSince1970:timestamp]];
    
    // 获取系统剪贴板
    NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
    // 清空剪贴板以便设置新内容
    [pasteboard clearContents];
    // 将字符串保存到剪贴板
    [pasteboard setString:pin forType:NSPasteboardTypeString];
    
    NSLog(@"%@",pin);
}

//Touch ID验证
void touchIDAuth(NSString *secret){
    LAContext *context = [[LAContext alloc] init];
    __block BOOL done = NO;
    
    NSError *error = nil;
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                localizedReason:@"Authenticate to receive your OTP"
                          reply:^(BOOL success, NSError *error) {
            if (success) {
                //认证成功
                generator(secret);
            } else {
                NSLog(@"Authentication Failed: %@", error.localizedDescription);
            }
            done = YES;
            exit(0);
        }];
    } else {
        NSLog(@"Touch ID not available: %@", error.localizedDescription);
        done = YES;
        exit(0);
    }
    while (!done) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]];
    }
}


int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // 解析命令行参数
        NSArray *arguments = [[NSProcessInfo processInfo] arguments];
        if ([arguments count] > 1) {
            NSString *action = arguments[1];
            if ([action isEqualToString:@"-s"] && [arguments count] == 3) {
                // 保存密码
                
                char passwordInput[100]; // 假设密码不会超过100个字符
                NSLog(@"Enter secret for code %@: ", arguments[2]);
                scanf("%99s", passwordInput); // 读取用户输入的密码
                NSString *password = [NSString stringWithUTF8String:passwordInput];

                // 检查输入的密码是否为空
                if ([password length] == 0) {
                    NSLog(@"Error: secret cannot be empty.");
                    exit(0);
                }
                
                savePassword(arguments[2], password);
                NSLog(@"secret saved for code: %@", arguments[2]);
            } else if ([action isEqualToString:@"-g"] && [arguments count] == 3) {
                // 获取密码
                NSString *secret = getPassword(arguments[2]);
                if (secret) {
                    touchIDAuth(secret);
                } else {
                    NSLog(@"No secret found for code %@", arguments[2]);
                }
            }else if ([action isEqualToString:@"-l"]) {
                          // 列出所有保存的codes
                          listCodes();
            } else if ([action isEqualToString:@"-d"] && [arguments count] == 3) {
                          // 删除指定code的password
                          deletePassword(arguments[2]);
                          NSLog(@"Deleted secret for code: %@", arguments[2]);
            } else {
                NSLog(@"No arguments provided. %@",help);
            }
        } else {
            NSLog(@"No arguments provided. %@",help);
        }
    }
    return 0;
}



#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

#import "TOTPGenerator.h"
#import "MF_Base32Additions.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        __block BOOL done = NO;

        NSError *error = nil;
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
            [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:@"Authenticate to receive your OTP"
            reply:^(BOOL success, NSError *error) {
                if (success) {
                    //认证成功
                    NSString *secret = @"SSYZYGYZPFLV7NMQ44AQ757H3YCHVNFM";
                    NSData *secretData =  [NSData dataWithBase32String:secret];
                    NSInteger digits = 6;
                    NSInteger period = 30;

                    NSDate *now = [NSDate date];
                    long timestamp = (long)[now timeIntervalSince1970];
                    if(timestamp % 30 != 0){
                        timestamp -= timestamp % 30;
                    }
                    TOTPGenerator *generator = [[TOTPGenerator alloc] initWithSecret:secretData algorithm:kOTPGeneratorSHA1Algorithm digits:digits period:period];

                    unsigned int pin = [generator generateOTPForDate:[NSDate dateWithTimeIntervalSince1970:timestamp]];

                    printf("%d\n",pin);
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
    return 0;
}

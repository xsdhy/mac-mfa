#import <Foundation/Foundation.h>

@interface OTPGenerator : NSObject

@property (readonly, nonatomic, copy) NSString *algorithm;
@property (readonly, nonatomic, copy) NSData *secret;
@property (readonly, nonatomic) NSUInteger digits;

// Some default values.
+ (NSString *)defaultAlgorithm;
+ (NSUInteger)defaultDigits;

// Designated initializer.
- (id)initWithSecret:(NSData *)secret
           algorithm:(NSString *)algorithm
              digits:(NSUInteger)digits;


// Instance method to generate an OTP using the |algorithm|, |secret|,
// |counter| and |digits| values configured on the object.
// The return value is an NSString of |digits| length, with leading
// zero-padding as required.
- (NSString *)generateOTPForCounter:(uint64_t)counter;


// Instance method to generate an OTP using the |algorithm|, |secret|,
// |counter| and |digits| values configured on the object.
// The return value is an NSString of |digits| length, with leading
// zero-padding as required.
- (NSString *)generateOTP;

@end

extern NSString *const kOTPGeneratorSHA1Algorithm;
extern NSString *const kOTPGeneratorSHA256Algorithm;
extern NSString *const kOTPGeneratorSHA512Algorithm;
extern NSString *const kOTPGeneratorSHAMD5Algorithm;

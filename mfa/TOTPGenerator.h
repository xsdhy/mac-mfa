#import <Foundation/Foundation.h>
#import "OTPGenerator.h"


@interface TOTPGenerator : OTPGenerator

// The period to use when calculating the counter.
@property(assign, nonatomic, readonly) NSTimeInterval period;

+ (NSTimeInterval)defaultPeriod;

// Designated initializer.
- (id)initWithSecret:(NSData *)secret
           algorithm:(NSString *)algorithm
              digits:(NSUInteger)digits
              period:(NSTimeInterval)period;

// Instance method to generate an OTP using the |algorithm|, |secret|,
// |digits|, |period| and |now| values configured on the object.
// The return value is an NSString of |digits| length, with leading
// zero-padding as required.
- (unsigned int)generateOTPForDate:(NSDate *)date;

@end

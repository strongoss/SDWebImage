/*
 * This file is part of the SDWebImage package.
 * (c) Olivier Poitrey <rs@dailymotion.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#import "SDAnimatedImage.h"
#import "NSImage+Additions.h"
#import "UIImage+WebCache.h"
#import "SDWebImageCoder.h"
#import "SDWebImageCodersManager.h"
#import "SDWebImageFrame.h"

#define LOCK(...) dispatch_semaphore_wait(self->_lock, DISPATCH_TIME_FOREVER); \
__VA_ARGS__; \
dispatch_semaphore_signal(self->_lock);

static CGFloat SDImageScaleFromPath(NSString *string) {
    if (string.length == 0 || [string hasSuffix:@"/"]) return 1;
    NSString *name = string.stringByDeletingPathExtension;
    __block CGFloat scale = 1;
    
    NSRegularExpression *pattern = [NSRegularExpression regularExpressionWithPattern:@"@[0-9]+\\.?[0-9]*x$" options:NSRegularExpressionAnchorsMatchLines error:nil];
    [pattern enumerateMatchesInString:name options:kNilOptions range:NSMakeRange(0, name.length) usingBlock:^(NSTextCheckingResult *result, NSMatchingFlags flags, BOOL *stop) {
        if (result.range.location >= 3) {
            scale = [string substringWithRange:NSMakeRange(result.range.location + 1, result.range.length - 2)].doubleValue;
        }
    }];
    
    return scale;
}

static NSArray *SDBundlePreferredScales() {
    static NSArray *scales;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
#if SD_WATCH
        CGFloat screenScale = [WKInterfaceDevice currentDevice].screenScale;
#elif SD_UIKIT
        CGFloat screenScale = [UIScreen mainScreen].scale;
#elif SD_MAC
        CGFloat screenScale = [NSScreen mainScreen].backingScaleFactor;
#endif
        if (screenScale <= 1) {
            scales = @[@1,@2,@3];
        } else if (screenScale <= 2) {
            scales = @[@2,@3,@1];
        } else {
            scales = @[@3,@2,@1];
        }
    });
    return scales;
}

#pragma mark - UIImage cache for bundle

// Apple parse the Asset Catalog compiled file(`Assets.car`) by CoreUI.framework, however it's a private framework and there are no other ways to directly get the data. So we just process the normal bundle files :)

@interface SDImageAssetManager : NSObject {
    dispatch_semaphore_t _lock;
}

@property (nonatomic, strong) NSMapTable<NSString *, UIImage *> *imageTable;

+ (instancetype)sharedAssetManager;
- (nullable NSString *)getPathForName:(nonnull NSString *)name bundle:(nonnull NSBundle *)bundle preferredScale:(CGFloat *)scale;
- (nullable UIImage *)imageForName:(nonnull NSString *)name;
- (void)storeImage:(nonnull UIImage *)image forName:(nonnull NSString *)name;

@end

@implementation SDImageAssetManager

+ (instancetype)sharedAssetManager {
    static dispatch_once_t onceToken;
    static SDImageAssetManager *assetManager;
    dispatch_once(&onceToken, ^{
        assetManager = [[SDImageAssetManager alloc] init];
    });
    return assetManager;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        NSPointerFunctionsOptions valueOptions;
#if SD_MAC
        // Apple says that NSImage use a weak reference to value
        valueOptions = NSPointerFunctionsWeakMemory;
#else
        // Apple says that UIImage use a strong reference to value
        valueOptions = NSPointerFunctionsStrongMemory;
#endif
        _imageTable = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsCopyIn valueOptions:valueOptions];
        _lock = dispatch_semaphore_create(1);
#if SD_UIKIT
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(didReceiveMemoryWarning:) name:UIApplicationDidReceiveMemoryWarningNotification object:nil];
#endif
    }
    return self;
}

- (void)dealloc {
#if SD_UIKIT
    [[NSNotificationCenter defaultCenter] removeObserver:self name:UIApplicationDidReceiveMemoryWarningNotification object:nil];
#endif
}

- (void)didReceiveMemoryWarning:(NSNotification *)notification {
    LOCK({
        [self.imageTable removeAllObjects];
    });
}

- (NSString *)getPathForName:(NSString *)name bundle:(NSBundle *)bundle preferredScale:(CGFloat *)scale {
    NSParameterAssert(name);
    NSParameterAssert(bundle);
    NSString *path;
    if (name.length == 0) {
        return path;
    }
    if ([name hasSuffix:@"/"]) {
        return path;
    }
    NSString *extension = name.pathExtension;
    if (extension.length == 0) {
        // If no extension, follow Apple's doc, check PNG format
        extension = @"png";
    }
    name = [name stringByDeletingPathExtension];
    
    CGFloat providedScale = *scale;
    NSArray *scales = SDBundlePreferredScales();
    
    // Check if file name contains scale
    for (size_t i = 0; i < scales.count; i++) {
        NSNumber *scaleValue = scales[i];
        if ([name hasSuffix:[NSString stringWithFormat:@"@%@x", scaleValue]]) {
            path = [bundle pathForResource:name ofType:extension];
            if (path) {
                *scale = scaleValue.doubleValue; // override
                return path;
            }
        }
    }
    
    // Search with provided scale first
    if (providedScale != 0) {
        NSString *scaledName = [name stringByAppendingFormat:@"@%@x", @(providedScale)];
        path = [bundle pathForResource:scaledName ofType:extension];
        if (path) {
            return path;
        }
    }
    
    // Search with preferred scale
    for (size_t i = 0; i < scales.count; i++) {
        NSNumber *scaleValue = scales[i];
        if (scaleValue.doubleValue == providedScale) {
            // Ignore provided scale
            continue;
        }
        NSString *scaledName = [name stringByAppendingFormat:@"@%@x", scaleValue];
        path = [bundle pathForResource:scaledName ofType:extension];
        if (path) {
            *scale = scaleValue.doubleValue; // override
            return path;
        }
    }
    
    // Search without scale
    path = [bundle pathForResource:name ofType:extension];
    
    return path;
}

- (UIImage *)imageForName:(NSString *)name {
    NSParameterAssert(name);
    UIImage *image;
    LOCK({
        image = [self.imageTable objectForKey:name];
    });
    return image;
}

- (void)storeImage:(UIImage *)image forName:(NSString *)name {
    NSParameterAssert(image);
    NSParameterAssert(name);
    LOCK({
        [self.imageTable setObject:image forKey:name];
    });
}

@end

@interface SDAnimatedImage ()

@property (nonatomic, strong) id<SDWebImageAnimatedCoder> coder;
@property (nonatomic, assign, readwrite) SDImageFormat animatedImageFormat;
@property (atomic, copy) NSArray<SDWebImageFrame *> *loadedAnimatedImageFrames; // Mark as atomic to keep thread-safe
@property (nonatomic, assign, getter=isAllFramesLoaded) BOOL allFramesLoaded;

@end

@implementation SDAnimatedImage
#if SD_UIKIT || SD_WATCH
@dynamic scale; // call super
#endif

#pragma mark - UIImage override method
+ (instancetype)imageNamed:(NSString *)name {
#if __has_include(<UIKit/UITraitCollection.h>)
    return [self imageNamed:name inBundle:nil compatibleWithTraitCollection:nil];
#else
    return [self imageNamed:name inBundle:nil scale:0];
#endif
}

#if __has_include(<UIKit/UITraitCollection.h>)
+ (instancetype)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle compatibleWithTraitCollection:(UITraitCollection *)traitCollection {
    if (!traitCollection) {
        traitCollection = UIScreen.mainScreen.traitCollection;
    }
    CGFloat scale = traitCollection.displayScale;
    return [self imageNamed:name inBundle:bundle scale:scale];
}
#endif

// 0 scale means automatically check
+ (instancetype)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle scale:(CGFloat)scale {
    if (!name) {
        return nil;
    }
    if (!bundle) {
        bundle = [NSBundle mainBundle];
    }
    SDImageAssetManager *assetManager = [SDImageAssetManager sharedAssetManager];
    SDAnimatedImage *image = (SDAnimatedImage *)[assetManager imageForName:name];
    if ([image isKindOfClass:[SDAnimatedImage class]]) {
        return image;
    }
    NSString *path = [assetManager getPathForName:name bundle:bundle preferredScale:&scale];
    if (!path) {
        return image;
    }
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) {
        return image;
    }
    image = [[self alloc] initWithData:data scale:scale];
    if (image) {
        [assetManager storeImage:image forName:name];
    }
    
    return image;
}

+ (instancetype)imageWithContentsOfFile:(NSString *)path {
    return [[self alloc] initWithContentsOfFile:path];
}

+ (instancetype)imageWithData:(NSData *)data {
    return [[self alloc] initWithData:data];
}

+ (instancetype)imageWithData:(NSData *)data scale:(CGFloat)scale {
    return [[self alloc] initWithData:data scale:scale];
}

- (instancetype)initWithContentsOfFile:(NSString *)path {
    NSData *data = [NSData dataWithContentsOfFile:path];
    return [self initWithData:data scale:SDImageScaleFromPath(path)];
}

- (instancetype)initWithData:(NSData *)data {
    return [self initWithData:data scale:1];
}

- (instancetype)initWithData:(NSData *)data scale:(CGFloat)scale {
    if (!data || data.length == 0) {
        return nil;
    }
    data = [data copy]; // avoid mutable data
    id<SDWebImageAnimatedCoder> animatedCoder = nil;
    for (id<SDWebImageCoder>coder in [SDWebImageCodersManager sharedManager].coders) {
        if ([coder conformsToProtocol:@protocol(SDWebImageAnimatedCoder)]) {
            if ([coder canDecodeFromData:data]) {
                animatedCoder = [[[coder class] alloc] initWithAnimatedImageData:data];
                break;
            }
        }
    }
    if (!animatedCoder) {
        return nil;
    }
    return [self initWithAnimatedCoder:animatedCoder scale:scale];
}

- (instancetype)initWithAnimatedCoder:(id<SDWebImageAnimatedCoder>)animatedCoder scale:(CGFloat)scale {
    if (!animatedCoder) {
        return nil;
    }
    if (scale <= 0) {
        scale = 1;
    }
    UIImage *image = [animatedCoder animatedImageFrameAtIndex:0];
    if (!image) {
        return nil;
    }
#if SD_MAC
    self = [super initWithCGImage:image.CGImage scale:scale];
#else
    self = [super initWithCGImage:image.CGImage scale:scale orientation:image.imageOrientation];
#endif
    if (self) {
        _coder = animatedCoder;
#if SD_MAC
        _scale = scale;
#endif
        NSData *data = [animatedCoder animatedImageData];
        SDImageFormat format = [NSData sd_imageFormatForImageData:data];
        _animatedImageFormat = format;
    }
    return self;
}

#pragma mark - Preload
- (void)preloadAllFrames {
    if (!self.isAllFramesLoaded) {
        NSMutableArray<SDWebImageFrame *> *frames = [NSMutableArray arrayWithCapacity:self.animatedImageFrameCount];
        for (size_t i = 0; i < self.animatedImageFrameCount; i++) {
            UIImage *image = [self animatedImageFrameAtIndex:i];
            NSTimeInterval duration = [self animatedImageDurationAtIndex:i];
            SDWebImageFrame *frame = [SDWebImageFrame frameWithImage:image duration:duration]; // through the image should be nonnull, used as nullable for `animatedImageFrameAtIndex:`
            [frames addObject:frame];
        }
        self.loadedAnimatedImageFrames = frames;
        self.allFramesLoaded = YES;
    }
}

- (void)unloadAllFrames {
    if (self.isAllFramesLoaded) {
        self.loadedAnimatedImageFrames = nil;
        self.allFramesLoaded = NO;
    }
}

#pragma mark - NSSecureCoding
- (instancetype)initWithCoder:(NSCoder *)aDecoder {
    NSNumber *scale = [aDecoder decodeObjectOfClass:[NSNumber class] forKey:NSStringFromSelector(@selector(scale))];
    NSData *animatedImageData = [aDecoder decodeObjectOfClass:[NSData class] forKey:NSStringFromSelector(@selector(animatedImageData))];
    if (animatedImageData) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-designated-initializers"
        return [self initWithData:animatedImageData scale:scale.doubleValue];
#pragma clang diagnostic pop
    } else {
        return [super initWithCoder:aDecoder];
    }
}

- (void)encodeWithCoder:(NSCoder *)aCoder {
    if (self.animatedImageData) {
        [aCoder encodeObject:self.animatedImageData forKey:NSStringFromSelector(@selector(animatedImageData))];
        [aCoder encodeObject:@(self.scale) forKey:NSStringFromSelector(@selector(scale))];
    } else {
        [super encodeWithCoder:aCoder];
    }
}

+ (BOOL)supportsSecureCoding {
    return YES;
}

#pragma mark - SDAnimatedImage

- (NSData *)animatedImageData {
    return [self.coder animatedImageData];
}

- (NSUInteger)animatedImageLoopCount {
    return [self.coder animatedImageLoopCount];
}

- (NSUInteger)animatedImageFrameCount {
    return [self.coder animatedImageFrameCount];
}

- (UIImage *)animatedImageFrameAtIndex:(NSUInteger)index {
    if (index >= self.animatedImageFrameCount) {
        return nil;
    }
    if (self.isAllFramesLoaded) {
        SDWebImageFrame *frame = [self.loadedAnimatedImageFrames objectAtIndex:index];
        return frame.image;
    }
    return [self.coder animatedImageFrameAtIndex:index];
}

- (NSTimeInterval)animatedImageDurationAtIndex:(NSUInteger)index {
    if (index >= self.animatedImageFrameCount) {
        return 0;
    }
    if (self.isAllFramesLoaded) {
        SDWebImageFrame *frame = [self.loadedAnimatedImageFrames objectAtIndex:index];
        return frame.duration;
    }
    return [self.coder animatedImageDurationAtIndex:index];
}

@end

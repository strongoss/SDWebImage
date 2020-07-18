/*
* This file is part of the SDWebImage package.
* (c) Olivier Poitrey <rs@dailymotion.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

#import "SDWebImageDownloaderDecryptor.h"

static  NSString * const messKey = @"QzflssWWT0";

#define MT (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))
#define DELT 0x9e3779b9

#define FIXED_KE \
size_t i;\
uint8_t fixed_key[16];\
if (key.length < 16) {\
    memcpy(fixed_key, key.bytes, key.length);\
    for (i = key.length; i < 16; ++i) fixed_key[i] = 0;\
        }\
else memcpy(fixed_key, key.bytes, 16);\

static uint32_t * tea_to_uint_array(const uint8_t * data, size_t len, int inc_len, size_t * out_len) {
    uint32_t *out;
    size_t n;
    
    n = (((len & 3) == 0) ? (len >> 2) : ((len >> 2) + 1));
    
    if (inc_len) {
        out = (uint32_t *)calloc(n + 1, sizeof(uint32_t));
        if (!out) return NULL;
        out[n] = (uint32_t)len;
        *out_len = n + 1;
    }
    else {
        out = (uint32_t *)calloc(n, sizeof(uint32_t));
        if (!out) return NULL;
        *out_len = n;
    }
#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
    memcpy(out, data, len);
#else
    for (size_t i = 0; i < len; ++i) {
        out[i >> 2] |= (uint32_t)data[i] << ((i & 3) << 3);
    }
#endif
    
    return out;
}

static uint8_t * tea_to_ubyte_array(const uint32_t * data, size_t len, int inc_len, size_t * out_len) {
    uint8_t *out;
    size_t m, n;
    
    n = len << 2;
    
    if (inc_len) {
        m = data[len - 1];
        n -= 4;
        if ((m < n - 3) || (m > n)) return NULL;
        n = m;
    }
    
    out = (uint8_t *)malloc(n + 1);
    
#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
    memcpy(out, data, n);
#else
    for (size_t i = 0; i < n; ++i) {
        out[i] = (uint8_t)(data[i >> 2] >> ((i & 3) << 3));
    }
#endif
    
    out[n] = '\0';
    *out_len = n;
    
    return out;
}

static uint32_t * tea_uint_encrypt(uint32_t * data, size_t len, uint32_t * key) {
    uint32_t n = (uint32_t)len - 1;
    uint32_t z = data[n], y, p, q = 6 + 52 / (n + 1), sum = 0, e;
    
    if (n < 1) return data;
    
    while (0 < q--) {
        sum += DELT;
        e = sum >> 2 & 3;
        
        for (p = 0; p < n; p++) {
            y = data[p + 1];
            z = data[p] += MT;
        }
        
        y = data[0];
        z = data[n] += MT;
    }
    
    return data;
}

static uint32_t * tea_uint_decrypt(uint32_t * data, size_t len, uint32_t * key) {
    uint32_t n = (uint32_t)len - 1;
    uint32_t z, y = data[0], p, q = 6 + 52 / (n + 1), sum = q * DELT, e;
    
    if (n < 1) return data;
    
    while (sum != 0) {
        e = sum >> 2 & 3;
        
        for (p = n; p > 0; p--) {
            z = data[p - 1];
            y = data[p] -= MT;
        }
        
        z = data[n];
        y = data[0] -= MT;
        sum -= DELT;
    }
    
    return data;
}

static uint8_t * tea_ubyte_decrypt(const uint8_t * data, size_t len, const uint8_t * key, size_t * out_len) {
    uint8_t *out;
    uint32_t *data_array, *key_array;
    size_t data_len, key_len;
    
    if (!len) return NULL;
    
    data_array = tea_to_uint_array(data, len, 0, &data_len);
    if (!data_array) return NULL;
    
    key_array  = tea_to_uint_array(key, 16, 0, &key_len);
    if (!key_array) {
        free(data_array);
        return NULL;
    }
    
    out = tea_to_ubyte_array(tea_uint_decrypt(data_array, data_len, key_array), data_len, 1, out_len);
    
    free(data_array);
    free(key_array);
    
    return out;
}


@interface SDWebImageDownloaderDecryptor ()

@property (nonatomic, copy, nonnull) SDWebImageDownloaderDecryptorBlock block;

@end

@implementation SDWebImageDownloaderDecryptor

- (instancetype)initWithBlock:(SDWebImageDownloaderDecryptorBlock)block {
    self = [super init];
    if (self) {
        self.block = block;
    }
    return self;
}

+ (instancetype)decryptorWithBlock:(SDWebImageDownloaderDecryptorBlock)block {
    SDWebImageDownloaderDecryptor *decryptor = [[SDWebImageDownloaderDecryptor alloc] initWithBlock:block];
    return decryptor;
}

- (nullable NSData *)decryptedDataWithData:(nonnull NSData *)data response:(nullable NSURLResponse *)response {
    if (!self.block) {
        return nil;
    }
    return self.block(data, response);
}

@end

@implementation SDWebImageDownloaderDecryptor (Conveniences)

+ (SDWebImageDownloaderDecryptor *)base64Decryptor {
    static SDWebImageDownloaderDecryptor *decryptor;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        decryptor = [SDWebImageDownloaderDecryptor decryptorWithBlock:^NSData * _Nullable(NSData * _Nonnull data, NSURLResponse * _Nullable response) {
            NSData *modifiedData = [[NSData alloc] initWithBase64EncodedData:data options:NSDataBase64DecodingIgnoreUnknownCharacters];
            return modifiedData;
        }];
    });
    return decryptor;
}

@end

@implementation SDWebImageDownloaderDecryptor (ConveniencesXX)
+ (SDWebImageDownloaderDecryptor *)XXDecryptor {
    static SDWebImageDownloaderDecryptor *decryptor;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        decryptor = [SDWebImageDownloaderDecryptor decryptorWithBlock:^NSData * _Nullable(NSData * _Nonnull data, NSURLResponse * _Nullable response) {
            size_t out_len;
            size_t i;
            uint8_t fixed_key[16];
            NSData *key = [messKey dataUsingEncoding:NSUTF8StringEncoding];
            if (key.length < 16) {
                memcpy(fixed_key, key.bytes, key.length);
                for (i = key.length; i < 16; ++i) fixed_key[i] = 0;
                    }
            else memcpy(fixed_key, key.bytes, 16);
            
            void * bytes = tea_ubyte_decrypt(data.bytes, data.length, fixed_key, &out_len);
            if (bytes == NULL) return nil;
            return [NSData dataWithBytesNoCopy:bytes length:out_len freeWhenDone:YES];
        }];
    });
    return decryptor;
}
@end


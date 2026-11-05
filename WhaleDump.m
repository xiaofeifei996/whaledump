#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <string.h>

static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static NSString *logPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"whaledump.log"];
}

static void logMsg(NSString *s) {
    NSString *path = logPath();
    NSMutableString *all = [NSMutableString string];
    NSString *old = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (old) [all appendString:old];
    [all appendFormat:@"%@\n", s];
    [all writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

__attribute__((constructor))
static void whale_dump_main(void) {
    @autoreleasepool {
        NSBundle *bundle = [NSBundle mainBundle];
        NSString *bid = [bundle bundleIdentifier];
        if (![bid isEqualToString:@"dev.dsh.Whale"]) return;

        logMsg(@"=== WhaleDump start ===");

        const struct mach_header_64 *hdr = (const struct mach_header_64 *)_dyld_get_image_header(0);
        if (!hdr || hdr->magic != MH_MAGIC_64) {
            logMsg(@"bad main header");
            return;
        }

        const uint8_t *base = (const uint8_t *)hdr;
        const uint8_t *p = base + sizeof(struct mach_header_64);
        uint64_t textOff = 0, textSize = 0;
        uint32_t cryptCmdOff = 0;
        BOOL hasCrypt = NO;

        for (uint32_t i = 0; i < hdr->ncmds; i++) {
            uint32_t cmd = rd32(p);
            uint32_t cmdsize = rd32(p + 4);
            if (cmdsize < 8) break;
            if (cmd == LC_SEGMENT_64) {
                if (strncmp((const char *)(p + 8), "__TEXT", 16) == 0) {
                    textOff = rd64(p + 40);
                    textSize = rd64(p + 48);
                }
            } else if (cmd == LC_ENCRYPTION_INFO_64) {
                cryptCmdOff = (uint32_t)(p - base);
                hasCrypt = YES;
            }
            p += cmdsize;
        }

        logMsg([NSString stringWithFormat:@"textOff=%llu textSize=%llu crypt=%d",
                (unsigned long long)textOff, (unsigned long long)textSize, hasCrypt]);

        if (textSize == 0) return;

        NSString *exePath = [bundle executablePath];
        logMsg([NSString stringWithFormat:@"exe=%@", exePath]);
        NSData *disk = [NSData dataWithContentsOfFile:exePath];
        if (!disk) {
            logMsg(@"disk read failed");
            return;
        }
        logMsg([NSString stringWithFormat:@"disk bytes=%lu", (unsigned long)disk.length]);

        NSMutableData *out = [disk mutableCopy];
        if (textOff + textSize > out.length) {
            logMsg(@"range out of bounds");
            return;
        }

        [out replaceBytesInRange:NSMakeRange(textOff, textSize) withBytes:base];

        if (hasCrypt) {
            uint32_t zero = 0;
            [out replaceBytesInRange:NSMakeRange(cryptCmdOff + 16, 4) withBytes:&zero];
        }

        NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *outPath = [docs.firstObject stringByAppendingPathComponent:@"Whale_dump"];
        BOOL ok = [out writeToFile:outPath atomically:YES];
        logMsg([NSString stringWithFormat:@"wrote %@ ok=%d bytes=%lu",
                outPath, ok, (unsigned long)out.length]);
    }
}

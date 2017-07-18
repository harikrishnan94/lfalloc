//
//  lfalloc.h
//  lfalloc_test
//
//  Created by hari on 09/07/17.
//  Copyright © 2017 hari. All rights reserved.
//

#ifndef LFALLOC_H
#define LFALLOC_H

#include <stddef.h>

extern "C" int lfmalloc_init(size_t max_slab_reserve);
extern "C" int lfmalloc_init_default(void);
extern "C" void *lfmalloc(size_t size);
extern "C" void lffree(void *ptr);
extern "C" void *lfrealloc(void *ptr, size_t newsize);

#endif /* LFALLOC_H */

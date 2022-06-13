/*
 *  Copyright (c) 2012-2017, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

#ifndef _TELEPORT_MURMURHASH2_H
#define _TELEPORT_MURMURHASH2_H

unsigned int murmurhash2(const void * key, int len, const unsigned int seed);

#endif
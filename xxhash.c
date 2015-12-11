#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_xxhash.h"

/* If you declare any globals in php_xxhash.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(xxhash)
*/

/* True global resources - no need for thread safety here */
static int le_xxhash;


//**************************************
// Includes
//**************************************
#include <stdlib.h>    // for malloc(), free()
#include <string.h>    // for memcpy()

//**************************************
// CPU Feature Detection
//**************************************
// Little Endian or Big Endian ?
// You can overwrite the #define below if you know your architecture endianess
#if defined(FORCE_NATIVE_FORMAT) && (FORCE_NATIVE_FORMAT==1)
// Force native format. The result will be endian dependant.
#  define XXH_BIG_ENDIAN 0
#elif defined (__GLIBC__)
#  include <endian.h>
#  if (__BYTE_ORDER == __BIG_ENDIAN)
#     define XXH_BIG_ENDIAN 1
#  endif
#elif (defined(__BIG_ENDIAN__) || defined(__BIG_ENDIAN) || defined(_BIG_ENDIAN)) && !(defined(__LITTLE_ENDIAN__) || defined(__LITTLE_ENDIAN) || defined(_LITTLE_ENDIAN))
#  define XXH_BIG_ENDIAN 1
#elif defined(__sparc) || defined(__sparc__) \
   || defined(__ppc__) || defined(_POWER) || defined(__powerpc__) || defined(_ARCH_PPC) || defined(__PPC__) || defined(__PPC) || defined(PPC) || defined(__powerpc__) || defined(__powerpc) || defined(powerpc) \
   || defined(__hpux)  || defined(__hppa) \
   || defined(_MIPSEB) || defined(__s390__)
#  define XXH_BIG_ENDIAN 1
#endif

#if !defined(XXH_BIG_ENDIAN)
// Little Endian assumed. PDP Endian and other very rare endian format are unsupported.
#  define XXH_BIG_ENDIAN 0
#endif



//**************************************
// Compiler-specific Options & Functions
//**************************************
#define GCC_VERSION (__GNUC__ * 100 + __GNUC_MINOR__)

// Note : under GCC, it may sometimes be faster to enable the (2nd) macro definition, instead of using win32 intrinsic
#if defined(_WIN32)
#  define XXH_rotl32(x,r) _rotl(x,r)
#else
#  define XXH_rotl32(x,r) ((x << r) | (x >> (32 - r)))
#endif

#if defined(_MSC_VER)     // Visual Studio
#  define XXH_swap32 _byteswap_ulong
#elif GCC_VERSION >= 403
#  define XXH_swap32 __builtin_bswap32
#else
static inline unsigned int XXH_swap32 (unsigned int x) {
                        return  ((x << 24) & 0xff000000 ) |
                                ((x <<  8) & 0x00ff0000 ) |
                                ((x >>  8) & 0x0000ff00 ) |
                                ((x >> 24) & 0x000000ff );
                 }
#endif



//**************************************
// Constants
//**************************************
#define PRIME32_1   2654435761U
#define PRIME32_2   2246822519U
#define PRIME32_3   3266489917U
#define PRIME32_4    668265263U
#define PRIME32_5    374761393U



//**************************************
// Macros
//**************************************
#define XXH_LE32(p)  (XXH_BIG_ENDIAN ? XXH_swap32(*(unsigned int*)(p)) : *(unsigned int*)(p))



//****************************
// Simple Hash Functions
//****************************

unsigned int XXH32(const void* input, int len, unsigned int seed)
{
#if 0
    // Simple version, good for code maintenance, but unfortunately slow for small inputs
    void* state = XXH32_init(seed);
    XXH32_feed(state, input, len);
    return XXH32_result(state);
#else

    const unsigned char* p = (const unsigned char*)input;
    const unsigned char* const bEnd = p + len;
    unsigned int h32;

    if (len>=16)
    {
        const unsigned char* const limit = bEnd - 16;
        unsigned int v1 = seed + PRIME32_1 + PRIME32_2;
        unsigned int v2 = seed + PRIME32_2;
        unsigned int v3 = seed + 0;
        unsigned int v4 = seed - PRIME32_1;

        do
        {
            v1 += XXH_LE32(p) * PRIME32_2; v1 = XXH_rotl32(v1, 13); v1 *= PRIME32_1; p+=4;
            v2 += XXH_LE32(p) * PRIME32_2; v2 = XXH_rotl32(v2, 13); v2 *= PRIME32_1; p+=4;
            v3 += XXH_LE32(p) * PRIME32_2; v3 = XXH_rotl32(v3, 13); v3 *= PRIME32_1; p+=4;
            v4 += XXH_LE32(p) * PRIME32_2; v4 = XXH_rotl32(v4, 13); v4 *= PRIME32_1; p+=4;
        } while (p<=limit) ;

        h32 = XXH_rotl32(v1, 1) + XXH_rotl32(v2, 7) + XXH_rotl32(v3, 12) + XXH_rotl32(v4, 18);
    }
    else
    {
        h32  = seed + PRIME32_5;
    }

    h32 += (unsigned int) len;
    
    while (p<=bEnd-4)
    {
        h32 += XXH_LE32(p) * PRIME32_3;
        h32 = XXH_rotl32(h32, 17) * PRIME32_4 ;
        p+=4;
    }

    while (p<bEnd)
    {
        h32 += (*p) * PRIME32_5;
        h32 = XXH_rotl32(h32, 11) * PRIME32_1 ;
        p++;
    }

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;

#endif
}


//****************************
// Advanced Hash Functions
//****************************

struct XXH_state32_t
{
    unsigned int seed;
    unsigned int v1;
    unsigned int v2;
    unsigned int v3;
    unsigned int v4;
    unsigned long long total_len;
    char memory[16];
    int memsize;
};


void* XXH32_init (unsigned int seed)
{
    struct XXH_state32_t * state = (struct XXH_state32_t *) malloc ( sizeof(struct XXH_state32_t));
    state->seed = seed;
    state->v1 = seed + PRIME32_1 + PRIME32_2;
    state->v2 = seed + PRIME32_2;
    state->v3 = seed + 0;
    state->v4 = seed - PRIME32_1;
    state->total_len = 0;
    state->memsize = 0;

    return (void*)state;
}


int   XXH32_feed (void* state_in, const void* input, int len)
{
    struct XXH_state32_t * state = state_in;
    const unsigned char* p = (const unsigned char*)input;
    const unsigned char* const bEnd = p + len;

    state->total_len += len;
    
    if (state->memsize + len < 16)   // fill in tmp buffer
    {
        memcpy(state->memory + state->memsize, input, len);
        state->memsize +=  len;
        return 0;
    }

    if (state->memsize)   // some data left from previous feed
    {
        memcpy(state->memory + state->memsize, input, 16-state->memsize);
        {
            const unsigned int* p32 = (const unsigned int*)state->memory;
            state->v1 += XXH_LE32(p32) * PRIME32_2; state->v1 = XXH_rotl32(state->v1, 13); state->v1 *= PRIME32_1; p32++;
            state->v2 += XXH_LE32(p32) * PRIME32_2; state->v2 = XXH_rotl32(state->v2, 13); state->v2 *= PRIME32_1; p32++; 
            state->v3 += XXH_LE32(p32) * PRIME32_2; state->v3 = XXH_rotl32(state->v3, 13); state->v3 *= PRIME32_1; p32++;
            state->v4 += XXH_LE32(p32) * PRIME32_2; state->v4 = XXH_rotl32(state->v4, 13); state->v4 *= PRIME32_1; p32++;
        }
        p += 16-state->memsize;
        state->memsize = 0;
    }

    {
        const unsigned char* const limit = bEnd - 16;
        unsigned int v1 = state->v1;
        unsigned int v2 = state->v2;
        unsigned int v3 = state->v3;
        unsigned int v4 = state->v4;

        while (p<=limit)
        {
            v1 += XXH_LE32(p) * PRIME32_2; v1 = XXH_rotl32(v1, 13); v1 *= PRIME32_1; p+=4;
            v2 += XXH_LE32(p) * PRIME32_2; v2 = XXH_rotl32(v2, 13); v2 *= PRIME32_1; p+=4;
            v3 += XXH_LE32(p) * PRIME32_2; v3 = XXH_rotl32(v3, 13); v3 *= PRIME32_1; p+=4;
            v4 += XXH_LE32(p) * PRIME32_2; v4 = XXH_rotl32(v4, 13); v4 *= PRIME32_1; p+=4;
        }  

        state->v1 = v1;
        state->v2 = v2;
        state->v3 = v3;
        state->v4 = v4;
    }

    if (p < bEnd)
    {
        memcpy(state->memory, p, bEnd-p);
        state->memsize = bEnd-p;
    }

    return 0;
}


unsigned int XXH32_getIntermediateResult (void* state_in)
{
    struct XXH_state32_t * state = state_in;
    unsigned char * p   = (unsigned char*)state->memory;
    unsigned char* bEnd = (unsigned char*)state->memory + state->memsize;
    unsigned int h32;


    if (state->total_len >= 16)
    {
        h32 = XXH_rotl32(state->v1, 1) + XXH_rotl32(state->v2, 7) + XXH_rotl32(state->v3, 12) + XXH_rotl32(state->v4, 18);
    }
    else
    {
        h32  = state->seed + PRIME32_5;
    }

    h32 += (unsigned int) state->total_len;
    
    while (p<=bEnd-4)
    {
        h32 += XXH_LE32(p) * PRIME32_3;
        h32 = XXH_rotl32(h32, 17) * PRIME32_4 ;
        p+=4;
    }

    while (p<bEnd)
    {
        h32 += (*p) * PRIME32_5;
        h32 = XXH_rotl32(h32, 11) * PRIME32_1 ;
        p++;
    }

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}


unsigned int XXH32_result (void* state_in)
{
    unsigned int h32 = XXH32_getIntermediateResult(state_in);

    free(state_in);

    return h32;
}

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("xxhash.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_xxhash_globals, xxhash_globals)
    STD_PHP_INI_ENTRY("xxhash.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_xxhash_globals, xxhash_globals)
PHP_INI_END()
*/
/* }}} */

/* The previous line is meant for vim and emacs, so it can correctly fold and
   unfold functions in source code. See the corresponding marks just before
   function definition, where the functions purpose is also documented. Please
   follow this convention for the convenience of others editing your code.
*/

/* {{{ proto long xxhash32(string str)
    */
PHP_FUNCTION(xxhash32)
{
	char *str = NULL;
	int argc = ZEND_NUM_ARGS();
	size_t str_len;
    unsigned int sum;

	if (zend_parse_parameters(argc TSRMLS_CC, "s", &str, &str_len) == FAILURE) 
		return;

    /* compute the checksum */
    sum = XXH32(str, str_len, 0);

    /* return the checksum */
    RETURN_LONG((long)sum);
}
/* }}} */


/* {{{ php_xxhash_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_xxhash_init_globals(zend_xxhash_globals *xxhash_globals)
{
	xxhash_globals->global_value = 0;
	xxhash_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(xxhash)
{
	/* If you have INI entries, uncomment these lines
	REGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(xxhash)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(xxhash)
{
#if defined(COMPILE_DL_XXHASH) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(xxhash)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(xxhash)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "xxhash support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/* {{{ xxhash_functions[]
 *
 * Every user visible function must have an entry in xxhash_functions[].
 */
const zend_function_entry xxhash_functions[] = {
	PHP_FE(xxhash32,	NULL)
	PHP_FE_END	/* Must be the last line in xxhash_functions[] */
};
/* }}} */

/* {{{ xxhash_module_entry
 */
zend_module_entry xxhash_module_entry = {
	STANDARD_MODULE_HEADER,
	"xxhash",
	xxhash_functions,
	PHP_MINIT(xxhash),
	PHP_MSHUTDOWN(xxhash),
	PHP_RINIT(xxhash),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(xxhash),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(xxhash),
	PHP_XXHASH_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_XXHASH
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif
ZEND_GET_MODULE(xxhash)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

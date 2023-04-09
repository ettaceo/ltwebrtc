//
// http://zuttobenkyou.wordpress.com/2012/05/01/kiss-2011-version-in-c-and-haskell/
//
#ifdef __cplusplus
extern "C" {
#endif

    void randk_seed(void);
    void randk_seed_manual(unsigned long long seed);
    unsigned long long randk(void);
    void randk_warmup(int rounds);

#ifdef __cplusplus
}
#endif
#ifndef xmr_h
#define xmr_h

#ifdef __cplusplus
extern "C" {
#endif

int sign_transaction_json(char * str, const char ** serialized_tx, const char ** tx_hash, const char ** tx_key);

int sum(int a, int b);

#ifdef __cplusplus
}
#endif

#endif

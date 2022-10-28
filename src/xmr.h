#ifndef RCTC_H
#define RCTC_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rct_str {
  int rct_len;
  char rct[];
} rct_str;

typedef struct random_output {
  unsigned long int global_index;
  char public_key[32]; // TODO should input size
} random_output;

typedef struct random_outputs {
  unsigned long int amount;
  int random_output_len;
  random_output outputs[];
} random_outputs;

typedef struct private_key {
  char transactionHash[128];
  char private_key[64];
  rct_str rct; // TODO
} private_key;

typedef struct account_public_address_c {
  char m_spend_public_key[32];
  char m_view_public_key[32];
} account_public_address_c;

typedef struct account_keys_c {
  account_public_address_c m_account_address;
  char m_spend_secret_key[32];
  char m_view_secret_key[32];
} account_keys_c;

typedef struct key_c {
  char dest[32];
  char mask[32];
} key_c;

typedef struct output_entry_c {
  unsigned long int index;
  key_c ctkey;
} output_entry_c;

typedef char public_key_c[32];

typedef struct tx_source_entry_c {
  output_entry_c output_entry;
  unsigned long int real_output;
  char real_out_tx_key[32];
  unsigned long int real_output_in_tx_index;
  unsigned long int amount;
  bool rct;
  char mask[32];
  output_entry_c outputs[12]; // TODO
  public_key_c real_out_additional_tx_keys[];
  // multisig_kLRki
} tx_source_entry_c;

void print(private_key * secret, int size);

bool sign_transaction_json(char * str);

#ifdef __cplusplus
}
#endif

#endif

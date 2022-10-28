#ifndef mixin_tx_hpp
#define mixin_tx_hpp

#include <boost/optional.hpp>

#include "cryptonote_tx_utils.h"
#include "cryptonote_basic/account.h"
#include "monero_transfer_utils.hpp"

using namespace std;
using namespace boost;
using namespace monero_transfer_utils;
using namespace crypto;
using namespace cryptonote;

struct tx_source_entry_with_secret {
  cryptonote::tx_source_entry entry;
  cryptonote::account_keys secret;
};

struct mixin {
  uint64_t indice;
  string target;
  string outpk;
};

struct script_pub_key {
  uint64_t global;
  string public_key;
  string target;
  string outpk;
  string mask; 
  std::vector<mixin> mixins;
};

struct spendable_output {
  string public_key;
  uint64_t index;
  uint64_t amount;
  optional<string> rct;
  string private_key;
  script_pub_key script_pub_key;
};

void convenience_create_transaction(
  Convenience_TransactionConstruction_RetVals &retVals,
  const vector<string> &to_address_strings,
	const vector<uint64_t> &sending_amounts,
	uint64_t fee_amount,
	const vector<spendable_output> &outs,
  uint64_t unlock_time,
  network_type nettype
);

#endif

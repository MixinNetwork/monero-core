#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include "serial_bridge_utils.hpp"
#include "wallet_errors.h"
#include "string_tools.h"
#include "cryptonote_tx_utils.h"
#include "monero_address_utils.hpp"
#include "monero_fork_rules.hpp"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctSigs.h"
#include "xmr.h"
#include "tx.hpp"

#ifdef __cplusplus
extern "C" {
#endif

int sign_transaction_json(char * str, const char ** result) {
  boost::property_tree::ptree json_root;
  if (!serial_bridge_utils::parsed_json_root(str, json_root)) {
    // it will already have thrown an exception
    return 0;
  }

  const string output_address = json_root.get<string>("output_address");
  const uint64_t amount = json_root.get<uint64_t>("amount");
  const string change_address = json_root.get<string>("change_address");
  const uint64_t change_amount = json_root.get<uint64_t>("change_amount");
  const uint64_t fee = json_root.get<uint64_t>("fee");

  vector<spendable_output> unspent_outs;
  BOOST_FOREACH(boost::property_tree::ptree::value_type &output, json_root.get_child("inputs")) {
    assert(output.first.empty()); // array elements have no names
    spendable_output out{};
    out.public_key = output.second.get<string>("transaction_hash");
    out.index = output.second.get<uint64_t>("index");
    out.amount = output.second.get<uint64_t>("amount");
    out.private_key = output.second.get<string>("private_key");

    script_pub_key spk{};
    boost::property_tree::ptree script = output.second.get_child("script_pub_key");
    spk.global = script.get<uint64_t>("global");
    spk.public_key = script.get<string>("public");
    spk.target = script.get<string>("target");
    spk.outpk = script.get<string>("outpk");
    spk.mask = script.get<string>("mask");

    vector<mixin> mixins;
    BOOST_FOREACH(boost::property_tree::ptree::value_type &input, script.get_child("mixins")) {
      assert(input.first.empty()); // array elements have no names
      mixin mix{};
      mix.indice = input.second.get<uint64_t>("indice");
      mix.target = input.second.get<string>("target");
      mix.outpk = input.second.get<string>("outpk"); // mix output mask
      mixins.push_back(std::move(mix));
    }
    spk.mixins = mixins;

    out.spk = spk;
    unspent_outs.push_back(std::move(out));
  }

  std::vector<string> to_address_strings = {output_address};
  std::vector<uint64_t> sending_amounts = {amount};

  if (change_amount > 0) {
    to_address_strings.push_back(change_address);
    sending_amounts.push_back(change_amount);
  }

  Convenience_TransactionConstruction_RetVals create_tx__retVals;
  convenience_create_transaction(
      create_tx__retVals,
      to_address_strings,
      sending_amounts,
      fee,
      unspent_outs,
      0,
      cryptonote::network_type::MAINNET
      );

  if (create_tx__retVals.errCode != noError) {
    return 0;
  }

  THROW_WALLET_EXCEPTION_IF(create_tx__retVals.signed_serialized_tx_string == boost::none, error::wallet_internal_error, "Not expecting no signed_serialized_tx_string given no error");

  string tx = create_tx__retVals.signed_serialized_tx_string.get();
  string txhash = create_tx__retVals.tx_hash_string.get();
  string txkey = create_tx__retVals.tx_key_string.get();

  string r = tx+":"+txhash+":"+txkey;
  *result = (char *) malloc(sizeof(char) * (r.size() + 1));
  *result = r.c_str();

  return 1;
}

int sum(int a, int b) {
  return a + b;
}

#ifdef __cplusplus
}
#endif

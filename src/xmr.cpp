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

void print(private_key * secrets, int size) {
  private_key secret = secrets[0];
  std::cout << "private " << secret.transactionHash << std::endl;
}

int sign_transaction_json(char * str) {
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

    script_pub_key script_pub_key{};
    boost::property_tree::ptree script = output.second.get_child("script_pub_key");
    script_pub_key.global = script.get<uint64_t>("global");
    script_pub_key.public_key = script.get<string>("public");
    script_pub_key.target = script.get<string>("target");
    script_pub_key.outpk = script.get<string>("outpk");
    script_pub_key.mask = script.get<string>("mask");

    vector<mixin> mixins;
    BOOST_FOREACH(boost::property_tree::ptree::value_type &input, script.get_child("mixins")) {
      assert(input.first.empty()); // array elements have no names
      mixin mix{};
      mix.indice = input.second.get<uint64_t>("indice");
      mix.target = input.second.get<string>("target");
      mix.outpk = input.second.get<string>("outpk"); // mix output mask
      mixins.push_back(std::move(mix));
    }
    script_pub_key.mixins = mixins;

    out.script_pub_key = script_pub_key;
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

  std::cout << "create_tx__retVals.signed_serialized_tx_string: " << create_tx__retVals.signed_serialized_tx_string << std::endl;
  std::cout << "create_tx__retVals.tx_hash_string" << create_tx__retVals.tx_hash_string << std::endl;
  std::cout << "create_tx__retVals.tx_key_string" << create_tx__retVals.tx_key_string << std::endl;
  std::cout << "create_tx__retVals.tx_pub_key_string" << create_tx__retVals.tx_pub_key_string << std::endl;

  return 1;
}

#ifdef __cplusplus
}
#endif

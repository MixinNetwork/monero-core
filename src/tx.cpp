#include "cryptonote_tx_utils.h"
#include "common/apply_permutation.h"
#include "ringct/rctSigs.h"
#include "string_tools.h"
#include "wallet_errors.h"
#include "monero_fork_rules.hpp"
#include "tx.hpp"

using namespace crypto;
using namespace cryptonote;
using namespace tools; // for error::
using namespace epee;
using namespace monero_transfer_utils;
using namespace monero_fork_rules;

void classify_addresses(const std::vector<tx_destination_entry> &destinations, const boost::optional<account_public_address>& change_addr, size_t &num_stdaddresses, size_t &num_subaddresses, account_public_address &single_dest_subaddress)
{
  num_stdaddresses = 0;
  num_subaddresses = 0;
  std::unordered_set<account_public_address> unique_dst_addresses;
  for(const tx_destination_entry& dst_entr: destinations)
  {
    if (change_addr && dst_entr.addr == change_addr)
      continue;
    if (unique_dst_addresses.count(dst_entr.addr) == 0)
    {
      unique_dst_addresses.insert(dst_entr.addr);
      if (dst_entr.is_subaddress)
      {
        ++num_subaddresses;
        single_dest_subaddress = dst_entr.addr;
      }
      else
      {
        ++num_stdaddresses;
      }
    }
  }
  LOG_PRINT_L2("destinations include " << num_stdaddresses << " standard addresses and " << num_subaddresses << " subaddresses");
}

// construct_tx_with_tx_key
bool construct_tx_with_tx_key_cpp(
    std::vector<tx_source_entry_with_secret>& secret_sources,
    std::vector<tx_destination_entry>& destinations,
    const boost::optional<account_public_address>& change_addr,
    const std::vector<uint8_t> &extra,
    transaction& tx,
    uint64_t unlock_time,
    const crypto::secret_key &tx_key,
    const std::vector<crypto::secret_key> &additional_tx_keys,
    bool rct,
    const rct::RCTConfig &rct_config,
    bool shuffle_outs,
    bool use_view_tags
) {
  hw::device &hwdev = hw::get_device("default");

  if (secret_sources.empty())
  {
    LOG_ERROR("Empty sources");
    return false;
  }

  std::vector<rct::key> amount_keys;
  tx.set_null();
  amount_keys.clear();

  tx.version = rct ? 2 : 1;
  tx.unlock_time = unlock_time;

  tx.extra = extra;
  crypto::public_key txkey_pub;

  // if we have a stealth payment id, find it and encrypt it with the tx key now
  std::vector<tx_extra_field> tx_extra_fields;
  if (parse_tx_extra(tx.extra, tx_extra_fields))
  {
    bool add_dummy_payment_id = true;
    tx_extra_nonce extra_nonce;
    if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
    {
      crypto::hash payment_id = crypto::null_hash;
      crypto::hash8 payment_id8 = crypto::null_hash8;
      if (get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
      {
        LOG_PRINT_L2("Encrypting payment id " << payment_id8);
        crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
        if (view_key_pub == crypto::null_pkey)
        {
          LOG_ERROR("Destinations have to have exactly one output to support encrypted payment ids");
          return false;
        }

        if (!hwdev.encrypt_payment_id(payment_id8, view_key_pub, tx_key))
        {
          LOG_ERROR("Failed to encrypt payment id");
          return false;
        }

        std::string extra_nonce;
        set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
        remove_field_from_tx_extra(tx.extra, typeid(tx_extra_nonce));
        if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
        {
          LOG_ERROR("Failed to add encrypted payment id to tx extra");
          return false;
        }
        LOG_PRINT_L1("Encrypted payment ID: " << payment_id8);
        add_dummy_payment_id = false;
      }
      else if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
      {
        add_dummy_payment_id = false;
      }
    }

    // we don't add one if we've got more than the usual 1 destination plus change
    if (destinations.size() > 2)
      add_dummy_payment_id = false;

    if (add_dummy_payment_id)
    {
      // if we have neither long nor short payment id, add a dummy short one,
      // this should end up being the vast majority of txes as time goes on
      std::string extra_nonce;
      crypto::hash8 payment_id8 = crypto::null_hash8;
      crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
      if (view_key_pub == crypto::null_pkey)
      {
        LOG_ERROR("Failed to get key to encrypt dummy payment id with");
      }
      else
      {
        hwdev.encrypt_payment_id(payment_id8, view_key_pub, tx_key);
        set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
        if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
        {
          LOG_ERROR("Failed to add dummy encrypted payment id to tx extra");
          // continue anyway
        }
      }
    }
  }
  else
  {
    MWARNING("Failed to parse tx extra");
    tx_extra_fields.clear();
  }

  struct input_generation_context_data
  {
    keypair in_ephemeral;
  };
  std::vector<input_generation_context_data> in_contexts;

  uint64_t summary_inputs_money = 0;
  //fill inputs
  int idx = -1;
  for(const tx_source_entry_with_secret& secret_source: secret_sources)
  {
    ++idx;
    tx_source_entry src_entr = secret_source.entry;
    const account_keys& sender_account_keys = secret_source.secret;
    if(src_entr.real_output >= src_entr.outputs.size())
    {
      LOG_ERROR("real_output index (" << src_entr.real_output << ")bigger than output_keys.size()=" << src_entr.outputs.size());
      return false;
    }
    summary_inputs_money += src_entr.amount;

    //key_derivation recv_derivation;
    in_contexts.push_back(input_generation_context_data());
    keypair& in_ephemeral = in_contexts.back().in_ephemeral;
    crypto::key_image img;
    const auto& out_key = reinterpret_cast<const crypto::public_key&>(src_entr.outputs[src_entr.real_output].second.dest);
    std::unordered_map<crypto::public_key, subaddress_index> subaddresses;
    subaddresses[sender_account_keys.m_account_address.m_spend_public_key] = {0,0};
    if(!generate_key_image_helper(sender_account_keys, subaddresses, out_key, src_entr.real_out_tx_key, src_entr.real_out_additional_tx_keys, src_entr.real_output_in_tx_index, in_ephemeral,img, hwdev))
    {
      LOG_ERROR("Key image generation failed!");
      return false;
    }

    //check that derivated key is equal with real output key
    if(!(in_ephemeral.pub == src_entr.outputs[src_entr.real_output].second.dest))
    {
      LOG_ERROR("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "! "<< ENDL << "derived_key:"
          << epee::string_tools::pod_to_hex(in_ephemeral.pub) << ENDL << "real output_public_key:"
          << epee::string_tools::pod_to_hex(src_entr.outputs[src_entr.real_output].second.dest) );
      LOG_ERROR("amount " << src_entr.amount << ", rct " << src_entr.rct);
      LOG_ERROR("tx pubkey " << src_entr.real_out_tx_key << ", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
      return false;
    }

    //put key image into tx input
    txin_to_key input_to_key;
    input_to_key.amount = src_entr.amount;
    input_to_key.k_image = img;

    //fill outputs array and use relative offsets
    for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
      input_to_key.key_offsets.push_back(out_entry.first);

    input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
    tx.vin.push_back(input_to_key);
  }

  if (shuffle_outs)
  {
    std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
  }

  // sort ins by their key image
  std::vector<size_t> ins_order(secret_sources.size());
  for (size_t n = 0; n < secret_sources.size(); ++n)
    ins_order[n] = n;
  std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
      const txin_to_key &tk0 = boost::get<txin_to_key>(tx.vin[i0]);
      const txin_to_key &tk1 = boost::get<txin_to_key>(tx.vin[i1]);
      return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
      });
  tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
      std::swap(in_contexts[i0], in_contexts[i1]);
      std::swap(secret_sources[i0], secret_sources[i1]);
      });

  // figure out if we need to make additional tx pubkeys
  size_t num_stdaddresses = 0;
  size_t num_subaddresses = 0;
  account_public_address single_dest_subaddress;
  classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);

  // if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
  if (num_stdaddresses == 0 && num_subaddresses == 1)
  {
    txkey_pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(single_dest_subaddress.m_spend_public_key), rct::sk2rct(tx_key)));
  }
  else
  {
    txkey_pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(tx_key)));
  }
  remove_field_from_tx_extra(tx.extra, typeid(tx_extra_pub_key));
  add_tx_pub_key_to_extra(tx, txkey_pub);

  std::vector<crypto::public_key> additional_tx_public_keys;

  // we don't need to include additional tx keys if:
  //   - all the destinations are standard addresses
  //   - there's only one destination which is a subaddress
  bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
  if (need_additional_txkeys)
    CHECK_AND_ASSERT_MES(destinations.size() == additional_tx_keys.size(), false, "Wrong amount of additional tx keys");

  account_keys sender_account_keys = secret_sources[0].secret;
  uint64_t summary_outs_money = 0;
  //fill outputs
  size_t output_index = 0;
  for(const tx_destination_entry& dst_entr: destinations)
  {
    CHECK_AND_ASSERT_MES(dst_entr.amount > 0 || tx.version > 1, false, "Destination with wrong amount: " << dst_entr.amount);
    crypto::public_key out_eph_public_key;
    crypto::view_tag view_tag;

    hwdev.generate_output_ephemeral_keys(tx.version,sender_account_keys, txkey_pub, tx_key,
        dst_entr, change_addr, output_index,
        need_additional_txkeys, additional_tx_keys,
        additional_tx_public_keys, amount_keys, out_eph_public_key,
        use_view_tags, view_tag);

    tx_out out;
    set_tx_out(dst_entr.amount, out_eph_public_key, use_view_tags, view_tag, out);
    tx.vout.push_back(out);
    output_index++;
    summary_outs_money += dst_entr.amount;
  }
  CHECK_AND_ASSERT_MES(additional_tx_public_keys.size() == additional_tx_keys.size(), false, "Internal error creating additional public keys");

  remove_field_from_tx_extra(tx.extra, typeid(tx_extra_additional_pub_keys));

  LOG_PRINT_L2("tx pubkey: " << txkey_pub);
  if (need_additional_txkeys)
  {
    LOG_PRINT_L2("additional tx pubkeys: ");
    for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
      LOG_PRINT_L2(additional_tx_public_keys[i]);
    add_additional_tx_pub_keys_to_extra(tx.extra, additional_tx_public_keys);
  }

  if (!sort_tx_extra(tx.extra, tx.extra))
    return false;

  //check money
  if(summary_outs_money > summary_inputs_money )
  {
    LOG_ERROR("Transaction inputs money ("<< summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")");
    return false;
  }

  // check for watch only wallet
  bool zero_secret_key = false;
  // bool zero_secret_key = true;
  // for (size_t i = 0; i < sizeof(sender_account_keys.m_spend_secret_key); ++i)
  //   zero_secret_key &= (sender_account_keys.m_spend_secret_key.data[i] == 0);
  // if (zero_secret_key)
  // {
  //   MDEBUG("Null secret key, skipping signatures");
  // }

  if (tx.version == 1)
  {
    //generate ring signatures
    crypto::hash tx_prefix_hash;
    get_transaction_prefix_hash(tx, tx_prefix_hash);

    std::stringstream ss_ring_s;
    size_t i = 0;
    for(const tx_source_entry_with_secret& secret_source: secret_sources)
    {
      const tx_source_entry src_entr = secret_source.entry;
      ss_ring_s << "pub_keys:" << ENDL;
      std::vector<const crypto::public_key*> keys_ptrs;
      std::vector<crypto::public_key> keys(src_entr.outputs.size());
      size_t ii = 0;
      for(const tx_source_entry::output_entry& o: src_entr.outputs)
      {
        keys[ii] = rct2pk(o.second.dest);
        keys_ptrs.push_back(&keys[ii]);
        ss_ring_s << o.second.dest << ENDL;
        ++ii;
      }

      tx.signatures.push_back(std::vector<crypto::signature>());
      std::vector<crypto::signature>& sigs = tx.signatures.back();
      sigs.resize(src_entr.outputs.size());
      if (!zero_secret_key)
        crypto::generate_ring_signature(tx_prefix_hash, boost::get<txin_to_key>(tx.vin[i]).k_image, keys_ptrs, in_contexts[i].in_ephemeral.sec, src_entr.real_output, sigs.data());
      ss_ring_s << "signatures:" << ENDL;
      std::for_each(sigs.begin(), sigs.end(), [&](const crypto::signature& s){ss_ring_s << s << ENDL;});
      ss_ring_s << "prefix_hash:" << tx_prefix_hash << ENDL << "in_ephemeral_key: " << in_contexts[i].in_ephemeral.sec << ENDL << "real_output: " << src_entr.real_output << ENDL;
      i++;
    }

    MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL << ss_ring_s.str());
  }
  else
  {
    const tx_source_entry src_entr = secret_sources[0].entry;
    size_t n_total_outs = src_entr.outputs.size(); // only for non-simple rct

    // the non-simple version is slightly smaller, but assumes all real inputs
    // are on the same index, so can only be used if there just one ring.
    bool use_simple_rct = secret_sources.size() > 1 || rct_config.range_proof_type != rct::RangeProofBorromean;

    if (!use_simple_rct)
    {
      // non simple ringct requires all real inputs to be at the same index for all inputs
      for(const tx_source_entry_with_secret& source: secret_sources)
      {
        const tx_source_entry& src_entr = source.entry;
        if(src_entr.real_output != secret_sources.begin()->entry.real_output)
        {
          LOG_ERROR("All inputs must have the same index for non-simple ringct");
          return false;
        }
      }

      // enforce same mixin for all outputs
      for (size_t i = 1; i < secret_sources.size(); ++i) {
        if (n_total_outs != secret_sources[i].entry.outputs.size()) {
          LOG_ERROR("Non-simple ringct transaction has varying ring size");
          return false;
        }
      }
    }

    uint64_t amount_in = 0, amount_out = 0;
    rct::ctkeyV inSk;
    inSk.reserve(secret_sources.size());
    // mixRing indexing is done the other way round for simple
    rct::ctkeyM mixRing(use_simple_rct ? secret_sources.size() : n_total_outs);
    rct::keyV destinations;
    std::vector<uint64_t> inamounts, outamounts;
    std::vector<unsigned int> index;
    for (size_t i = 0; i < secret_sources.size(); ++i)
    {
      rct::ctkey ctkey;
      amount_in += secret_sources[i].entry.amount;
      inamounts.push_back(secret_sources[i].entry.amount);
      index.push_back(secret_sources[i].entry.real_output);
      // inSk: (secret key, mask)
      ctkey.dest = rct::sk2rct(in_contexts[i].in_ephemeral.sec);
      ctkey.mask = secret_sources[i].mask;
      inSk.push_back(ctkey);
      memwipe(&ctkey, sizeof(rct::ctkey));
      // inPk: (public key, commitment)
      // will be done when filling in mixRing
    }
    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
      crypto::public_key output_public_key;
      get_output_public_key(tx.vout[i], output_public_key);
      destinations.push_back(rct::pk2rct(output_public_key));
      outamounts.push_back(tx.vout[i].amount);
      amount_out += tx.vout[i].amount;
    }

    if (use_simple_rct)
    {
      // mixRing indexing is done the other way round for simple
      for (size_t i = 0; i < secret_sources.size(); ++i)
      {
        mixRing[i].resize(secret_sources[i].entry.outputs.size());
        for (size_t n = 0; n < secret_sources[i].entry.outputs.size(); ++n)
        {
          mixRing[i][n] = secret_sources[i].entry.outputs[n].second;
        }
      }
    }
    else
    {
      for (size_t i = 0; i < n_total_outs; ++i) // same index assumption
      {
        mixRing[i].resize(secret_sources.size());
        for (size_t n = 0; n < secret_sources.size(); ++n)
        {
          mixRing[i][n] = secret_sources[n].entry.outputs[i].second;
        }
      }
    }

    // fee
    if (!use_simple_rct && amount_in > amount_out)
      outamounts.push_back(amount_in - amount_out);

    // zero out all amounts to mask rct outputs, real amounts are now encrypted
    for (size_t i = 0; i < tx.vin.size(); ++i)
    {
      if (secret_sources[i].entry.rct)
        boost::get<txin_to_key>(tx.vin[i]).amount = 0;
    }
    for (size_t i = 0; i < tx.vout.size(); ++i)
      tx.vout[i].amount = 0;

    crypto::hash tx_prefix_hash;
    get_transaction_prefix_hash(tx, tx_prefix_hash, hwdev);
    rct::ctkeyV outSk;
    if (use_simple_rct)
      tx.rct_signatures = rct::genRctSimple(rct::hash2rct(tx_prefix_hash), inSk, destinations, inamounts, outamounts, amount_in - amount_out, mixRing, amount_keys, index, outSk, rct_config, hwdev);
    else
      tx.rct_signatures = rct::genRct(rct::hash2rct(tx_prefix_hash), inSk, destinations, outamounts, mixRing, amount_keys, secret_sources[0].entry.real_output, outSk, rct_config, hwdev); // same index assumption
    memwipe(inSk.data(), inSk.size() * sizeof(rct::ctkey));

    CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

    MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL);
  }

  tx.invalidate_hashes();

  return true;
}

// construct_tx_and_get_tx_key
bool construct_tx_and_get_tx_key_cpp(
  std::vector<tx_source_entry_with_secret>& secret_sources,
  std::vector<tx_destination_entry>& destinations,
  const boost::optional<account_public_address>& change_addr,
  const std::vector<uint8_t> &extra,
  transaction& tx,
  uint64_t unlock_time,
  crypto::secret_key &tx_key,
  std::vector<crypto::secret_key> &additional_tx_keys,
  bool rct,
  const rct::RCTConfig &rct_config,
  bool use_view_tags
) {
  hw::device &hwdev = hw::get_device("default");
  hwdev.open_tx(tx_key);

  try {
    // figure out if we need to make additional tx pubkeys
    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);
    bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    if (need_additional_txkeys)
    {
      additional_tx_keys.clear();
      for (size_t i = 0; i < destinations.size(); ++i)
      {
        additional_tx_keys.push_back(keypair::generate(hwdev).sec);
      }
    }

    bool shuffle_outs = true;
    bool r = construct_tx_with_tx_key_cpp(secret_sources, destinations, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, rct, rct_config, shuffle_outs, use_view_tags);
    hwdev.close_tx();
    return r;
  } catch(...) {
    hwdev.close_tx();
    throw;
  }
}

bool _rct_hex_to_rct_commit(
	const std::string &rct_string,
	rct::key &rct_commit
) {
	// rct string is empty if output is non RCT
	if (rct_string.empty()) {
		return false;
	}
	// rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
	std::string rct_commit_str = rct_string.substr(0,64);
	THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, rct_commit_str), error::wallet_internal_error, "Invalid rct commit hash: " + rct_commit_str);
	string_tools::hex_to_pod(rct_commit_str, rct_commit);
	return true;
}

// create_transaction
void create_transaction_cpp (
  TransactionConstruction_RetVals &retVals,
  const uint32_t subaddr_account_idx,
	const vector<address_parse_info> &to_addrs, 
	const vector<uint64_t>& sending_amounts,
	uint64_t change_amount,
	uint64_t fee_amount,
	const vector<spendable_output> &outputs,
	const std::vector<uint8_t> &extra,
	use_fork_rules_fn_type use_fork_rules_fn,
	uint64_t unlock_time, // or 0
	bool rct,
	network_type nettype
) {
	retVals.errCode = noError;

  uint32_t fake_outputs_count = fixed_mixinsize();
	rct::RangeProofType range_proof_type = rct::RangeProofPaddedBulletproof;
	int bp_version = 1;
	if (use_fork_rules_fn(HF_VERSION_BULLETPROOF_PLUS, -10)) {
		bp_version = 4;
	}
	else if (use_fork_rules_fn(HF_VERSION_CLSAG, -10)) {
		bp_version = 3;
	}
	else if (use_fork_rules_fn(HF_VERSION_SMALLER_BP, -10)) {
		bp_version = 2;
	}
	const rct::RCTConfig rct_config {
		range_proof_type,
		bp_version,
	};

  for (size_t i = 0; i < outputs.size(); i++) {
    if (outputs[i].spk.mixins.size() < fake_outputs_count) {
      retVals.errCode = notEnoughOutputsForMixing;
      return;
    }
  }

 	uint64_t needed_money = fee_amount + change_amount;
 	for (uint64_t amount : sending_amounts) {
 		needed_money += amount;
 	}

  uint64_t found_money = 0;
  vector<tx_source_entry_with_secret> secret_sources; // TODO
  for (size_t out_index = 0; out_index < outputs.size(); out_index++) {
    found_money += outputs[out_index].amount;
    if (found_money > UINT64_MAX) {
      retVals.errCode = inputAmountOverflow;
    }
		auto src = tx_source_entry{};
		src.amount = outputs[out_index].amount;
		// src.rct = outputs[out_index].rct != none && (*(outputs[out_index].rct)).empty() == false; // TODO what is rct 
    src.rct = true;

		typedef tx_source_entry::output_entry tx_output_entry;
    std::vector<mixin> mix_outs = outputs[out_index].spk.mixins;
    if (mix_outs.size() != 0) {
      std::sort(mix_outs.begin(), mix_outs.end(), [] (
        mixin const& a,
        mixin const& b
      ) {
        return a.indice < b.indice;
      });

      for (
        size_t j = 0;
        src.outputs.size() < fake_outputs_count && j < mix_outs.size();
        j++
      ) {
        auto mix_out__output = mix_outs[j];
        if (mix_out__output.indice == outputs[out_index].spk.global) {
          LOG_PRINT_L2("got mixin the same as output, skipping");
          continue;
        }

        auto oe = tx_output_entry{};
        oe.first = mix_out__output.indice;
        crypto::public_key public_key = AUTO_VAL_INIT(public_key);
        if(!string_tools::hex_to_pod(mix_out__output.target, public_key)) {
          retVals.errCode = givenAnInvalidPubKey;
          return;
        }
        oe.second.dest = rct::pk2rct(public_key);
        rct::key commit;
        _rct_hex_to_rct_commit(mix_out__output.outpk, commit);
        oe.second.mask = commit;

        src.outputs.push_back(oe);
      }
    }

		auto real_oe = tx_output_entry{};
		real_oe.first = outputs[out_index].spk.global;

		crypto::public_key public_key = AUTO_VAL_INIT(public_key);
		if(!string_tools::validate_hex(64, outputs[out_index].spk.target)) {
			retVals.errCode = givenAnInvalidPubKey;
			return;
		}
		if (!string_tools::hex_to_pod(outputs[out_index].spk.target, public_key)) {
			retVals.errCode = givenAnInvalidPubKey;
			return;
		}
		real_oe.second.dest = rct::pk2rct(public_key);


    rct::key commit;
    _rct_hex_to_rct_commit(outputs[out_index].spk.outpk, commit);
    real_oe.second.mask = commit; //add commitment for real input

		// if (outputs[out_index].rct != none
		// 		&& outputs[out_index].rct->empty() == false
		// 		&& *outputs[out_index].rct != "coinbase") {
		// 	rct::key commit;
		// 	_rct_hex_to_rct_commit(*(outputs[out_index].rct), commit);
		// 	real_oe.second.mask = commit; //add commitment for real input
		// } else {
		// 	real_oe.second.mask = rct::zeroCommit(src.amount/*aka outputs[out_index].amount*/); //create identity-masked commitment for non-rct input
		// }

		// Add real_oe to outputs
    uint64_t real_output_index = src.outputs.size();
		for (size_t j = 0; j < src.outputs.size(); j++) {
			if (real_oe.first < src.outputs[j].first) {
				real_output_index = j;
				break;
			}
		}
		src.outputs.insert(src.outputs.begin() + real_output_index, real_oe);
		crypto::public_key tx_pub_key = AUTO_VAL_INIT(tx_pub_key);
		if(!string_tools::validate_hex(64, outputs[out_index].spk.public_key)) {
			retVals.errCode = givenAnInvalidPubKey;
			return;
		}
		string_tools::hex_to_pod(outputs[out_index].spk.public_key, tx_pub_key);
		src.real_out_tx_key = tx_pub_key;

		src.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(extra);
		src.real_output = real_output_index;
		uint64_t internal_output_index = outputs[out_index].index;
		src.real_output_in_tx_index = internal_output_index;

    // use outpk not rct
    rct::key mask;
    _rct_hex_to_rct_commit(outputs[out_index].spk.outpk, mask);
    src.mask = mask;
		src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
    tx_source_entry_with_secret secret_source;
    secret_source.entry = src;

    account_keys secret;
    crypto::secret_key sec_viewKey;
    string secret_view = outputs[out_index].private_key.substr(0, 64);
		THROW_WALLET_EXCEPTION_IF(!string_tools::hex_to_pod(secret_view, sec_viewKey), error::wallet_internal_error, "Couldn't parse view key");
    secret.m_view_secret_key = sec_viewKey;
    
    crypto::secret_key sec_spendKey;
    string secret_spent = outputs[out_index].private_key.substr(64, 64);
		THROW_WALLET_EXCEPTION_IF(!string_tools::hex_to_pod(secret_spent, sec_spendKey), error::wallet_internal_error, "Couldn't parse spend key");
    secret.m_spend_secret_key = sec_spendKey;

    account_public_address m_account_address;
    crypto::public_key pub_viewKey;
    THROW_WALLET_EXCEPTION_IF(!crypto::secret_key_to_public_key(sec_viewKey, pub_viewKey), error::wallet_internal_error, "Couldn't parse view pub key");
    m_account_address.m_view_public_key = pub_viewKey;
    crypto::public_key pub_spendKey;
    THROW_WALLET_EXCEPTION_IF(!crypto::secret_key_to_public_key(sec_spendKey, pub_spendKey), error::wallet_internal_error, "Couldn't parse spend pub key");
    m_account_address.m_spend_public_key = pub_spendKey;

    secret.m_account_address = m_account_address;
    secret_source.secret = secret;
    rct::key maski;
    _rct_hex_to_rct_commit(outputs[out_index].spk.mask, maski);
    secret_source.mask = maski;
    secret_sources.push_back(secret_source);
  }

  THROW_WALLET_EXCEPTION_IF(to_addrs.size() != sending_amounts.size(),
      error::wallet_internal_error,
      "Amounts don't match destinations");

	std::vector<tx_destination_entry> splitted_dsts;
  for (size_t i = 0; i < to_addrs.size(); ++i) {
    tx_destination_entry to_dst = AUTO_VAL_INIT(to_dst);
    to_dst.addr = to_addrs[i].address;
    to_dst.amount = sending_amounts[i];
    to_dst.is_subaddress = to_addrs[i].is_subaddress;
    splitted_dsts.push_back(to_dst);
  }

	tx_destination_entry change_dst = AUTO_VAL_INIT(change_dst);
	change_dst.amount = change_amount;
	//
  if (change_dst.amount == 0) {
    if (splitted_dsts.size() == 1) {
      // If the change is 0, send it to a random address, to avoid confusing
      // the sender with a 0 amount output. We send a 0 amount in order to avoid
      // letting the destination be able to work out which of the inputs is the
      // real one in our rings
      LOG_PRINT_L2("generating dummy address for 0 change");
      account_base dummy;
      dummy.generate();
      change_dst.addr = dummy.get_keys().m_account_address;
      LOG_PRINT_L2("generated dummy address for 0 change");
      splitted_dsts.push_back(change_dst);
    }
  }

	if (found_money > needed_money) {
		if (change_dst.amount != fee_amount) {
			retVals.errCode = resultFeeNotEqualToGiven; // aka "early fee calculation != later"
			return; // early
		}
	} else if (found_money < needed_money) {
		retVals.errCode = needMoreMoneyThanFound; // TODO: return actual found_money and needed_money in generalized err params in return val
		return;
	}

	transaction tx;
	crypto::secret_key tx_key;
	std::vector<crypto::secret_key> additional_tx_keys;

  bool r = construct_tx_and_get_tx_key_cpp(
    secret_sources,
    splitted_dsts, change_dst.addr, extra,
    tx, unlock_time, tx_key, additional_tx_keys,
    true, rct_config, true
  );

	LOG_PRINT_L2("constructed tx, r="<<r);
	if (!r) {
		// TODO: return error::tx_not_constructed, sources, dsts, unlock_time, nettype
		retVals.errCode = transactionNotConstructed;
		return;
	}
	bool use_bulletproofs = !tx.rct_signatures.p.bulletproofs_plus.empty();
	THROW_WALLET_EXCEPTION_IF(use_bulletproofs != true, error::wallet_internal_error, "Expected tx use_bulletproofs to equal bulletproof flag");
	//
	retVals.tx = tx;
	retVals.tx_key = tx_key;
	retVals.additional_tx_keys = additional_tx_keys;
}

// convenience__create_transaction
void convenience_create_transaction(
  Convenience_TransactionConstruction_RetVals& retVals,
  const vector<string>& to_address_strings,
	const vector<uint64_t>& sending_amounts,
	uint64_t fee_amount,
	const vector<spendable_output> &outs,
  uint64_t unlock_time,
  network_type nettype
) {
	retVals.errCode = noError;

	vector<address_parse_info> to_addr_infos(to_address_strings.size());
 	size_t to_addr_idx = 0;
 	for (const auto& addr : to_address_strings) {
 		THROW_WALLET_EXCEPTION_IF(
 			addr.find(".") != std::string::npos, // assumed to be an OA address asXMR addresses do not have periods and OA addrs must
 			error::wallet_internal_error,
 			"Integrators must resolve OA addresses before calling Send"
 		); // This would be an app code fault
 		if (!get_account_address_from_str(to_addr_infos[to_addr_idx++], nettype, addr)) {
 			retVals.errCode = couldntDecodeToAddress;
 			return;
 		}
	}

	std::vector<uint8_t> extra;
  // payment_id_string is empty
  bool payment_id_seen = false;
	for (const auto& to_addr_info : to_addr_infos) {
		if (to_addr_info.is_subaddress && payment_id_seen) {
 			retVals.errCode = cantUsePIDWithSubAddress; // Never use a subaddress with a payment ID
 			return;
		}
		if (to_addr_info.has_payment_id) {
 			if (payment_id_seen) {
 				retVals.errCode = nonZeroPIDWithIntAddress; // can't use int addr at same time as supplying manual pid
 				return;
 			}
 			if (to_addr_info.is_subaddress) {
 				THROW_WALLET_EXCEPTION_IF(false, error::wallet_internal_error, "Unexpected is_subaddress && has_payment_id"); // should never happen
 				return;
 			}
 			std::string extra_nonce;
 			set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, to_addr_info.payment_id);
 			bool r = add_extra_nonce_to_tx_extra(extra, extra_nonce);
 			if (!r) {
 				retVals.errCode = couldntAddPIDNonceToTXExtra;
 				return;
 			}
 			payment_id_seen = true;
		}
	}

  //subaddresses always {0,0}
	const uint32_t subaddr_account_idx = 0;
  uint64_t change_amount = 0;
  uint8_t fork_version = 0;

	TransactionConstruction_RetVals actualCall_retVals;
  create_transaction_cpp(
    actualCall_retVals,
    subaddr_account_idx,
		to_addr_infos,
		sending_amounts,
    change_amount,
    fee_amount,
    outs,
    extra,
    make_use_fork_rules_fn(fork_version),
    unlock_time,
    true,
    nettype
  );

	if (actualCall_retVals.errCode != noError) {
		retVals.errCode = actualCall_retVals.errCode; // pass-through
		return; // already set the error
	}

	auto txBlob = t_serializable_object_to_blob(*actualCall_retVals.tx);
	size_t txBlob_byteLength = txBlob.size();
	THROW_WALLET_EXCEPTION_IF(txBlob_byteLength <= 0, error::wallet_internal_error, "Expected tx blob byte length > 0");

	// tx hash
	retVals.tx_hash_string = epee::string_tools::pod_to_hex(get_transaction_hash(*actualCall_retVals.tx));
	// signed serialized tx
	retVals.signed_serialized_tx_string = epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(*actualCall_retVals.tx));
	// (concatenated) tx key
	{
		ostringstream oss;
		oss << epee::string_tools::pod_to_hex(*actualCall_retVals.tx_key);
		for (size_t i = 0; i < (*actualCall_retVals.additional_tx_keys).size(); ++i) {
			oss << epee::string_tools::pod_to_hex((*actualCall_retVals.additional_tx_keys)[i]);
		}
		retVals.tx_key_string = oss.str();
	}
	{
		ostringstream oss;
		oss << epee::string_tools::pod_to_hex(get_tx_pub_key_from_extra(*actualCall_retVals.tx));
		retVals.tx_pub_key_string = oss.str();
	}
	retVals.tx = *actualCall_retVals.tx; // for calculating block weight; FIXME: std::move?
	retVals.txBlob_byteLength = txBlob_byteLength;
}

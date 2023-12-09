-module(aspike).
-include("../include/aspike.hrl").
-include("../include/aspike_protocol.hrl").

%% API
-export_type([
  node_id/0,
  node_params/0,
  namespace/0,
  set/0,
  key_digest/0,
  credential/0,
  bin_name/0,
  bin_value/0,
  bin/0,
  bins/0,
  bin_names/0,
  op/0,
  response_id/0,
  response/0,
  handled_response/0,
  status/0,
  status_code/0,
  as_proto/0,
  as_msg/0,
  uint8_t/0,
  uint16_t/0,
  uint32_t/0,
  uint48_t/0
]).

-type node_id() :: atom().
-type node_params() :: #aspike_node_params{}.
-type namespace() :: string().
-type set() :: string().
-type key_digest() :: <<_:(20*8)>>. % RIPEMD-160 digest of key for Aerospike record
-type credential() :: <<_:(60*8)>>. % Blowfish ciphered password, BUT with Aerospike specifics
-type bin_name() :: string().
-type bin_value() :: undefined | boolean() |
                      integer() | float() |
                      string() | binary().
-type bin() :: {bin_name(), bin_value()}.
-type bins() :: [bin()].
-type bin_names() :: [bin_name()].
-type op() :: put | get | remove | exists.

-type uint8_t()  :: 0..255.
-type uint16_t() :: 0..65_535.
-type uint32_t() :: 0..4_294_967_295.
%%-type uint48_t() :: 0..281_474_976_710_655.
-type uint48_t() :: 0..(?PROTO_SIZE_MAX-1). % 28 bits out of 48

-type as_proto() :: #as_proto{}.
-type as_msg() :: #as_msg{}.

-type response_field() :: binary(). % <<_:0..4_294_967_295>>.
-type response_fields() :: [response_field()].
-type response_bin_name() :: binary().
-type response_op() :: {response_bin_name(), bin_value()}.
-type response_ops() :: [response_op()].
%%-type response_id() :: shackle:request_id() :: {shackle_server:name(), reference()} :: {atom(), reference()}.
-type response_id() :: {atom(), reference()}.
-type response() :: {as_proto(), as_msg(), response_fields(), response_ops()}.
-type handled_response() :: ok | boolean() | {ok, bins()} |
  {error, {
    record_not_found |
    aspike:status() |
    {aspike:op(), term()} |
    {unrecognized_op_response, aspike:op(), term()}}}.

-type status_code() :: uint8_t().
-type status_code_string() :: binary().
-type status_msg() :: binary().
-type status() :: {status_code(), status_code_string(), status_msg()}.
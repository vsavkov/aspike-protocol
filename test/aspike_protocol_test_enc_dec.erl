-module(aspike_protocol_test_enc_dec).
-include_lib("eunit/include/eunit.hrl").
-include("../include/aspike_protocol.hrl").
-include("../include/aspike_status.hrl").

%%  c("test/aspike_protocol_test_enc_dec.erl").
%%  eunit:test({module, aspike_protocol_test_enc_dec}).

%% API
-export([]).

%% runners
aspike_protocol_enc_dec_test_() ->
  {setup,
    fun () -> ok end,
    fun (_) -> ok end,
    [
      fun test_lv/0,
      fun test_ltv/0,
      fun test_proto/0,
      fun test_admin_pkt/0,
      fun test_admin_header/0,
      fun test_login_pkt/0,
      fun test_login_request/0,
      fun test_login_response/0,
      fun test_dec_login_request/0,
      fun test_enc_response/0,
      fun test_typed_enc_value/0,
      fun test_enc_op_response/0,
      fun test_enc_ops_response/0,
      fun test_enc_get_response_pkt/0,
      fun test_enc_bin/0,
      fun test_enc_bins/0,
      fun test_enc_bin_names/0,
      fun test_put_header/0,
      fun test_key_digest/0,
      fun test_put_request_pkt/0,
      fun test_put_request/0,
      fun test_dec_put_request/0,
      fun test_dec_put_response/0,
      fun test_get_request/0,
      fun test_get_response/0
    ]}.

test_lv() ->
  D1 = <<"1111111">>,
  Enc1 = aspike_protocol:enc_lv(D1),
  {ok, [D1_dec], Rest1_dec} = aspike_protocol:dec_lv(1, Enc1),
  ?assertEqual(D1, D1_dec),
  ?assertEqual(<<>>, Rest1_dec),

  D2 = <<"222222222222">>,
  Enc2 = aspike_protocol:enc_lv(D2),

  Enc12 = <<Enc1/binary, Enc2/binary>>,
  {ok, Tvs12, Rest12_dec} = aspike_protocol:dec_lv(2, Enc12),
  ?assertEqual(2, length(Tvs12)),
  [D1_dec, D2_dec] = Tvs12,
  ?assertEqual(D1, D1_dec),
  ?assertEqual(D2, D2_dec),
  ?assertEqual(<<>>, Rest12_dec),

  D3 = <<"333">>,
  Enc3 = aspike_protocol:enc_lv(D3),
  Enc123 = <<Enc1/binary, Enc2/binary, Enc3/binary>>,
  {ok, Tvs123_2, Rest123_2_dec} = aspike_protocol:dec_lv(2, Enc123),
  ?assertEqual(2, length(Tvs123_2)),
  [D1_dec, D2_dec] = Tvs123_2,
  ?assertEqual(D1, D1_dec),
  ?assertEqual(D2, D2_dec),
  ?assertEqual(Enc3, Rest123_2_dec),

  Ret12_3 = aspike_protocol:dec_lv(3, Enc12),
  ?assertEqual(need_more, Ret12_3),

  <<Partial:(size(Enc3)-1)/binary, _/binary>> = Enc3,
  Enc12partial = <<Enc1/binary, Enc2/binary, Partial/binary>>,
  Ret12partial_3 = aspike_protocol:dec_ltv(3, Enc12partial),
  ?assertEqual(need_more, Ret12partial_3).

test_ltv() ->
  T1 = 1, D1 = <<"1111111">>,
  Enc1 = aspike_protocol:enc_ltv(T1, D1),
  {ok, [{T1_dec, D1_dec}], Rest1_dec} = aspike_protocol:dec_ltv(1, Enc1),
  ?assertEqual(T1, T1_dec),
  ?assertEqual(D1, D1_dec),
  ?assertEqual(<<>>, Rest1_dec),

  T2 = 2, D2 = <<"222222222222">>,
  Enc2 = aspike_protocol:enc_ltv(T2, D2),

  Enc12 = <<Enc1/binary, Enc2/binary>>,
  {ok, Tvs12, Rest12_dec} = aspike_protocol:dec_ltv(2, Enc12),
  ?assertEqual(2, length(Tvs12)),
  ?assertEqual(D1, proplists:get_value(T1, Tvs12)),
  ?assertEqual(D2, proplists:get_value(T2, Tvs12)),
  ?assertEqual(<<>>, Rest12_dec),

  T3 = 3, D3 = <<"333">>,
  Enc3 = aspike_protocol:enc_ltv(T3, D3),
  Enc123 = <<Enc1/binary, Enc2/binary, Enc3/binary>>,
  {ok, Tvs123_2, Rest123_2_dec} = aspike_protocol:dec_ltv(2, Enc123),
  ?assertEqual(2, length(Tvs123_2)),
  ?assertEqual(D1, proplists:get_value(T1, Tvs123_2)),
  ?assertEqual(D2, proplists:get_value(T2, Tvs123_2)),
  ?assertEqual(Enc3, Rest123_2_dec),

  Ret12_3 = aspike_protocol:dec_ltv(3, Enc12),
  ?assertEqual(need_more, Ret12_3),

  <<Partial:(size(Enc3)-1)/binary, _/binary>> = Enc3,
  Enc12partial = <<Enc1/binary, Enc2/binary, Partial/binary>>,
  Ret12partial_3 = aspike_protocol:dec_ltv(3, Enc12partial),
  ?assertEqual(need_more, Ret12partial_3).

test_proto() ->
  Version = ?AS_PROTO_VERSION, Type = ?AS_INFO_MESSAGE_TYPE,
  Bin = <<"0123456789abcdef">>,
  Enc = aspike_protocol:enc_proto(Version, Type, Bin),
  Ret = aspike_protocol:dec_proto(Enc),
  ?assertEqual({ok, {Version, Type, Bin}, <<>>}, Ret),

  <<Prefix:(size(Enc)-3)/binary, _/binary>> = Enc,
  Ret_prefix = aspike_protocol:dec_proto(Prefix),
  ?assertEqual(need_more, Ret_prefix),

  Suffix = <<"ZXCVW">>,
  Extended = <<Enc/binary, Suffix/binary>>,
  Ret_extended = aspike_protocol:dec_proto(Extended),
  ?assertEqual({ok, {Version, Type, Bin}, Suffix}, Ret_extended),

  Dec_info = aspike_protocol:dec_proto(?AS_INFO_MESSAGE_TYPE, Enc),
  ?assertEqual({ok, {Version, Type, Bin}, <<>>}, Dec_info),

  Dec_admin = aspike_protocol:dec_proto(?AS_ADMIN_MESSAGE_TYPE, Enc),
  ?assertEqual({error,
    {expected_typed, ?AS_ADMIN_MESSAGE_TYPE,
      decoded_type, ?AS_INFO_MESSAGE_TYPE}},
    Dec_admin),

  Not_supported = ?AS_PROTO_VERSION+1, Type = ?AS_INFO_MESSAGE_TYPE,
  Bin = <<"0123456789abcdef">>,
  Enc_not_supported = aspike_protocol:enc_proto(Not_supported, Type, Bin),
  Ret_not_supported = aspike_protocol:dec_proto(?AS_INFO_MESSAGE_TYPE, Enc_not_supported),
  ?assertEqual({error,
    {expected_version, ?AS_PROTO_VERSION,
      decoded_version, Not_supported}},
    Ret_not_supported).

test_admin_pkt() ->
  Bin = <<"0123456789abcdef">>,
  Enc = aspike_protocol:enc_admin_pkt(Bin),
  Suffix = <<"ZXCVW">>,
  Extended = <<Enc/binary, Suffix/binary>>,
  Ret = aspike_protocol:dec_admin_pkt(Extended),
  ?assertEqual({ok, {?AS_PROTO_VERSION, ?AS_ADMIN_MESSAGE_TYPE, Bin}, Suffix}, Ret).

test_admin_header() ->
  Command = ?LOGIN, Field_count = 2,
  Enc = aspike_protocol:enc_admin_header(Command, Field_count),
  Suffix = <<"ZXCVW">>,
  Extended = <<Enc/binary, Suffix/binary>>,
  Ret = aspike_protocol:dec_admin_header(Extended),
  ?assertEqual({ok, {Command, Field_count}, Suffix}, Ret).

test_login_pkt() ->
  User = <<"User">>, Credential = <<"Credential">>,
  Enc = aspike_protocol:enc_login_request_pkt(User, {?CREDENTIAL, Credential}),

  <<Prefix:(size(Enc)-3)/binary, _/binary>> = Enc,
  Ret_prefix = aspike_protocol:dec_login_request_pkt(Prefix),
  ?assertEqual(need_more, Ret_prefix),

  Suffix = <<"ZXCVW">>,
  Extended = <<Enc/binary, Suffix/binary>>,
  {ok, {?LOGIN, Fields}, Suffix} = aspike_protocol:dec_login_request_pkt(Extended),
  ?assertEqual(2, length(Fields)),
  ?assertEqual(User, proplists:get_value(?USER, Fields)),
  ?assertEqual(Credential, proplists:get_value(?CREDENTIAL, Fields)).

test_login_request() ->
  User = <<"User">>, Credential = <<"Credential">>,
  Enc = aspike_protocol:enc_login_request(User, {?CREDENTIAL, Credential}),

  <<Prefix:(size(Enc)-3)/binary, _/binary>> = Enc,
  Ret_prefix = aspike_protocol:dec_login_request(Prefix),
  ?assertEqual(need_more, Ret_prefix),

  Suffix = <<"ZXCVW">>,
  Extended = <<Enc/binary, Suffix/binary>>,
  {ok, {?LOGIN, Fields}, Suffix} = aspike_protocol:dec_login_request(Extended),
  ?assertEqual(2, length(Fields)),
  ?assertEqual(User, proplists:get_value(?USER, Fields)),
  ?assertEqual(Credential, proplists:get_value(?CREDENTIAL, Fields)).

test_login_response() ->
  Token = <<"test_session_token">>, Ttl = 123456,
  Status_ok = ?AEROSPIKE_OK,
  Enc = aspike_protocol:enc_login_response(Status_ok,
    [{session_token, Token}, {session_ttl, Ttl}]),
  {ok, {Status, Fields}, <<>>} = aspike_protocol:dec_login_response(Enc),
  ?assertEqual(Status_ok, Status),
  ?assertEqual(2, length(Fields)),
  ?assertEqual(Token, proplists:get_value(session_token, Fields)),
  ?assertEqual(Ttl, proplists:get_value(session_ttl, Fields)),

  Status_not_ok = ?AEROSPIKE_INVALID_CREDENTIAL,
  Enc_status_not_ok = aspike_protocol:enc_login_response(Status_not_ok, []),
  {ok, {Dec_status, Dec_fields}, <<>>} = aspike_protocol:dec_login_response(Enc_status_not_ok),
  ?assertEqual(Status_not_ok, Dec_status),
  ?assertEqual([], Dec_fields).

test_dec_login_request() ->
  User = <<"User">>, Credential = <<"Credential">>,
  Enc = aspike_protocol:enc_login_request(User, {?CREDENTIAL, Credential}),
  {ok, {login_request,{?LOGIN, Fields}}, Rest} = aspike_server_protocol:dec_request(Enc),
  ?assertEqual(2, length(Fields)),
  ?assertEqual(User, proplists:get_value(?USER, Fields)),
  ?assertEqual(Credential, proplists:get_value(?CREDENTIAL, Fields)),
  ?assertEqual(<<>>, Rest),

  <<B1:1/binary, _/binary>> = Enc,
  B1_ret = aspike_server_protocol:dec_request(B1),
  ?assertEqual(need_more, B1_ret),

  <<B3:1/binary, _/binary>> = Enc,
  B3_ret = aspike_server_protocol:dec_request(B3),
  ?assertEqual(need_more, B3_ret),

  Bad_request = <<"123">>,
  Unknown_ret = aspike_server_protocol:dec_request(Bad_request),
  ?assertEqual({error, {unknown_request, Bad_request}}, Unknown_ret).

test_enc_response() ->
  Token = <<"test_session_token">>, Ttl = 123456,
  Enc = aspike_server_protocol:enc_response({login_response, #{?SESSION_TTL => Ttl, ?SESSION_TOKEN => Token}}),
  aspike_protocol:dec_login_response(Enc),
  {ok, {Status, Fields}, <<>>} = aspike_protocol:dec_login_response(Enc),
  ?assertEqual(?AEROSPIKE_OK, Status),
  ?assertEqual(2, length(Fields)),
  ?assertEqual(Token, proplists:get_value(session_token, Fields)),
  ?assertEqual(Ttl, proplists:get_value(session_ttl, Fields)).

test_typed_enc_value() ->
  test_typed_enc_value(undefined),
  test_typed_enc_value(true),
  test_typed_enc_value(false),
  test_typed_enc_value(16#1234ABCDEF),
  test_typed_enc_value(23.457),
  test_typed_enc_value("test_string"),
  test_typed_enc_value(<<"binary_test_string">>).

test_typed_enc_value(V) ->
  ?assertEqual(V,
    aspike_protocol:from_typed_enc_value(
      aspike_protocol:to_typed_enc_value(V))).

test_enc_op_response() ->
  test_enc_op_response("Undefined", undefined),
  test_enc_op_response("true", true),
  test_enc_op_response("false", false),
  test_enc_op_response("16#1234ABCDEF", 16#1234ABCDEF),
  test_enc_op_response("23.457", 23.457),
  test_enc_op_response("String: test_string", "test_string"),
  test_enc_op_response("Binary: binary_test_string", <<"binary_test_string">>).

test_enc_op_response(Name, Value) ->
  Enc_op = aspike_protocol:enc_op_response({Name, Value}),
  {Name_dec, Value_dec} = aspike_protocol:dec_op(Enc_op),
  ?assertEqual(Name, binary_to_list(Name_dec)),
  ?assertEqual(Value, Value_dec).

test_enc_ops_response() ->
  Ops = [
    {"Undefined", undefined},
    {"true", true},
    {"false", false},
    {"16#1234ABCDEF", 16#1234ABCDEF},
    {"23.457", 23.457},
    {"String: test_string", "test_string"},
    {"Binary: binary_test_string", <<"binary_test_string">>}
  ],
  {Count, Enc_ops} = aspike_protocol:enc_ops_response(Ops),
  ?assertEqual(length(Ops), Count),
  {ok, Dec_ops, Rest} = aspike_protocol:dec_ops(Count, Enc_ops),
  Dec_ops1 = lists:map(fun ({Name, V}) -> {binary_to_list(Name), V} end, Dec_ops),
  ?assertEqual(Ops, Dec_ops1),
  ?assertEqual(<<>>, Rest).

test_enc_get_response_pkt() ->
  Result_code = 7,
  Fields = ["Field1", "Field2", "Field2"],
  Ops = [
    {"Undefined", undefined},
    {"true", true},
    {"false", false},
    {"16#1234ABCDEF", 16#1234ABCDEF},
    {"23.457", 23.457},
    {"String: test_string", "test_string"},
    {"Binary: binary_test_string", <<"binary_test_string">>}
  ],

  Enc = aspike_protocol:enc_get_response_pkt(Result_code, Fields, Ops),
  {ok, {Result_code_dec, Fields_dec, Ops_dec}, Rest} = aspike_protocol:dec_get_response_pkt(Enc),

  Fields_dec1 = [binary_to_list(X) || X <- Fields_dec],
  Ops_dec1 = [{binary_to_list(X), Y} || {X, Y} <- Ops_dec],

  ?assertEqual(Result_code, Result_code_dec),
  ?assertEqual(Fields, Fields_dec1),
  ?assertEqual(Ops, Ops_dec1),
  ?assertEqual(<<>>, Rest).

test_enc_bin() ->
  test_enc_bin(0, "Bin_0", undefined),
  test_enc_bin(1, "Bin_1", true),
  test_enc_bin(2, "Bin_2", false),
  test_enc_bin(3, "Bin_3", 16#1234ABCDEF),
  test_enc_bin(4, "Bin_4", 23.457),
  test_enc_bin(5, "Bin_5", "test_string"),
  test_enc_bin(6, "Bin_6", <<"binary_test_string">>).

test_enc_bin(Op, Bin_name, Bin_value) ->
  Enc = aspike_protocol:enc_bin(Op, Bin_name, Bin_value),
  {ok, {Op_dec, Name_dec, Value_dec}, Rest} = aspike_protocol:dec_bin(Enc),
  ?assertEqual(Op, Op_dec),
  ?assertEqual(Bin_name, Name_dec),
  ?assertEqual(Bin_value, Value_dec),
  ?assertEqual(<<>>, Rest).

test_enc_bins() ->
  Op_type = 3,
  Bins = [
    {"Bin_0", undefined},
    {"Bin_1", true},
    {"Bin_2", false},
    {"Bin_3", 16#1234ABCDEF},
    {"Bin_4", 23.457},
    {"Bin_5", "test_string"},
    {"Bin_6", <<"binary_test_string">>}],
  {Count, Enc} = aspike_protocol:enc_bins(Op_type, Bins),
  Expected = lists:map(fun ({X, Y}) -> {Op_type, X, Y} end, Bins),
  {ok, Decoded, Rest} = aspike_protocol:dec_bins(Count, Enc),
  ?assertEqual(Expected, Decoded),
  ?assertEqual(<<>>, Rest).

test_enc_bin_names() ->
  Op_type = 3,
  Bins = [
    "Bin_0",
    "Bin_1",
    "Bin_2",
    "Bin_3",
    "Bin_4",
    "Bin_5",
    "Bin_6"],
  {Count, Enc} = aspike_protocol:enc_bin_names(Op_type, Bins),
  Expected = lists:map(fun (X) -> {Op_type, X} end, Bins),
  {ok, Decoded, Rest} = aspike_protocol:dec_bin_names(Count, Enc),
  ?assertEqual(Expected, Decoded),
  ?assertEqual(<<>>, Rest).

test_put_header() ->
  _Put_header = {N_fields = 3, N_bins = 7,
    Ttl = 120, Timeout = 10_000,
    Read_attr = 16#01, Write_attr = 16#10, Info_attr = 16#37,
    Generation = 12_345},
  Enc = aspike_protocol:enc_put_header(N_fields, N_bins, Ttl, Timeout,
    Read_attr, Write_attr, Info_attr, Generation),
  Expected = #aspike_message_type_header{result_code = ?AEROSPIKE_OK,
    n_fields = N_fields, n_bins = N_bins,
    ttl = Ttl, timeout = Timeout,
    read_attr = Read_attr, write_attr = Write_attr, info_attr = Info_attr,
    generation = Generation,
    unused = 0},
  {ok, Decoded, Rest} = aspike_protocol:dec_put_header(Enc),
  ?assertEqual(Expected, Decoded),
  ?assertEqual(<<>>, Rest).

test_key_digest() ->
  N = "Namespace_value",
  S = "Set_value",
  K = <<"Key_digest_valur">>,
  Enc = aspike_protocol:enc_key_digest(N, S, K),
  {ok, Decoded, Rest} = aspike_protocol:dec_key_digest(Enc),
  ?assertEqual({N, S, K}, Decoded),
  ?assertEqual(<<>>, Rest).

test_put_request_pkt() ->
  N = "Namespace_value",
  S = "Set_value",
  K = <<"Key_digest_valur">>,
  Bins = [
    {"Bin_0", undefined},
    {"Bin_1", true},
    {"Bin_2", false},
    {"Bin_3", 16#1234ABCDEF},
    {"Bin_4", 23.457},
    {"Bin_5", "test_string"},
    {"Bin_6", <<"binary_test_string">>}],
  Enc = aspike_protocol:enc_put_request_pkt(N, S, K, Bins),
  {ok, Decoded, Rest} = aspike_protocol:dec_put_request_pkt(Enc),
  Expected_bins = lists:map(fun ({X, Y}) -> {?AS_OPERATOR_WRITE, X, Y} end, Bins),
  ?assertEqual({N, S, K, Expected_bins}, Decoded),
  ?assertEqual(<<>>, Rest).

test_put_request() ->
  N = "Namespace_value",
  S = "Set_value",
  K = <<"Key_digest_valur">>,
  Bins = [
    {"Bin_0", undefined},
    {"Bin_1", true},
    {"Bin_2", false},
    {"Bin_3", 16#1234ABCDEF},
    {"Bin_4", 23.457},
    {"Bin_5", "test_string"},
    {"Bin_6", <<"binary_test_string">>}],
  Enc = aspike_protocol:enc_put_request(N, S, K, Bins),
  {ok, Decoded, Rest} = aspike_protocol:dec_put_request(Enc),
  Expected_bins = lists:map(fun ({X, Y}) -> {?AS_OPERATOR_WRITE, X, Y} end, Bins),
  ?assertEqual({N, S, K, Expected_bins}, Decoded),
  ?assertEqual(<<>>, Rest).

test_dec_put_request() ->
  Ns = "Namespace_test", S = "Set_test",
  K = <<"Key_digest_test">>,
  Bins = [
    {"Bin_0", undefined},
    {"Bin_1", true},
    {"Bin_2", false},
    {"Bin_3", 16#1234ABCDEF},
    {"Bin_4", 23.457},
    {"Bin_5", "test_string"},
    {"Bin_6", <<"binary_test_string">>}],

  Enc = aspike_protocol:enc_put_request(Ns, S, K, Bins),
  {ok, {put_request, Decoded}, Rest} = aspike_server_protocol:dec_request(Enc),
  {Ns_dec, S_dec, K_dec, Bins_dec} = Decoded,
  {_Ops, Bin_names, Bin_values} = lists:unzip3(Bins_dec),
  Bin_names_values = lists:zip(Bin_names, Bin_values),
  ?assertEqual(Ns, Ns_dec),
  ?assertEqual(S, S_dec),
  ?assertEqual(K, K_dec),
  ?assertEqual(Bins, Bin_names_values),
  ?assertEqual(<<>>, Rest).

test_dec_put_response() ->
  Enc = aspike_protocol:enc_put_response(?AEROSPIKE_OK),
  {ok, #aspike_message_type_header{result_code = Result_code} = _Decoded, Rest}
    = aspike_protocol:dec_put_response(Enc),
  ?assertEqual(?AEROSPIKE_OK, Result_code),
  ?assertEqual(<<>>, Rest).

test_get_request() ->
  N = "Namespace_value",
  S = "Set_value",
  K = <<"Key_digest_valur">>,
  Bins = [
    "Bin_0",
    "Bin_1",
    "Bin_2",
    "Bin_3",
    "Bin_4",
    "Bin_5",
    "Bin_6"],
  Enc = aspike_protocol:enc_get_request(N, S, K, Bins),
  {ok, Decoded, Rest} = aspike_protocol:dec_get_request(Enc),
  Expected_bins = lists:map(fun (X) -> {?AS_OPERATOR_READ, X} end, Bins),
  ?assertEqual({N, S, K, Expected_bins}, Decoded),
  ?assertEqual(<<>>, Rest),

  Enc_all_bins = aspike_protocol:enc_get_request(N, S, K, []),
  {ok, Decoded_all_bins, Rest_all_bins} = aspike_protocol:dec_get_request(Enc_all_bins),
  Expected_all_bins = [],
  ?assertEqual({N, S, K, Expected_all_bins}, Decoded_all_bins),
  ?assertEqual(<<>>, Rest_all_bins).

test_get_response() ->
  Result_code = 7,
  Fields = ["Field1", "Field2", "Field2"],
  Ops = [
    {"Undefined", undefined},
    {"true", true},
    {"false", false},
    {"16#1234ABCDEF", 16#1234ABCDEF},
    {"23.457", 23.457},
    {"String: test_string", "test_string"},
    {"Binary: binary_test_string", <<"binary_test_string">>}
  ],

  Enc = aspike_protocol:enc_get_response(Result_code, Fields, Ops),
  {ok, {Result_code_dec, Fields_dec, Ops_dec}, Rest} = aspike_protocol:dec_get_response(Enc),

  Fields_dec1 = [binary_to_list(X) || X <- Fields_dec],
  Ops_dec1 = [{binary_to_list(X), Y} || {X, Y} <- Ops_dec],

  ?assertEqual(Result_code, Result_code_dec),
  ?assertEqual(Fields, Fields_dec1),
  ?assertEqual(Ops, Ops_dec1),
  ?assertEqual(<<>>, Rest).

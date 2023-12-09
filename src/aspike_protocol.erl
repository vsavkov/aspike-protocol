-module(aspike_protocol).
-include("../include/aspike_protocol.hrl").
-include("../include/aspike_status.hrl").

%%
%% Encoding/decoding binary data for Aerospike protocol
%%


%% API

%% High-level encoders/decoders, Client side
-export([
  enc_login_request/2,
  dec_login_response/1,
  enc_put_request/4,
  dec_put_response/1,
  enc_get_request/4,
  dec_get_response/1,
  enc_remove_request/3,
  dec_remove_response/1,
  enc_exists_request/3,
  dec_exists_response/1
]).

%% High-level encoders/decoders, Server side
-export([
  dec_login_request/1,
  enc_login_response/2,
  dec_put_request/1,
  enc_put_response/1,
  dec_get_request/1,
  enc_get_response/3,
  dec_remove_request/1,
  enc_remove_response/1,
  dec_exists_request/1,
  enc_exists_response/1
]).

%% Login-specific encoders/decoders
-export([
  enc_login_request_pkt/2,
  dec_login_request_pkt/1,
  enc_admin_header/2,
  dec_admin_header/1,
  enc_proto_admin_fields/1,
  dec_proto_admin_fields/2
]).

%% Put-specific encoders/decoders
-export([
  enc_put_request_pkt/4,
  dec_put_request_pkt/1,
  enc_put_response_pkt/1,
  dec_put_response_pkt/1,
  enc_put_header/8,
  dec_put_header/1,
  enc_bins/2,
  enc_bin/3,
  dec_bins/2,
  dec_bin/1
]).

%% Get-specific encoders/decoders
-export([
  enc_get_request_pkt/4,
  dec_get_request_pkt/1,
  enc_get_response_pkt/3,
  dec_get_response_pkt/1,
  enc_get_header/5,
  dec_get_header/1,
  enc_get_response_header/3,
  dec_get_response_header/1,
  check_get_request/2,
  enc_bin_names/2,
  enc_bin_name/2,
  dec_bin_names/2,
  dec_bin_name/1,
  enc_fields_and_ops/2,
  enc_fields/1,
  enc_ops_response/1,
  enc_op_response/1,
  dec_fields_and_ops/3,
  dec_ops/2,
  dec_op/1
]).

%% Remove-specific encoders/decoders
-export([
  enc_remove_request_pkt/3,
  dec_remove_request_pkt/1,
  enc_remove_response_pkt/1,
  dec_remove_response_pkt/1,
  enc_remove_header/6,
  dec_remove_header/1
]).

%% Exists-specific encoders/decoders
-export([
  enc_exists_request_pkt/3,
  dec_exists_request_pkt/1,
  enc_exists_response_pkt/1,
  dec_exists_response_pkt/1,
  enc_exists_header/6,
  dec_exists_header/1
]).

%% Key-specific
-export([
  digest/2,
  enc_key_digest/3,
  dec_key_digest/1
]).

%% Protocol encoders/decoders
-export([
  enc_admin_pkt/1,
  dec_admin_pkt/1,
  enc_message_pkt/1,
  dec_message_pkt/1,
  enc_message_type_header/10,
  dec_message_type_header/1,
  enc_proto/2,
  enc_proto/3,
  dec_proto/1,
  dec_proto/2
]).

%% Utils
-export([
  enc_lv/1,
  dec_lv/2,
  enc_ltv/2,
  dec_ltv/2,
  to_typed_enc_value/1,
  from_typed_enc_value/1
]).

%% Response decoder for 'shackle client' handle_data/2
-export([
  dec_responses/1
]).

%% High-level encoders/decoders, Client side
enc_login_request(User, Credential) ->
  enc_admin_pkt(enc_login_request_pkt(User, Credential)).

dec_login_response(Data) ->
  case dec_admin_pkt(Data) of
    need_more -> need_more;
    {error, _Reason} = Err -> Err;
    {ok, {_Version, _Type, Data1}, Rest} ->
      case dec_login_response_pkt(Data1) of
        {error, _Reason} = Err -> Err;
        {ok, Decoded} -> {ok, Decoded, Rest}
      end
  end.

enc_put_request(Namespace_str, Set_name, Key_digest, Bins) ->
  enc_message_pkt(enc_put_request_pkt(Namespace_str, Set_name, Key_digest, Bins)).

dec_put_response(Data) ->
  case dec_message_pkt(Data) of
    need_more -> need_more;
    {error, _Reason} = Err -> Err;
    {ok, {_Version, _Type, Data1}, Rest} ->
      case dec_put_response_pkt(Data1) of
        need_more -> need_more;
        {ok, #aspike_message_type_header{} = Decoded, _Data2} ->
          {ok, Decoded, Rest}
      end
  end.

enc_get_request(Namespace_str, Set_name, Key_digest, Bins) ->
  enc_message_pkt(enc_get_request_pkt(Namespace_str, Set_name, Key_digest, Bins)).

dec_get_response(Data) ->
  case dec_message_pkt(Data) of
    need_more -> need_more;
    {error, _Reason} = Err -> Err;
    {ok, {_Version, _Type, Data1}, Rest} ->
      case dec_get_response_pkt(Data1) of
        need_more -> need_more;
        {ok, {_Result_code, _Fields, _Ops} = Decoded, _Data2} ->
          {ok, Decoded, Rest}
      end
  end.

enc_remove_request(Namespace_str, Set_name, Key_digest) ->
  enc_message_pkt(enc_remove_request_pkt(Namespace_str, Set_name, Key_digest)).

dec_remove_response(Data) ->
  case dec_message_pkt(Data) of
    need_more -> need_more;
    {error, _Reason} = Err -> Err;
    {ok, {_Version, _Type, Data1}, Rest} ->
      case dec_remove_response_pkt(Data1) of
        need_more -> need_more;
        {ok, #aspike_message_type_header{} = Decoded, _Data2} ->
          {ok, Decoded, Rest}
      end
  end.

enc_exists_request(Namespace_str, Set_name, Key_digest) ->
  enc_message_pkt(enc_exists_request_pkt(Namespace_str, Set_name, Key_digest)).

dec_exists_response(Data) ->
  case dec_message_pkt(Data) of
    need_more -> need_more;
    {error, _Reason} = Err -> Err;
    {ok, {_Version, _Type, Data1}, Rest} ->
      case dec_exists_response_pkt(Data1) of
        need_more -> need_more;
        {ok, #aspike_message_type_header{} = Decoded, _Data2} ->
          {ok, Decoded, Rest}
      end
  end.

%% High-level encoders/decoders, Client side. End

%% High-level encoders/decoders, Server side
dec_login_request(Data) ->
  case dec_admin_pkt(Data) of
    need_more -> need_more;
    {error, _Reason} = Err -> Err;
    {ok, {_Version, _Type, Data1}, Rest} ->
      case dec_login_request_pkt(Data1) of
        need_more -> need_more;
        {ok, {_Command, _Fields} = Decoded, _Data2} ->
          {ok, Decoded, Rest}
      end
  end.

enc_login_response(Status, Fields) ->
  {Count, Data} = enc_proto_admin_fields(Fields),
  enc_admin_pkt(enc_login_response_pkt(Status, Count, Data)).

dec_put_request(Data) ->
  case dec_message_pkt(Data) of
    need_more -> need_more;
    {error, _Reason} = Err -> Err;
    {ok, {_Version, _Type, Data1}, Rest} ->
      case dec_put_request_pkt(Data1) of
        need_more -> need_more;
        {ok,
          {_Namespace_str, _Set_name, _Key_digest, _Bins} = Decoded,
          _Data2} ->
          {ok, Decoded, Rest}
      end
  end.

enc_put_response(Status) ->
  enc_message_pkt(enc_put_response_pkt(Status)).

dec_get_request(Data) ->
  case dec_message_pkt(Data) of
    need_more -> need_more;
    {error, _Reason1} = Err1 -> Err1;
    {ok, {_Version, _Type, Data1}, Rest} ->
      case dec_get_request_pkt(Data1) of
        need_more -> need_more; % TODO: return {error, get_request_pkt_bad_format}
        {error, _Reason2} = Err2 -> Err2;
        {ok,
          {_Namespace_str, _Set_name, _Key_digest, _Bin_names} = Decoded,
          _Data2} ->
          {ok, Decoded, Rest}
      end
  end.

enc_get_response(Result_code, Fields, Ops) ->
  enc_message_pkt(enc_get_response_pkt(Result_code, Fields, Ops)).

dec_remove_request(Data) ->
  case dec_message_pkt(Data) of
    need_more -> need_more;
    {error, _Reason1} = Err1 -> Err1;
    {ok, {_Version, _Type, Data1}, Rest} ->
      case dec_remove_request_pkt(Data1) of
        need_more -> need_more; % TODO: return {error, remove_request_pkt_bad_format}
        {error, _Reason2} = Err2 -> Err2;
        {ok,
          {_Namespace_str, _Set_name, _Key_digest} = Decoded,
          _Data2} ->
          {ok, Decoded, Rest}
      end
  end.

enc_remove_response(Status) ->
  enc_message_pkt(enc_remove_response_pkt(Status)).

dec_exists_request(Data) ->
  case dec_message_pkt(Data) of
    need_more -> need_more;
    {error, _Reason1} = Err1 -> Err1;
    {ok, {_Version, _Type, Data1}, Rest} ->
      case dec_exists_request_pkt(Data1) of
        need_more -> need_more; % TODO: return {error, exists_request_pkt_bad_format}
        {error, _Reason2} = Err2 -> Err2;
        {ok,
          {_Namespace_str, _Set_name, _Key_digest} = Decoded,
          _Data2} ->
          {ok, Decoded, Rest}
      end
  end.

enc_exists_response(Status) ->
  enc_message_pkt(enc_exists_response_pkt(Status)).

%% High-level encoders/decoders, Server side. End

%% Login-specific encoders/decoders
enc_login_request_pkt(User, {Type, Value} = _Credential) ->
  H = enc_admin_header(?LOGIN, 2),
  U = enc_ltv(?USER, User),
  C = enc_ltv(Type, Value),
  <<H/binary, U/binary, C/binary>>.

dec_login_request_pkt(Data) ->
  case dec_admin_header(Data) of
    need_more -> need_more;
    {ok, {Command, Field_count}, Data1} ->
      case dec_ltv(Field_count, Data1) of
        need_more -> need_more;
        {ok, Fields, Data2} ->
          Decoded = {Command, Fields},
          {ok, Decoded, Data2}
      end
  end.

enc_login_response_pkt(Status, Count, Data) ->
  Unused1 = <<0:8>>, Unused12 = <<0:(8*12)>>,
  <<Unused1/binary, Status:8/integer, Unused1/binary,
    Count:8/integer, Unused12/binary, Data/binary>>.

dec_login_response_pkt(<<_:8,
  Status:8/integer, _:8,
  Field_count:8/integer, _:(8*12),
  Fields_data/binary>>) ->
  case dec_proto_admin_fields(Field_count, Fields_data) of
    need_more -> {error, bad_login_response_format};
    {ok, Fields, _Rest} ->
      Decoded =  {Status, Fields},
      {ok, Decoded}
  end.

enc_admin_header(Command, Field_count) ->
  <<0:(8*2),
    Command:8/unsigned-integer, Field_count:8/unsigned-integer,
    0:(8*12)>>.

dec_admin_header(<<0:(8*2),
  Command:8/unsigned-integer, Field_count:8/unsigned-integer,
  0:(8*12), Rest/binary>>) ->
  Decoded = {Command, Field_count},
  {ok, Decoded, Rest};
dec_admin_header(_Data) ->
  need_more.

enc_proto_admin_fields(Fields) ->
  lists:foldl(fun ({_Tag, _Value} = TV, {Count, Data}) ->
    {T, V} = from_admin_field(TV),
    Enc = enc_ltv(T, V), {Count+1, <<Enc/binary, Data/binary>>}
              end, {0, <<>>}, Fields).

dec_proto_admin_fields(Field_count, Fields_data) ->
  case dec_ltv(Field_count, Fields_data) of
    need_more -> need_more;
    {ok, Tvs, Data} ->
      {ok, lists:map(fun to_admin_field/1, Tvs), Data}
  end.

to_admin_field({?SESSION_TOKEN, V}) ->
  {session_token, V};
to_admin_field({?SESSION_TTL, <<Ttl:32/big-unsigned-integer>> = _V}) ->
  {session_ttl, Ttl};
to_admin_field({T, V}) ->
  {T, V}.

from_admin_field({session_token, V}) ->
  {?SESSION_TOKEN, V};
from_admin_field({session_ttl, V}) ->
  {?SESSION_TTL, <<V:32/big-unsigned-integer>>};
from_admin_field({_, _} = TV) ->
  TV.

%% Login-specific encoders/decoders. End

%% Put-specific encoders/decoders
enc_put_request_pkt(Namespace_str, Set_name, Key_digest, Bins) ->
  N_fields = 3, % Namespace, Set, Key digest
  {N_bins, B} = enc_bins(?AS_OPERATOR_WRITE, Bins),
  H = enc_put_header(N_fields, N_bins, _Ttl = 0, _Timeout = 1000,
    _Read_attr = 0,
    _Write_attr = ?AS_MSG_INFO2_WRITE,
    _Info_attr = 0, _Generation = 0),
  K = enc_key_digest(Namespace_str, Set_name, Key_digest),
  <<H/binary, K/binary, B/binary>>.

dec_put_request_pkt(Data) ->
  case dec_put_header(Data) of
    need_more -> need_more;
    {ok, #aspike_message_type_header{
      write_attr = ?AS_MSG_INFO2_WRITE,
      n_bins = N_bins}, Data1} ->
      case dec_key_digest(Data1) of
        need_more -> need_more;
        {ok, {Namespace_str, Set_name, Key_digest}, Data2} ->
          case dec_bins(N_bins, Data2) of
            need_more -> need_more;
            {ok, Bins, Rest} ->
              Decoded = {Namespace_str, Set_name, Key_digest, Bins},
              {ok, Decoded, Rest};
            {error, _Reason2} = Err2 -> Err2
          end;
        {error, _Reason1} = Err1 -> Err1
      end;
    _ -> {error, {put_request_pkt_wrong_header, Data}}
  end.

enc_put_response_pkt(Status) ->
  enc_message_type_header(
    Status,
    _N_fields = 0,
    _N_bins = 0,
    _Ttl = 0,
    _Timeout = 0,
    _Read_attr = 0,
    _Write_attr = 0,
    _Info_attr = 0,
    _Generation = 0,
    _Unused = 0).

dec_put_response_pkt(Data) ->
  dec_message_type_header(Data).

enc_put_header(
    N_fields,
    N_bins,
    Ttl, % in seconds
    Timeout, % in milliseconds
    Read_attr,
    Write_attr,
    Info_attr,
    Generation) ->
  enc_message_type_header(
    ?AEROSPIKE_OK,
    N_fields,
    N_bins,
    Ttl, % in seconds
    Timeout, % in milliseconds
    Read_attr,
    Write_attr,
    Info_attr,
    Generation,
    _Unused = 0).

dec_put_header(Data) ->
  dec_message_type_header(Data).

%% Encoding of Aerospike bin, NOT binary data
% Bins = [{Bin_name, Bin_value}]
enc_bins(Op_type, Bins) ->
  lists:foldl(fun ({Bin_name, Bin_value}, {Count, Acc}) ->
    Enc_bin = enc_bin(Op_type, Bin_name, Bin_value),
    {Count+1, <<Acc/binary, Enc_bin/binary>>}
              end, {0, <<>>}, Bins).

enc_bin(Op_type, Bin_name, Bin_value) ->
  {_Value_type, _Enc_value} = Typed_value = to_typed_enc_value(Bin_value),
  enc_bin_typed_value(Op_type, Bin_name, Typed_value).

enc_bin_typed_value(Op_type, Bin_name, {error, Reason}) ->
  Details = [{op_type, Op_type},{bin_name, Bin_name}],
  {error, {Reason, Details}};
enc_bin_typed_value(Op_type, Bin_name, {Value_type, Enc_value}) ->
  Enc_name = list_to_binary(Bin_name),
  Enc_op_bin_value = <<Op_type:8, Value_type:8, 0:8, (size(Enc_name)):8,
    Enc_name/binary, Enc_value/binary>>,
  enc_lv(Enc_op_bin_value).

dec_bins(N, Data) ->
  dec_bins(N, Data, []).

dec_bins(0, Data, Acc) ->
  {ok, lists:reverse(Acc), Data};
dec_bins(N, Data, Acc) ->
  case dec_bin(Data) of
    need_more -> need_more;
    {error, _Reason} = Err -> Err;
    {ok, Decoded, Rest} -> dec_bins(N-1, Rest, [Decoded|Acc])
  end.

dec_bin(<<
  Size:32/big-unsigned-integer,
  Op_type:8, Value_type:8, _:8, Name_len:8, % Header, 4 bytes
  Enc_name:Name_len/binary,
  Enc_value:(Size-4-Name_len)/binary, Rest/binary>>) ->
  Bin_value = from_typed_enc_value({Value_type, Enc_value}),
  dec_bin(Op_type, Enc_name, Bin_value, Rest);
dec_bin(<<_/binary>>) ->
  need_more.

dec_bin(Op_type, Bin_name, {error, Reason}, _Rest) ->
  Details = [{op_type, Op_type},{bin_name, Bin_name}],
  {error, {Reason, Details}};
dec_bin(Op_type, Enc_name, Bin_value, Rest) ->
  Bin_name = binary_to_list(Enc_name),
  Decoded = {Op_type, Bin_name, Bin_value},
  {ok, Decoded, Rest}.

%% Put-specific encoders/decoders. End

%% Get-specific encoders/decoders
enc_get_request_pkt(Namespace_str, Set_name, Key_digest, Bins) ->
  N_fields = 3, % Namespace, Set, Key digest
  {N_bin_names, B} = enc_bin_names(?AS_OPERATOR_READ, Bins),
  Read_attr = case N_bin_names of
                0 -> (?AS_MSG_INFO1_READ bor ?AS_MSG_INFO1_GET_ALL);
                _ -> ?AS_MSG_INFO1_READ
              end,
  H = enc_get_header(N_fields, N_bin_names, _Timeout = 1000,
    Read_attr, _Info_attr = 0),
  K = enc_key_digest(Namespace_str, Set_name, Key_digest),
  <<H/binary, K/binary, B/binary>>.

dec_get_request_pkt(Data) ->
  case dec_get_header(Data) of
    need_more -> need_more;
    {ok, #aspike_message_type_header{
      read_attr = Read_attr,
      n_bins = N_bins}, Data1} ->
      case check_get_request(N_bins, Read_attr) of
        {error, _} = Err3 -> Err3;
        ok ->
          case dec_key_digest(Data1) of
            need_more -> need_more;
            {ok, {Namespace_str, Set_name, Key_digest}, Data2} ->
              case dec_bin_names(N_bins, Data2) of
                need_more -> need_more;
                {ok, Bin_names, Rest} ->
                  Decoded = {Namespace_str, Set_name, Key_digest, Bin_names},
                  {ok, Decoded, Rest};
                {error, _Reason2} = Err2 -> Err2
              end;
            {error, _Reason1} = Err1 -> Err1
          end
      end
  end.

enc_get_response_pkt(Result_code, Fields, Ops) ->
  {N_fields, N_ops, Enc_fields_and_ops} = enc_fields_and_ops(Fields, Ops),
  Enc_header = enc_get_response_header(Result_code, N_fields, N_ops),
  <<Enc_header/binary, Enc_fields_and_ops/binary>>.

dec_get_response_pkt(Data) ->
  case dec_get_response_header(Data) of
    need_more -> need_more;
    {ok, #aspike_message_type_header{
      result_code = Result_code,
      n_fields = N_fields, n_bins = N_bins}, Data1} ->
      case dec_fields_and_ops(N_fields, N_bins, Data1) of
        need_more -> need_more;
        {ok, {Fields, Ops}, Rest} ->
          Decoded = {Result_code, Fields, Ops},
          {ok, Decoded, Rest}
      end
  end.

enc_get_header(
    N_fields,
    N_bins,
    Timeout, % in milliseconds
    Read_attr,
    Info_attr) ->
  enc_message_type_header(
    ?AEROSPIKE_OK,
    N_fields,
    N_bins,
    _Ttl = 0, % in seconds
    Timeout, % in milliseconds
    Read_attr,
    _Write_attr = 0,
    Info_attr,
    _Generation = 0,
    _Unused = 0).

dec_get_header(Data) ->
  dec_message_type_header(Data).

enc_get_response_header(Result_code, N_fields, N_ops) ->
  enc_message_type_header(Result_code, N_fields, N_ops,
    _Ttl = 0, _Timeout = 0,
    _Read_attr = 0, _Write_attr = 0, _Info_attr = 0,
    _Generation = 0, _Unused = 0).

dec_get_response_header(Data) ->
  dec_message_type_header(Data).

check_get_request(_N_bins = 0,
    _Read_attr = (?AS_MSG_INFO1_READ bor ?AS_MSG_INFO1_GET_ALL)) ->
  ok;
check_get_request(N_bins,
    _Read_attr = ?AS_MSG_INFO1_READ) when N_bins > 0 ->
  ok;
check_get_request(N_bins, Read_attr) ->
  {error, {wrong_combination_of_bins_and_read_attr, N_bins, Read_attr}}.

enc_bin_names(Op_type, Bin_names) ->
  lists:foldl(fun (B, {Count, Acc}) ->
    Enc_bin_name = enc_bin_name(Op_type, B),
    {Count+1, <<Acc/binary, Enc_bin_name/binary>>}
              end, {0, <<>>}, Bin_names).

enc_bin_name(Op_type, Bin_name) ->
  Enc_name = list_to_binary(Bin_name),
  Name_len = size(Enc_name),
  % The size of <<(Name_len+4):32/big-unsigned-integer, Op_type:8, 0:8, 0:8, Name_len:8>>
  % should be equal to ?AS_OPERATION_HEADER_SIZE=8
  <<(Name_len+4):32/big-unsigned-integer, Op_type:8, 0:8, 0:8, Name_len:8, Enc_name/binary>>.

dec_bin_names(N, Data) ->
  dec_bin_names(N, Data, []).

dec_bin_names(0, Data, Acc) ->
  {ok, lists:reverse(Acc), Data};
dec_bin_names(N, Data, Acc) ->
  case dec_bin_name(Data) of
    need_more -> need_more;
    {error, _Reason} = Err -> Err;
    {ok, Decoded, Rest} -> dec_bin_names(N-1, Rest, [Decoded|Acc])
  end.

dec_bin_name(<<
  Size:32/big-unsigned-integer,
  Op_type:8, _:8, _:8,
  Name_len:8,
  Enc_name:Name_len/binary, Rest/binary>>) when Name_len+4 =:= Size ->
  Decoded = {Op_type, binary_to_list(Enc_name)},
  {ok, Decoded, Rest};
dec_bin_name(<<
  Size:32/big-unsigned-integer,
  _Op_type:8, _:8, _:8,
  Name_len:8,
  _Enc_name:Name_len/binary, _Rest/binary>>) when Name_len+4 =/= Size ->
  {error, bin_name_decoding};
dec_bin_name(<<_/binary>>) ->
  need_more.

enc_fields_and_ops(Fields, Ops) ->
  {N_fields, Enc_fields} = enc_fields(Fields),
  {N_ops, Enc_ops} = enc_ops_response(Ops),
  {N_fields, N_ops, <<Enc_fields/binary, Enc_ops/binary>>}.

enc_fields(Fields) ->
  lists:foldl(fun (X, {Count, Acc}) ->
    Enc = enc_lv(X), {Count+1, <<Acc/binary, Enc/binary>>}
              end, {0, <<>>}, Fields).

enc_ops_response(Ops) ->
  lists:foldl(fun (Op, {Count, Acc}) ->
    Enc_lv = enc_lv(enc_op_response(Op)),
    {Count+1, <<Acc/binary, Enc_lv/binary>>}
              end, {0, <<>>}, Ops).

enc_op_response({Name, Value} = _Op) when is_list(Name) ->
  enc_op_response({list_to_binary(Name), Value});
enc_op_response({Name, Value} = _Op) ->
  {Value_type, Enc_value} = case to_typed_enc_value(Value) of
                              {error, _} = Err ->
                                {?AS_BYTES_STRING, lists:flatten(io_lib:format("~tp", [Err]))};
                              Ret -> Ret
                            end,
  Unused = 0,
  Name_size = size(Name),
  <<Unused:8, Value_type:8, Unused:8,
    Name_size:8/unsigned-integer, Name:Name_size/binary,
    Enc_value/binary>>.

dec_fields_and_ops(N_fields, N_ops, Data) ->
  case dec_lv(N_fields, Data) of
    need_more -> need_more;
    {ok, Fields, Data1} ->
      case dec_ops(N_ops, Data1) of
        need_more -> need_more;
        {ok, Ops, Data2} ->
          Decoded = {Fields, Ops},
          {ok, Decoded, Data2}
      end
  end.

dec_ops(N_ops, Data) ->
  case dec_lv(N_ops, Data) of
    need_more -> need_more;
    {ok, Vs, Data1} ->
      {ok, lists:map(fun dec_op/1, Vs), Data1}
  end.

dec_op(<<_Skip1:8, Value_type:8, _Skip2:8,
  Name_size:8/unsigned-integer, Name:Name_size/binary,
  Data_for_value/binary>>) ->
  Value = case from_typed_enc_value({Value_type, Data_for_value}) of
            {error, _} = Err ->
              lists:flatten(io_lib:format("~tp", [Err]));
            V -> V
          end,
  {Name, Value};
dec_op(Op) ->
  {<<"op_bad_format">>, Op}.

%% Get-specific encoders/decoders. End

%% Remove-specific encoders/decoders
enc_remove_request_pkt(Namespace_str, Set_name, Key_digest) ->
  N_fields = 3, % Namespace, Set, Key digest
  H = enc_remove_header(N_fields, _Timeout = 1000,
    _Read_attr = 0,
    _Write_attr = (?AS_MSG_INFO2_WRITE bor ?AS_MSG_INFO2_DELETE),
    _Info_attr = 0, _Generation = 0),
  K = enc_key_digest(Namespace_str, Set_name, Key_digest),
  <<H/binary, K/binary>>.

dec_remove_request_pkt(Data) ->
  case dec_remove_header(Data) of
    need_more -> need_more;
    {ok, #aspike_message_type_header{
      write_attr = (?AS_MSG_INFO2_WRITE bor ?AS_MSG_INFO2_DELETE)},
      Data1} ->
      case dec_key_digest(Data1) of
        need_more -> need_more;
        {ok, {Namespace_str, Set_name, Key_digest}, Data2} ->
          Decoded = {Namespace_str, Set_name, Key_digest},
          {ok, Decoded, Data2};
        {error, _Reason1} = Err1 -> Err1
      end;
    _ -> {error, {remove_request_pkt_wrong_header, Data}}
  end.

enc_remove_response_pkt(Status) ->
  enc_message_type_header(
    Status,
    _N_fields = 0,
    _N_bins = 0,
    _Ttl = 0,
    _Timeout = 0,
    _Read_attr = 0,
    _Write_attr = 0,
    _Info_attr = 0,
    _Generation = 0,
    _Unused = 0).

dec_remove_response_pkt(Data) ->
  dec_message_type_header(Data).

enc_remove_header(
    N_fields,
    Timeout, % in milliseconds
    Read_attr,
    Write_attr,
    Info_attr,
    Generation) ->
  enc_message_type_header(
    ?AEROSPIKE_OK,
    N_fields,
    _N_bins = 0,
    _Ttl = 0, % in seconds
    Timeout, % in milliseconds
    Read_attr,
    Write_attr,
    Info_attr,
    Generation,
    _Unused = 0).

dec_remove_header(Data) ->
  dec_message_type_header(Data).

%% Remove-specific encoders/decoders. End

%% Exists-specific encoders/decoders
enc_exists_request_pkt(Namespace_str, Set_name, Key_digest) ->
  N_fields = 3, % Namespace, Set, Key digest
  H = enc_exists_header(N_fields, _Timeout = 1000,
    _Read_attr = (?AS_MSG_INFO1_READ bor ?AS_MSG_INFO1_GET_NOBINDATA),
    _Write_attr = 0,
    _Info_attr = 0, _Generation = 0),
  K = enc_key_digest(Namespace_str, Set_name, Key_digest),
  <<H/binary, K/binary>>.

dec_exists_request_pkt(Data) ->
  case dec_exists_header(Data) of
    need_more -> need_more;
    {ok, #aspike_message_type_header{
      read_attr = (?AS_MSG_INFO1_READ bor ?AS_MSG_INFO1_GET_NOBINDATA)},
      Data1} ->
      case dec_key_digest(Data1) of
        need_more -> need_more;
        {ok, {Namespace_str, Set_name, Key_digest}, Data2} ->
          Decoded = {Namespace_str, Set_name, Key_digest},
          {ok, Decoded, Data2};
        {error, _Reason1} = Err1 -> Err1
      end;
    _ -> {error, {remove_request_pkt_wrong_header, Data}}
  end.

enc_exists_response_pkt(Status) ->
  enc_message_type_header(
    Status,
    _N_fields = 0,
    _N_bins = 0,
    _Ttl = 0,
    _Timeout = 0,
    _Read_attr = 0,
    _Write_attr = 0,
    _Info_attr = 0,
    _Generation = 0,
    _Unused = 0).

dec_exists_response_pkt(Data) ->
  dec_message_type_header(Data).

enc_exists_header(
    N_fields,
    Timeout, % in milliseconds
    Read_attr,
    Write_attr,
    Info_attr,
    Generation) ->
  enc_message_type_header(
    ?AEROSPIKE_OK,
    N_fields,
    _N_bins = 0,
    _Ttl = 0, % in seconds
    Timeout, % in milliseconds
    Read_attr,
    Write_attr,
    Info_attr,
    Generation,
    _Unused = 0).

dec_exists_header(Data) ->
  dec_message_type_header(Data).

%% Exists-specific encoders/decoders. End

%% Key-specific
digest([], Key) ->
  K = enc_key(Key),
  crypto:hash(ripemd160, K);
digest(Set, Key) ->
  K = enc_key(Key),
  S0 = crypto:hash_init(ripemd160),
  S1 = crypto:hash_update(S0, Set),
  S2 = crypto:hash_update(S1, K),
  crypto:hash_final(S2).

enc_key(Key) when is_integer(Key) ->
  <<?AS_BYTES_INTEGER:8, Key:64/big-signed-integer>>;
enc_key(Key) when is_float(Key) ->
  <<?AS_BYTES_DOUBLE:8, Key:64/big-signed-float>>;
enc_key(Key) when is_list(Key) ->
  Data = list_to_binary(Key),
  <<?AS_BYTES_STRING:8, Data/binary>>;
enc_key(Key) when is_binary(Key) ->
  <<?AS_BYTES_BLOB:8, Key/binary>>;
enc_key(Key) ->
  {error, {invalid_key_type, Key}}.

enc_key_digest( % corresponds to as_command_write_key, in as_command.c
    Namespace_str, Set_str, Key_digest) ->
  Enc_ns = enc_ltv(?AS_FIELD_NAMESPACE, Namespace_str),
  Enc_set = enc_ltv(?AS_FIELD_SETNAME, Set_str),
  Enc_key_digest = enc_ltv(?AS_FIELD_DIGEST, Key_digest),
  <<Enc_ns/binary,Enc_set/binary,Enc_key_digest/binary>>.

dec_key_digest(Data) ->
  case dec_ltv(1, Data) of
    need_more -> need_more;
    {ok, [{?AS_FIELD_NAMESPACE, V_ns}], Data1} ->
      case dec_ltv(1, Data1) of
        need_more -> need_more;
        {ok, [{?AS_FIELD_SETNAME, V_set}], Data2} ->
          case dec_ltv(1, Data2) of
            need_more -> need_more;
            {ok, [{?AS_FIELD_DIGEST, V_digest}], Rest} ->
              Decoded = {binary_to_list(V_ns), binary_to_list(V_set), V_digest},
              {ok, Decoded, Rest};
            Err3 -> {error, {expected_key_digest_but_decoded, Err3}}
          end;
        Err2 -> {error, {expected_set_name_but_decoded, Err2}}
      end;
    Err1 -> {error, {expected_namespace_but_decoded, Err1}}
  end.

%% Key-specific. End

%% Protocol encoders/decoders
enc_admin_pkt(Data) ->
  enc_proto(?AS_ADMIN_MESSAGE_TYPE, Data).

dec_admin_pkt(Data) ->
  dec_proto(?AS_ADMIN_MESSAGE_TYPE, Data).

enc_message_pkt(Data) ->
  enc_proto(?AS_MESSAGE_TYPE, Data).

dec_message_pkt(Data) ->
  dec_proto(?AS_MESSAGE_TYPE, Data).

enc_message_type_header( % corresponds to as_command_write_header_write
    Result_code,
    N_fields,
    N_bins,
    % see details in Note below
    Ttl, % in seconds
    % timeout to be sent to server for single record transactions
    % see details in Note below
    Timeout, % in milliseconds
    Read_attr,
    Write_attr,
    Info_attr,
    Generation, % uint32_t gen
    Unused
) ->
%%  #as_msg layout
  <<22:8/unsigned-integer, % 22 bytes in this header
    Read_attr:8/unsigned-integer,
    Write_attr:8/unsigned-integer,
    Info_attr:8/unsigned-integer,
    Unused:8/unsigned-integer,
    Result_code:8/unsigned-integer,
    Generation:32/big-unsigned-integer,
    Ttl:32/big-unsigned-integer,
    Timeout:32/big-unsigned-integer,
    N_fields:16/big-unsigned-integer,
    N_bins:16/big-unsigned-integer>>.

%%  #as_msg layout
dec_message_type_header(<<22:8/unsigned-integer,
  Read_attr:8/unsigned-integer,
  Write_attr:8/unsigned-integer,
  Info_attr:8/unsigned-integer,
  Unused:8,
  Result_code:8,
  Generation:32/big-unsigned-integer,
  Ttl:32/big-unsigned-integer,
  Timeout:32/big-unsigned-integer,
  N_fields:16/big-unsigned-integer,
  N_bins:16/big-unsigned-integer, Rest/binary>>) ->
  Decoded = #aspike_message_type_header{
    result_code = Result_code,
    n_fields = N_fields, n_bins = N_bins,
    ttl = Ttl, timeout = Timeout,
    read_attr = Read_attr, write_attr = Write_attr, info_attr = Info_attr,
    generation = Generation, unused = Unused},
  {ok, Decoded, Rest};
dec_message_type_header(<<_/binary>>) ->
  need_more.

enc_proto(Type, Data) ->
  enc_proto(?AS_PROTO_VERSION, Type, Data).

enc_proto(Version, Type, Data) ->
  <<Version:8/unsigned-integer,
    Type:8/unsigned-integer,
    (size(Data)):48/big-unsigned-integer,
    Data/binary>>.

dec_proto(Type, Data) ->
  case dec_proto(Data) of
    need_more -> need_more;
    {ok, {?AS_PROTO_VERSION, Type, _Data1}, _Rest} = Decoded -> Decoded;
    {ok, {?AS_PROTO_VERSION, Type1, _Data1}, _Rest} ->
      {error, {expected_typed, Type, decoded_type, Type1}};
    {ok, {Version, _Type1, _Data1}, _Rest} ->
      {error, {expected_version, ?AS_PROTO_VERSION, decoded_version, Version}}
  end.

dec_proto(<<Version:8/unsigned-integer,
  Type:8/unsigned-integer,
  Sz:48/big-unsigned-integer,
  Data:Sz/binary, Rest/binary>>) ->
  Decoded = {Version, Type, Data},
  {ok, Decoded, Rest};
dec_proto(_Data) ->
  need_more.

%% Protocol encoders/decoders. End

%% Utils

%% lv - Len-Value encoding
enc_lv(<<_/binary>> = Data) ->
  <<(size(Data)):32/big-unsigned-integer, Data/binary>>;
enc_lv(Data) ->
  enc_lv(list_to_binary(Data)).

dec_lv(N, Data) ->
  dec_lv(N, Data, []).

dec_lv(0, Rest, Acc) ->
  {ok, lists:reverse(Acc), Rest};
dec_lv(N,
    <<Len:32/big-unsigned-integer,
      Value:Len/binary, Rest/binary>>,
    Acc) ->
  dec_lv(N-1, Rest, [Value|Acc]);
dec_lv(_N, _Rest, _Acc) ->
  need_more.

%% ltv - Len-Tag-Value encoding
enc_ltv(T, <<_/binary>> = Data) ->
  <<(size(Data)+1):32/big-unsigned-integer,
    T:8/unsigned-integer, Data/binary>>;
enc_ltv(T, Data) ->
  enc_ltv(T, list_to_binary(Data)).

dec_ltv(N, Data) ->
  dec_ltv(N, Data, []).

dec_ltv(0, Rest, Acc) ->
  {ok, Acc, Rest};
dec_ltv(N,
    <<Len:32/big-unsigned-integer,
      Tag:8/unsigned-integer,
      Value:(Len-1)/binary, Rest/binary>>,
    Acc) ->
  dec_ltv(N-1, Rest, [{Tag, Value}|Acc]);
dec_ltv(_N, _Rest, _Acc) ->
  need_more.

to_typed_enc_value(undefined) ->
  {?AS_BYTES_UNDEF, <<>>};
to_typed_enc_value(true) ->
  {?AS_BYTES_BOOL, <<1:8>>};
to_typed_enc_value(false) ->
  {?AS_BYTES_BOOL, <<0:8>>};
to_typed_enc_value(V) when is_integer(V) ->
  {?AS_BYTES_INTEGER, <<V:64/big-integer>>};
to_typed_enc_value(V) when is_float(V) ->
  {?AS_BYTES_DOUBLE, <<V:64/big-float>>};
to_typed_enc_value(V) when is_list(V) ->
  {?AS_BYTES_STRING, list_to_binary(V)};
to_typed_enc_value(V) when is_binary(V) ->
  {?AS_BYTES_BLOB, V};
to_typed_enc_value(V) ->
  {error, {type_not_supported, V}}.

from_typed_enc_value({?AS_BYTES_UNDEF, <<>>}) -> undefined;
from_typed_enc_value({?AS_BYTES_BOOL, <<1:8>>}) -> true;
from_typed_enc_value({?AS_BYTES_BOOL, <<0:8>>}) -> false;
from_typed_enc_value({?AS_BYTES_INTEGER, <<V:64/big-integer>>}) -> V;
from_typed_enc_value({?AS_BYTES_DOUBLE, <<V:64/big-float>>}) -> V;
from_typed_enc_value({?AS_BYTES_STRING, V}) -> binary_to_list(V);
from_typed_enc_value({?AS_BYTES_BLOB, V}) -> V;
from_typed_enc_value({T, V}) ->
  {error, {type_not_supported, T, V}}.

%% Utils. End

%% Response decoder for 'shackle client' handle_data/2
dec_responses(Data) ->
  dec_responses(Data, []).

dec_responses(
    <<Version:8,
      Type:8,
      Sz:48/big-unsigned-integer,
      Header_sz:8, Info1:8, Info2:8, Info3:8, Unused:8,
      Result_code:8,
      Generation:32/big-unsigned-integer,
      Record_ttl:32/big-unsigned-integer,
      Transaction_ttl:32/big-unsigned-integer,
      N_fields:16/big-unsigned-integer,
      N_ops:16/big-unsigned-integer,
%%      Fields_and_ops:(Sz-Header_sz)/binary, % Header_sz should be 22 bytes - the header size
      Fields_and_ops:(Sz-22)/binary, % Header_sz should be 22 bytes - the header size
      Rest/binary>> = _Data,
    Acc) ->
  case dec_lv(N_fields, Fields_and_ops) of
    need_more ->
      {error, {failed_to_decode_fields, N_fields, Fields_and_ops}};
    {ok, Fields, Data_for_ops} ->
      case dec_ops(N_ops, Data_for_ops) of
        need_more ->
          {error, {failed_to_decode_ops, N_ops, Data_for_ops}};
        {ok, Ops, _Rest} ->
          Decoded = {#as_proto{version = Version, type = Type, sz = Sz},
            #as_msg{header_sz = Header_sz,
              info1 = Info1, info2 = Info2, info3 = Info3, unused = Unused,
              result_code = Result_code, generation = Generation,
              record_ttl = Record_ttl, transaction_ttl = Transaction_ttl,
              n_fields = N_fields, n_ops = N_ops},
            Fields, Ops},
          dec_responses(Rest, [{ok, Decoded}|Acc])
      end
  end;
dec_responses(Data, Acc) ->
  {lists:reverse(Acc), Data}.
%%  Acc is NOT reversed.
%%  Acc will be reversed when Reply_id will be attached to each element
%%  {Acc, Data}.

%% Response decoder for 'shackle client' handle_data/2. End

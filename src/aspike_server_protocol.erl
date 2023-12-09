-module(aspike_server_protocol).
-include("../include/aspike_protocol.hrl").
-include("../include/aspike_status.hrl").

%%
%% Aerospike server emulator
%%

-export([
  dec_request/1,
  enc_response/1
]).

dec_request(<<?AS_PROTO_VERSION:8, ?AS_ADMIN_MESSAGE_TYPE:8,
  _/binary>> = Data) ->
  case aspike_protocol:dec_login_request(Data) of
    need_more -> need_more;
    {error, Reason} -> {error, {login_request, Reason}};
    {ok, Decoded, Rest} -> {ok, {login_request, Decoded}, Rest}
  end;

dec_request(<<?AS_PROTO_VERSION:8, ?AS_MESSAGE_TYPE:8,
  _/binary>> = Data) ->
  case aspike_protocol:dec_message_pkt(Data) of
    need_more -> need_more;
    {error, _Reason} = Err -> Err;
    {ok, {_Version, _Type, Header_and_else}, _Rest1} ->
      {ok, H, _Rest2} = aspike_protocol:dec_message_type_header(Header_and_else),
      case message_type_request_type(H) of
        undefined -> {error, unrecognized_message_type_request};
        put ->
          case aspike_protocol:dec_put_request(Data) of
            need_more -> need_more;
            {error, Reason} -> {error, {put_request, Reason}};
            {ok, Decoded, Rest} -> {ok, {put_request, Decoded}, Rest}
          end;
        get ->
          case aspike_protocol:dec_get_request(Data) of
            need_more -> need_more;
            {error, Reason} -> {error, {get_request, Reason}};
            {ok, Decoded, Rest} -> {ok, {get_request, Decoded}, Rest}
          end;
        remove ->
          case aspike_protocol:dec_remove_request(Data) of
            need_more -> need_more;
            {error, Reason} -> {error, {remove_request, Reason}};
            {ok, Decoded, Rest} -> {ok, {remove_request, Decoded}, Rest}
          end;
        exists ->
          case aspike_protocol:dec_exists_request(Data) of
            need_more -> need_more;
            {error, Reason} -> {error, {exists_request, Reason}};
            {ok, Decoded, Rest} -> {ok, {exists_request, Decoded}, Rest}
          end
      end
  end;

dec_request(<<>>) ->
  need_more;
dec_request(<<?AS_PROTO_VERSION:8>>) ->
  need_more;

dec_request(Data) ->
  {error, {unknown_request, Data}}.

enc_response({login_response, no_password}) ->
  aspike_protocol:enc_login_response(?AEROSPIKE_INVALID_CREDENTIAL, []);
enc_response({login_response, wrong_password}) ->
  aspike_protocol:enc_login_response(?AEROSPIKE_INVALID_CREDENTIAL, []);
enc_response({login_response, no_user}) ->
  aspike_protocol:enc_login_response(?AEROSPIKE_INVALID_USER, []);
enc_response({login_response, unknown_user}) ->
  aspike_protocol:enc_login_response(?AEROSPIKE_INVALID_USER, []);
enc_response({login_response, #{?SESSION_TTL := Ttl, ?SESSION_TOKEN := Token}}) ->
  aspike_protocol:enc_login_response(?AEROSPIKE_OK, [{session_token, Token}, {session_ttl, Ttl}]);

enc_response({put_response, ok}) ->
  aspike_protocol:enc_put_response(?AEROSPIKE_OK);

enc_response({get_response, Bins}) ->
  aspike_protocol:enc_get_response(?AEROSPIKE_OK, [], Bins);

enc_response({remove_response, ok}) ->
  aspike_protocol:enc_remove_response(?AEROSPIKE_OK);

enc_response({remove_response, record_not_found}) ->
  aspike_protocol:enc_remove_response(?AEROSPIKE_ERR_RECORD_NOT_FOUND);

enc_response({exists_response, ok}) ->
  aspike_protocol:enc_exists_response(?AEROSPIKE_OK);

enc_response({exists_response, record_not_found}) ->
  aspike_protocol:enc_exists_response(?AEROSPIKE_ERR_RECORD_NOT_FOUND);

enc_response(X) ->
  {error, {unknown_response, X}}.

message_type_request_type(#aspike_message_type_header{
  write_attr = ?AS_MSG_INFO2_WRITE}) ->
  put;
message_type_request_type(#aspike_message_type_header{
  read_attr = ?AS_MSG_INFO1_READ}) ->
  get;
message_type_request_type(#aspike_message_type_header{
  read_attr = (?AS_MSG_INFO1_READ bor ?AS_MSG_INFO1_GET_ALL)}) ->
  get;
message_type_request_type(#aspike_message_type_header{
  write_attr = (?AS_MSG_INFO2_WRITE bor ?AS_MSG_INFO2_DELETE)}) ->
  remove;
message_type_request_type(#aspike_message_type_header{
  read_attr = (?AS_MSG_INFO1_READ bor ?AS_MSG_INFO1_GET_NOBINDATA)}) ->
  exists;
message_type_request_type(_) -> undefined.

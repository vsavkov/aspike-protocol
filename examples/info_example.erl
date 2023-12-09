-module(info_example).

%% API
-export([
  info/6
]).

info(Address, Port, User, Encrypted_password, Names, Timeout) ->
  case aspike_protocol:open_session(Address, Port, User, Encrypted_password) of
    {error, Reason} ->
      {error, {Reason, info, Address, Port, User}};
    {ok, #{socket := Socket} = Session} ->
      Encoded = aspike_protocol:enc_info_request(Names),
      ok = gen_tcp:send(Socket, Encoded),
      case aspike_protocol:receive_response_info(Socket, Timeout) of
        {error, _Reason} = Err ->
          aspike_protocol:close_session(Session),
          Err;
        Response ->
          aspike_protocol:close_session(Session),
          case aspike_protocol:dec_info_response(Response) of
            need_more ->
              {error, <<"Not enough data to decode response">>};
            {error, _Reason} = Err -> Err;
            {ok, Decoded, _Rest} ->
              Decoded
          end
      end
  end.

-module(exists_example).

%% API
-export([
  exists/7
]).

exists(Address, Port, User, Encrypted_password, Namespace, Set, Key) ->
  case aspike_protocol:open_session(Address, Port, User, Encrypted_password) of
    {error, Reason} ->
      {error, {Reason, put, Address, Port, User}};
    {ok, #{socket := Socket} = Session} ->
      Key_digest = aspike_protocol:digest(Set, Key),
      Encoded = aspike_protocol:enc_exists_request(Namespace, Set, Key_digest),
      ok = gen_tcp:send(Socket, Encoded),
      case aspike_protocol:receive_response_message(Socket, 1000) of
        {error, _Reason} = Err ->
          aspike_protocol:close_session(Session),
          Err;
        Response ->
          aspike_protocol:close_session(Session),
          case aspike_protocol:dec_exists_response(Response) of
            need_more ->
              {error, <<"Not enough data to decode response">>};
            {error, _Reason} = Err -> Err;
            {ok, Decoded, _Rest} ->
              Result_code = Decoded,
              aspike_status:status(Result_code)
          end
      end
  end.

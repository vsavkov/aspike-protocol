-module(get_example).

%% API
-export([
  get/8
]).

get(Address, Port, User, Encrypted_password, Namespace, Set, Key, Bins) ->
  case aspike_protocol:open_session(Address, Port, User, Encrypted_password) of
    {error, Reason} ->
      {error, {Reason, put, Address, Port, User}};
    {ok, #{socket := Socket} = Session} ->
      Key_digest = aspike_protocol:digest(Set, Key),
      Encoded = aspike_protocol:enc_get_request(Namespace, Set, Key_digest, Bins),
      ok = gen_tcp:send(Socket, Encoded),
      case aspike_protocol:receive_response_message(Socket, 1000) of
        {error, _Reason} = Err ->
          aspike_protocol:close_session(Session),
          Err;
        Response ->
          aspike_protocol:close_session(Session),
          case aspike_protocol:dec_get_response(Response) of
            need_more ->
              {error, <<"Not enough data to decode response">>};
            {error, _Reason} = Err -> Err;
            {ok, Decoded, _Rest} ->
              {Result_code, Fields, Ops} = Decoded,
              Status = aspike_status:status(Result_code),
              io:format("~p~n", [Status]),
              io:format("~p, ~p~n", [Fields, Ops])
          end
      end
  end.

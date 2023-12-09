-module(login_example).

%% API
-export([login/4]).

login(Address, Port, User, Password) ->
  % NOTE: aspike_blowfish:crypt could take 2-5 seconds
  io:format("[login] encrypting password (could take 2-5 seconds)..."),
  Encrypted_password = aspike_blowfish:crypt(Password),
  io:format(" ok~n"),
  case aspike_protocol:open_session(Address, Port, User, Encrypted_password) of
    {error, Reason} ->
      io:format("~p:~p, User: ~p: failed to login: ~p~n", [Address, Port, User, Reason]);
    {ok, #{address := A, port := P, user := U, socket:= _S} = Session} ->
      io:format("~p:~p, User: ~p: logged in.~n", [A, P, U]),
      aspike_protocol:close_session(Session)
  end.

-module(aspike_util).

%% API
-export([
  binary_to_integer/1,
  bitmap_size/1,
  base64_encoding_len/1,
  to_term/1
]).

binary_to_integer(Data) when is_binary(Data) ->
  try erlang:binary_to_integer(Data) of
    V -> {ok, V}
  catch error:badarg ->
    {error, {not_an_integer, Data}}
  end;
binary_to_integer(Data) ->
  {error, {not_a_binary, Data}}.

%% Size of bit map, in bytes, that is needed to map N_partitions partitions
bitmap_size(N_partitions) ->
  trunc((N_partitions + 7) / 8).

%% Length, in bytes, that is needed to make base64 encoding of N_bytes
base64_encoding_len(N_bytes) ->
  trunc((N_bytes+2)/3) bsl 2.

%% Convert a string representation of a list to Erlang term
to_term(Str) ->
  tokenized_to_term(tokenize(Str)).

tokenized_to_term(Ts) ->
  tokenized_to_term(Ts, []).

-define(CHAR_COMMA, $,).
-define(CHAR_LSB, $[).
-define(CHAR_RSB, $]).

tokenized_to_term([], [Stack]) ->
  Stack;

tokenized_to_term([sb_close|T], Stack) ->
  Folded = fold_sb(Stack, []),
  tokenized_to_term(T, Folded);
tokenized_to_term([quote_close|T], Stack) ->
  Folded = fold_quote(Stack, []),
  tokenized_to_term(T, Folded);
tokenized_to_term([?CHAR_COMMA|T], Stack) ->
  tokenized_to_term(T, Stack);
tokenized_to_term([H|T], Stack) ->
  tokenized_to_term(T, [H|Stack]).

fold_sb([], []) ->
  [];
fold_sb([], _Acc) ->
  {error, missing_open_square_bracket};
fold_sb([sb_open|T], Acc) ->
  [Acc|T];
fold_sb([H|T], Acc) ->
  fold_sb(T, [H|Acc]).

fold_quote([], []) ->
  [];
fold_quote([], _Acc) ->
  {error, missing_open_quote};
fold_quote([quote_open|T], Acc) ->
  [Acc|T];
fold_quote([H|T], Acc) ->
  fold_quote(T, [H|Acc]).

quote_open(Acc) ->
  [quote_open|Acc].
quote_close(Acc) ->
  [quote_close|Acc].
quote_open_close(Acc) ->
  quote_close(quote_open(Acc)).

sb_open(Acc) ->
  [sb_open|Acc].
sb_close(Acc) ->
  [sb_close|Acc].

tokenize([?CHAR_LSB|_]=Str) ->
  tokenize(Str, []);
tokenize(Str) ->
  tokenize(lists:append(["[", Str, "]"]), []).

tokenize([], Acc) ->
  lists:reverse(Acc);

tokenize([?CHAR_LSB|T], [?CHAR_COMMA|_]=Acc) ->
  tokenize(T, sb_open(Acc));
tokenize([?CHAR_LSB|T], [sb_open|_]=Acc) ->
  tokenize(T, sb_open(Acc));
tokenize([?CHAR_LSB|T], Acc) ->
  tokenize(T, sb_open(Acc));
tokenize([?CHAR_COMMA|T], [sb_close|_]=Acc) ->
  tokenize(T, [?CHAR_COMMA|Acc]);
tokenize([?CHAR_RSB|T], [?CHAR_COMMA|_]=Acc) ->
  tokenize(T, sb_close(quote_open_close(Acc)));
tokenize([?CHAR_COMMA|T], [sb_open|_]=Acc) ->
  tokenize(T, [?CHAR_COMMA|quote_open_close(Acc)]);
tokenize([?CHAR_COMMA|T], [?CHAR_COMMA|_]=Acc) ->
  tokenize(T, [?CHAR_COMMA|quote_open_close(Acc)]);
tokenize([?CHAR_COMMA|T], Acc) ->
  tokenize(T, [?CHAR_COMMA|quote_close(Acc)]);
tokenize([H|T], [?CHAR_COMMA|_]=Acc) ->
  tokenize(T, [H|quote_open(Acc)]);

tokenize([?CHAR_RSB|T], [sb_open|_]=Acc) ->
  tokenize(T, sb_close(Acc));
tokenize([?CHAR_RSB|T], [sb_close|_]=Acc) ->
  tokenize(T, sb_close(Acc));
tokenize([H|T], [sb_open|_]=Acc) ->
  tokenize(T, [H|quote_open(Acc)]);
tokenize([?CHAR_RSB|T], Acc) ->
  tokenize(T, sb_close(quote_close(Acc)));

tokenize([H|T], Acc) ->
  tokenize(T, [H|Acc]).

%% Convert a string representation of a list to Erlang term. End

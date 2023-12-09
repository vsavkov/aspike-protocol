-module(aspike_blowfish).

%%
%% Aerospike-specific Blowfish implementation
%%

%% API
-export([
  crypt/1
]).

%% utils
-export([
  hex/1,
  hex_output/1
]).

%% tests
-export([
  test_all/0
]).

%%#define BCRYPT_SALT "$2a$10$7EqJtq98hPqEX7fNZaFWoO"
-define(BCRYPT_SALT, <<"$2a$10$7EqJtq98hPqEX7fNZaFWoO">>).
%% Number of Blowfish rounds
-define(BF_N, 16).

crypt(Data) ->
  bf_crypt(Data, ?BCRYPT_SALT).

%%  crypt_blowfish.c
%%  char *_crypt_blowfish_rn(const char *key, const char *setting, char *output, int size);

bf_crypt(Key, Setting) ->
  Count = bf_count(Setting),
  Salt = bf_salt(Setting),
  {Expanded, Ctx_P} = bf_set_key_using_setting(Key, Setting),
  Ctx_S = bf_init_state_S(),
  {Ctx_P1, L, R} = bf_ctx_P(Salt, Ctx_S, Ctx_P),
  {Ctx_S1, _L1, _R1} = bf_ctx_S(Salt, L, R, Ctx_P1, Ctx_S),
  S = salt_4_elems(Salt),
  {Ctx_P2, Ctx_S2} = bf_ctx_using_Salt_and_Expanded(S, Expanded, Count, Ctx_P1, Ctx_S1),
  Magic_output = bf_magic_to_output(6, 0, Ctx_P2, Ctx_S2, <<>>),
  Encoded_magic_output = bf_encode_magic_output(Magic_output),
  Final_setting = bf_setting_to_final(Setting),
  <<Final_setting/binary, Encoded_magic_output/binary>>.

bf_count(Setting) ->
  <<_:4/binary, D1:8/unsigned-integer, D2:8/unsigned-integer, _/binary>> = Setting,
  1 bsl ((D1 - $0) * 10 + (D2 - $0)).

%% Section. Salt related
bf_salt(Setting) ->
  <<_:7/binary, Settings_for_salt/binary>> = Setting,
  Salt = bf_decode(Settings_for_salt),
  Salt_swapped = bf_swap4(Salt),
  Salt_swapped.

salt_4_elems(Salt) ->
  <<Bin:16/binary, _T/binary>> = Salt,
  Bin.

salt_elem(Salt, 0) ->
  <<L:32/little-unsigned-integer, R:32/little-unsigned-integer, _T/binary>> = Salt,
  {L, R};
salt_elem(Salt, 2) ->
  <<_:8/binary, L:32/little-unsigned-integer, R:32/little-unsigned-integer>> = Salt,
  {L, R};
salt_elem(_Salt, X) ->
  {error, {out_of_range, X}}.

%% Section. Salt related. End

%% Section. Expand key using setting
bf_set_key_using_setting(Key, Setting) ->
  <<_:2/binary, Setting_for_flags:8/unsigned-integer,_/binary>> = Setting,
  Flags = bf_flags_by_subtype(Setting_for_flags - $a),
  {Expanded, Initial} = bf_set_key_using_flags(Key, Flags),
  {list_of_4_byte_ints_to_binary(Expanded, []),
    list_of_4_byte_ints_to_binary(Initial, [])}.

bf_set_key_using_flags(Key, Flags) ->
  Bug = Flags band 1,
  Safety = (Flags band 2) bsl 15,
  Sign = Diff = 0,
  Key_for_expanded_initial = expand_list_with_trailing_zero(Key, (?BF_N+2)*4),
  {Sign1, Diff1, L_expanded, L_initial} =
    bf_expanded_initial(?BF_N+2, 0, Key_for_expanded_initial,
      Bug, Sign, Diff, {[], []}),
  Diff2 = Diff1 bor (Diff1 bsr 16),
  Diff3 = Diff2 band 16#FFFF,
  Diff4 = Diff3 + 16#FFFF,
  Sign2 = Sign1 bsl 9,
  Sign3 = Sign2 band ((bnot Diff4) band Safety),
  [H|T] = L_initial,
  {L_expanded, [(H bxor Sign3)|T]}.

bf_expanded_initial(0, _I, _Key, _Bug, Sign, Diff,
    {Acc_expanded, Acc_initial}) ->
  {Sign, Diff, lists:reverse(Acc_expanded), lists:reverse(Acc_initial)};
bf_expanded_initial(N, I, Key, Bug, Sign, Diff,
    {Acc_expanded, Acc_initial}) ->
  {[C1, C2, C3, C4], Key1} = lists:split(4, Key),
  {Sign1, Tmp0, Tmp1} = bf_mix_4_chars_from_key(I, Sign, C1, C2, C3, C4),
  Diff1 = Diff bor (Tmp0 bxor Tmp1),
  {Expanded, Initial} = to_expanded_initial(Bug, bf_init_state_P(I), Tmp0, Tmp1),
  bf_expanded_initial(N-1, I+1, Key1, Bug, Sign1, Diff1,
    {[Expanded|Acc_expanded], [Initial|Acc_initial]}).

to_expanded_initial(0 = _Bug, BF_init_state_P, Tmp0, _Tmp1) ->
  {Tmp0, BF_init_state_P bxor Tmp0};
to_expanded_initial(1 = _Bug, BF_init_state_P, _Tmp0, Tmp1) ->
  {Tmp1, BF_init_state_P bxor Tmp1}.

list_of_4_byte_ints_to_binary([], Acc) ->
  list_to_binary(lists:reverse(Acc));
list_of_4_byte_ints_to_binary([H|T], Acc) ->
  list_of_4_byte_ints_to_binary(T, [<<H:32/little-unsigned-integer>>|Acc]).

%% NOTE: _I - index of 4-character block in the Key,
%% for debugging/tracing purpose only.
bf_mix_4_chars_from_key(_I, Sign, Ch0, Ch1, Ch2, Ch3) ->
  Tmp0_0 = 0, Tmp1_0 = 0,
  {Tmp0_1, Tmp1_1} = bf_mix_1_char_from_key(Tmp0_0, Tmp1_0, Ch0),
  {Tmp0_2, Tmp1_2} = bf_mix_1_char_from_key(Tmp0_1, Tmp1_1, Ch1),
  Sign2 = Sign bor (Tmp1_2 band 16#80),
  {Tmp0_3, Tmp1_3} = bf_mix_1_char_from_key(Tmp0_2, Tmp1_2, Ch2),
  Sign3 = Sign2 bor (Tmp1_3 band 16#80),
  {Tmp0_4, Tmp1_4} = bf_mix_1_char_from_key(Tmp0_3, Tmp1_3, Ch3),
  Sign4 = Sign3 bor (Tmp1_4 band 16#80),
  {Sign4, Tmp0_4, Tmp1_4}.

bf_mix_1_char_from_key(Tmp0, Tmp1, Ch) ->
  {(Tmp0 bsl 8) bor Ch,
    (Tmp1 bsl 8) bor to_4_byte_int_with_sign_extension(Ch)}.

to_4_byte_int_with_sign_extension(Ch) ->
  case Ch band 16#80 of
    16#80 -> 16#FFFFFF00 bor Ch;
    _ -> Ch
  end.

%% Section. Expand key using setting. End

%% Section. P-array (subkeys) and S-boxes (substitution-boxes)
bf_ctx_P(Salt, Ctx_S, Ctx_P) ->
  bf_ctx_P(?BF_N+2, 0, 0, 0, Salt, Ctx_S, Ctx_P).

bf_ctx_P(0, _I, L, R, _Salt, _Ctx_S, Ctx_P) ->
  {Ctx_P, L, R};
bf_ctx_P(N, I, L, R, Salt, Ctx_S, Ctx_P) ->
  {L_salt, R_salt} = salt_elem(Salt, (I band 2)),
  L1 = L bxor L_salt,
  R1 = R bxor R_salt,
  {L2, R2} = bf_encrypt(L1, R1, Ctx_S, Ctx_P),
  Ctx_P1 = bf_ctx_P_update(Ctx_P, I, L2, R2),
  bf_ctx_P(N-2, I+2, L2, R2, Salt, Ctx_S, Ctx_P1).

bf_ctx_P_update(Ctx_P, I, L, R) ->
  <<Before_I:(I bsl 2)/binary, _Elem_I:4/binary, _Elem_I_plus_1:4/binary, After_I_plus_1/binary>> = Ctx_P,
  <<Before_I/binary,
    L:32/little-unsigned-integer, R:32/little-unsigned-integer,
    After_I_plus_1/binary>>.

bf_ctx_P_get_first_and_nth(Ctx_P, N) ->
  <<First:32/little-unsigned-integer,
    _:((N-2) bsl 2)/binary,
    Nth:32/little-unsigned-integer, _/binary>> = Ctx_P,
  {First, Nth}.

bf_ctx_P_get(Ctx_P, I) ->
  <<_Before_I:(I bsl 2)/binary,
    Elem_I:32/little-unsigned-integer,
    _After_I/binary>> = Ctx_P,
  Elem_I.

bf_ctx_S(Salt, L, R, Ctx_P, Ctx_S) ->
  bf_ctx_S(1024, 0, L, R, Salt, Ctx_P, Ctx_S).

bf_ctx_S(0, _I, L, R, _Salt, _Ctx_P, Ctx_S) ->
  {Ctx_S, L, R};
bf_ctx_S(N, I, L, R, Salt, Ctx_P, Ctx_S) ->

  {L_salt, R_salt} = salt_elem(Salt, ((?BF_N+2) band 3)),
  L1 = L bxor L_salt,
  R1 = R bxor R_salt,
  {L2, R2} = bf_encrypt(L1, R1, Ctx_S, Ctx_P),
  Ctx_S1 = bf_ctx_S_update(Ctx_S, I, L2, R2),

  {L_salt1, R_salt1} = salt_elem(Salt, ((?BF_N+4) band 3)),
  L3 = L2 bxor L_salt1,
  R3 = R2 bxor R_salt1,
  {L4, R4} = bf_encrypt(L3, R3, Ctx_S1, Ctx_P),
  Ctx_S2 = bf_ctx_S_update(Ctx_S1, I+2, L4, R4),

  bf_ctx_S(N-4, I+4, L4, R4, Salt, Ctx_P, Ctx_S2).

bf_ctx_S_update(Ctx_S, I, L, R) ->
  <<Before_I:(I bsl 2)/binary, _Elem_I:4/binary, _Elem_I_plus_1:4/binary, After_I_plus_1/binary>> = Ctx_S,
  <<Before_I/binary,
    L:32/little-unsigned-integer, R:32/little-unsigned-integer,
    After_I_plus_1/binary>>.

bf_ctx_S_get(Ctx_S, S0, S1, S2, S3) ->
  N0 = S0 bsl 2, % S0 * 4
  N1 = (1024 + (S1 bsl 2)) - N0 - 4,
  N2 = (2048 + (S2 bsl 2)) - N0 - 4 - N1 - 4,
  N3 = (3072 + (S3 bsl 2)) - N0 - 4 - N1 - 4 - N2 - 4,
  <<_:N0/binary, E0:32/little-unsigned-integer,
    _:N1/binary, E1:32/little-unsigned-integer,
    _:N2/binary, E2:32/little-unsigned-integer,
    _:N3/binary, E3:32/little-unsigned-integer,
    _/binary>>
    = Ctx_S,
  {E0, E1, E2, E3}.

bf_ctx_using_Salt_and_Expanded(_Salt, _Expanded, 0, Ctx_P, Ctx_S) ->
  {Ctx_P, Ctx_S};
bf_ctx_using_Salt_and_Expanded(Salt, Expanded, Count, Ctx_P, Ctx_S) ->
  Ctx_P1 = bf_ctx_using_Expanded(Expanded, Ctx_P),
  {Ctx_P2, Ctx_S1} = bf_ctx_using_Salt(Salt, Ctx_P1, Ctx_S),
  bf_ctx_using_Salt_and_Expanded(Salt, Expanded, Count-1, Ctx_P2, Ctx_S1).

bf_ctx_using_Expanded(Expanded, Ctx_P) ->
  bits_xor(Expanded, Ctx_P).

bf_ctx_using_Salt(Salt, Ctx_P, Ctx_S) ->
  {Ctx_P1, Ctx_S1} = bf_body(Ctx_P, Ctx_S),
  Ctx_P2 = bf_ctx_apply_Salt(?BF_N, 0, Salt, Ctx_P1),
  {_Ctx_P3, _Ctx_S2} = Ret = bf_body(Ctx_P2, Ctx_S1),
  Ret.

bf_ctx_apply_Salt(0, I, Salt, Ctx_P) ->
  {Prefix, Bin, Suffix} = bin_get(Ctx_P, I, 2),
  {_, Salt2, _} = bin_get(Salt, 0, 2),
  Salted = bits_xor(Bin, Salt2),
  <<Prefix/binary, Salted/binary, Suffix/binary>>;
bf_ctx_apply_Salt(N, I, Salt, Ctx_P) ->
  {Prefix, Bin, Suffix} = bin_get(Ctx_P, I, 4),
  Salted = bits_xor(Bin, Salt),
  Ctx_P1 = <<Prefix/binary, Salted/binary, Suffix/binary>>,
  bf_ctx_apply_Salt(N-4, I+4, Salt, Ctx_P1).

bf_body(Ctx_P, Ctx_S) ->
  {Ctx_P1, L1, R1} = bf_body_ctx_P(0, 0, Ctx_S, Ctx_P),
  {Ctx_S1, _L2, _R2} = bf_body_ctx_S(L1, R1, Ctx_P1, Ctx_S),
  {Ctx_P1, Ctx_S1}.

bf_body_ctx_P(L, R, Ctx_S, Ctx_P) ->
  bf_body_ctx_P(?BF_N+2, 0, L, R, Ctx_S, Ctx_P).

bf_body_ctx_P(0, _I, L, R, _Ctx_S, Ctx_P) ->
  {Ctx_P, L, R};
bf_body_ctx_P(N, I, L, R, Ctx_S, Ctx_P) ->
  {L1, R1} = bf_encrypt(L, R, Ctx_S, Ctx_P),
  Ctx_P1 = bf_ctx_P_update(Ctx_P, I, L1, R1),
  bf_body_ctx_P(N-2, I+2, L1, R1, Ctx_S, Ctx_P1).

bf_body_ctx_S(L, R, Ctx_P, Ctx_S) ->
  bf_body_ctx_S(1024, 0, L, R, Ctx_P, Ctx_S).

bf_body_ctx_S(0, _I, L, R, _Ctx_P, Ctx_S) ->
  {Ctx_S, L, R};
bf_body_ctx_S(N, I, L, R, Ctx_P, Ctx_S) ->
  {L1, R1} = bf_encrypt(L, R, Ctx_S, Ctx_P),
  Ctx_S1 = bf_ctx_S_update(Ctx_S, I, L1, R1),
  bf_body_ctx_S(N-2, I+2, L1, R1, Ctx_P, Ctx_S1).

%% Section. P-array (subkeys) and S-boxes (substitution-boxes). End

%% Section. Encrypt - major bits churning part
bf_encrypt_iterate(0, L, R, _Ctx_S, _Ctx_P) ->
  {L, R};
bf_encrypt_iterate(N, L, R, Ctx_S, Ctx_P) ->
  {L1, R1} = bf_encrypt(L, R, Ctx_S, Ctx_P),
  bf_encrypt_iterate(N-1, L1, R1, Ctx_S, Ctx_P).

bf_encrypt(L, R, Ctx_S, Ctx_P) ->
  {Ctx_P_0, Ctx_P_BF_N_plus_1} = bf_ctx_P_get_first_and_nth(Ctx_P, ?BF_N+2),
  {L1, R1} = bf_round_iterate(?BF_N, L bxor Ctx_P_0, R, Ctx_S, Ctx_P),
  {R1 bxor Ctx_P_BF_N_plus_1, L1}.

bf_round_iterate(N, L, R, Ctx_S, Ctx_P) ->
  bf_round_iterate(N, 0, L, R, Ctx_S, Ctx_P).

bf_round_iterate(0, _Count, L, R, _Ctx_S, _Ctx_P) ->
  {L, R};
bf_round_iterate(N, Count, L, R, Ctx_S, Ctx_P) ->
  R1 = bf_round(L, R, Count, Ctx_S, Ctx_P),
  bf_round_iterate(N-1, Count+1, R1, L, Ctx_S, Ctx_P).

bf_round(L, R, N, Ctx_S, Ctx_P) ->
  <<Tmp4:8/unsigned-integer,
    Tmp3:8/unsigned-integer,
    Tmp2:8/unsigned-integer,
    Tmp1:8/unsigned-integer>>
    = <<L:32/unsigned-integer>>,
  {S0, S1, Tmp2_S, Tmp1_S} = bf_ctx_S_get(Ctx_S, Tmp4, Tmp3, Tmp2, Tmp1),
  Tmp3_S = (S1 + S0) band 16#FFFFFFFF,
  Tmp3_S_xor_tmp2_S = Tmp3_S bxor Tmp2_S,
  Ctx_P_N_plus_1 = bf_ctx_P_get(Ctx_P, N+1),
  R_P = R bxor Ctx_P_N_plus_1,
  Tmp3_final = (Tmp3_S_xor_tmp2_S + Tmp1_S) band 16#FFFFFFFF,
  R_final = R_P bxor Tmp3_final,
  R_final.

%% Section. Encrypt - major bits churning part. End

%% Section. IV (magic) related
bf_magic_to_output(0, _I, _Ctx_P, _Ctx_S, Output) ->
  Output;
bf_magic_to_output(N, I, Ctx_P, Ctx_S, Output) ->
  L = bf_magic(I),
  R = bf_magic(I+1),
  {L1, R1} = bf_encrypt_iterate(64, L, R, Ctx_S, Ctx_P),
  bf_magic_to_output(N-2, I+2, Ctx_P, Ctx_S,
    <<Output/binary, L1:32/little-unsigned-integer, R1:32/little-unsigned-integer>>).

bf_encode_magic_output(Output) ->
  Swapped = bf_swap(Output, 4),
  bf_encode(Swapped, 23, <<>>).

%% Section. IV (magic) related. End

%% Extracting from initial setting for final output
bf_setting_to_final(Setting) ->
  <<H:(7 + 22 - 1)/binary, I:8/unsigned-integer, _/binary>> = Setting,
  I1 = bf_itoa64(bf_atoi64(I) band 16#30),
  <<H/binary, I1:8/unsigned-integer>>.

-dialyzer({nowarn_function, bf_encode/3}).
%% Integer-to-ASCII encoding
bf_encode(_Bin, 0, Acc) ->
  Acc;
bf_encode(Bin, Size, Acc) ->
  <<C1:8/unsigned-integer, T1/binary>> = Bin,
  D1 = bf_itoa64(C1 bsr 2),
  Size1 = Size - 1,
  C1_1 = (C1 band 16#03) bsl 4,
  case Size1 of
    0 ->
      D2 = bf_itoa64(C1_1),
      <<Acc/binary,
        D1:8/unsigned-integer, D2:8/unsigned-integer>>;
    _ ->
      <<C2:8/unsigned-integer, T2/binary>> = T1,
      C1_2 = C1_1 bor (C2 bsr 4),
      D3 = bf_itoa64(C1_2),
      Size2 = Size1 - 1,
      C1_3 = (C2 band 16#0f) bsl 2,
      case Size2 of
        0 ->
          D4 = bf_itoa64(C1_3),
          <<Acc/binary,
            D1:8/unsigned-integer, D3:8/unsigned-integer, D4:8/unsigned-integer>>;
        _ ->
          <<C2_1:8/unsigned-integer, T3/binary>> = T2,
          C1_4 = C1_3 bor (C2_1 bsr 6),
          D5 = bf_itoa64(C1_4),
          D6 = bf_itoa64(C2_1 band 16#3f),
          bf_encode(T3, Size2-1,
            <<Acc/binary, D1:8/unsigned-integer, D3:8/unsigned-integer,
              D5:8/unsigned-integer, D6:8/unsigned-integer>>)
      end
  end.

%% Section. Decode ASCII string to binary
bf_decode(Bin) ->
  case bf_decode_next_4_bytes(Bin) of
    {error, _} = Err1 -> Err1;
    {Bin1, T1} ->
      case bf_decode_next_4_bytes(T1) of
        {error, _} = Err2 -> Err2;
        {Bin2, T2} ->
          case bf_decode_next_4_bytes(T2) of
            {error, _} = Err3 -> Err3;
            {Bin3, T3} ->
              case bf_decode_next_4_bytes(T3) of
                {error, _} = Err4 -> Err4;
                {Bin4, T4} ->
                  case bf_decode_next_4_bytes(T4) of
                    {error, _} = Err5 -> Err5;
                    {Bin5, T5} ->
                      case bf_decode_next_4_bytes(T5) of
                        {error, _} = Err6 -> Err6;
                        {Bin6, _T6} ->
                          <<Bin1/binary, Bin2/binary, Bin3/binary,
                            Bin4/binary, Bin5/binary, Bin6/binary>>
                      end
                  end
              end
          end
      end
  end.

bf_decode_next_4_bytes(
    <<H1:8/unsigned-integer,
      H2:8/unsigned-integer,
      H3:8/unsigned-integer,
      H4:8/unsigned-integer,
      T/binary>>) ->
  case bf_atoi64(H1) of
    {error, _} = Err1 -> Err1;
    C1 ->
      case bf_atoi64(H2) of
        {error, _} = Err2 -> Err2;
        C2 ->
          case bf_atoi64(H3) of
            {error, _} = Err3 -> Err3;
            C3 ->
              case bf_atoi64(H4) of
                {error, _} = Err4 -> Err4;
                C4 ->
                  Mix_c1_c2 = (C1 bsl 2) bor ((C2 band 16#30) bsr 4),
                  Mix_c2_c3 = ((C2 band 16#0F) bsl 4) bor ((C3 band 16#3C) bsr 2),
                  Mix_c3_c4 = ((C3 band 16#03) bsl 6) bor C4,
                  {
                    <<Mix_c1_c2:8/unsigned-integer,
                      Mix_c2_c3:8/unsigned-integer,
                      Mix_c3_c4:8/unsigned-integer>>,
                    T}
              end
          end
      end
  end;
bf_decode_next_4_bytes(
    <<H1:8/unsigned-integer,
      H2:8/unsigned-integer,
      H3:8/unsigned-integer,
      T/binary>>) ->
  case bf_atoi64(H1) of
    {error, _} = Err1 -> Err1;
    C1 ->
      case bf_atoi64(H2) of
        {error, _} = Err2 -> Err2;
        C2 ->
          case bf_atoi64(H3) of
            {error, _} = Err3 -> Err3;
            C3 ->
              Mix_c1_c2 = (C1 bsl 2) bor ((C2 band 16#30) bsr 4),
              Mix_c2_c3 = ((C2 band 16#0F) bsl 4) bor ((C3 band 16#3C) bsr 2),
              {
                <<Mix_c1_c2:8/unsigned-integer,
                  Mix_c2_c3:8/unsigned-integer>>,
                T}
          end
      end
  end;
bf_decode_next_4_bytes(
    <<H1:8/unsigned-integer,
      H2:8/unsigned-integer,
      T/binary>>) ->
  case bf_atoi64(H1) of
    {error, _} = Err1 -> Err1;
    C1 ->
      case bf_atoi64(H2) of
        {error, _} = Err2 -> Err2;
        C2 ->
          Mix_c1_c2 = (C1 bsl 2) bor ((C2 band 16#30) bsr 4),
          {
            <<Mix_c1_c2:8/unsigned-integer>>,
            T}
      end
  end;
bf_decode_next_4_bytes(X) ->
  {error, {need_more_than_one_byte_in, X}}.

%% Section. Decode ASCII string to binary. End

%% Section. Misc utils
bin_get(B, I, N) ->
  <<Prefix:(I bsl 2)/binary, E:(N bsl 2)/binary, Suffix/binary>> = B,
  {Prefix, E, Suffix}.

bf_swap4(
    <<I1:32/native-unsigned-integer,
      I2:32/native-unsigned-integer,
      I3:32/native-unsigned-integer,
      I4:32/native-unsigned-integer>>) ->
  <<I1:32/big-unsigned-integer,
    I2:32/big-unsigned-integer,
    I3:32/big-unsigned-integer,
    I4:32/big-unsigned-integer>>.

bf_swap(Bin, Bytes_in_element) ->
  bf_swap(Bin, Bytes_in_element, <<>>).

bf_swap(<<>>, _Bytes_in_element, Acc) ->
  Acc;
bf_swap(Bin, Bytes_in_element, Acc) ->
  <<Element:Bytes_in_element/binary, T/binary>> = Bin,
  Swapped_element = bf_swap_element(Element),
  bf_swap(T, Bytes_in_element, <<Acc/binary, Swapped_element/binary>>).

bf_swap_element(Bin) ->
  binary:list_to_bin(lists:reverse(binary:bin_to_list(Bin))).

bits_xor(B1, B2) ->
  Bitsize = bit_size(B1),
  <<B1_bits:Bitsize>> = B1,
  <<B2_bits:Bitsize>> = B2,
  <<(B1_bits bxor B2_bits):Bitsize>>.

hex(V) -> integer_to_list(V, 16).

hex_output(Bin) ->
  Hex = binary:encode_hex(Bin),
  L = binary_to_list(Hex),
  hex_output(L, "").

hex_output([H1,H2], Acc) ->
  lists:append([Acc, [H1], [H2]]);
hex_output([H1,H2|R], Acc) ->
  hex_output(R, lists:append([Acc, [H1], [H2], [32]])).

expand_list(Xs, At_least) ->
  L = length(Xs),
  D = floor(At_least / L),
  M = case At_least rem L of
    0 -> D;
    _ -> D+1
  end,
  lists:append(lists:duplicate(M, Xs)).

expand_list_with_trailing_zero(Xs, At_least) ->
  Ys = lists:append([Xs, [16#0]]),
  expand_list(Ys, At_least).

%% Section. Misc utils. End

%%  static unsigned char BF_itoa64[64 + 1] =
%%  "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
%% Integer-to-ASCII encoding
bf_itoa64(0) -> $.;
bf_itoa64(1) -> $/;
bf_itoa64(2) -> $A;
bf_itoa64(3) -> $B;
bf_itoa64(4) -> $C;
bf_itoa64(5) -> $D;
bf_itoa64(6) -> $E;
bf_itoa64(7) -> $F;
bf_itoa64(8) -> $G;
bf_itoa64(9) -> $H;
bf_itoa64(10) -> $I;
bf_itoa64(11) -> $J;
bf_itoa64(12) -> $K;
bf_itoa64(13) -> $L;
bf_itoa64(14) -> $M;
bf_itoa64(15) -> $N;
bf_itoa64(16) -> $O;
bf_itoa64(17) -> $P;
bf_itoa64(18) -> $Q;
bf_itoa64(19) -> $R;
bf_itoa64(20) -> $S;
bf_itoa64(21) -> $T;
bf_itoa64(22) -> $U;
bf_itoa64(23) -> $V;
bf_itoa64(24) -> $W;
bf_itoa64(25) -> $X;
bf_itoa64(26) -> $Y;
bf_itoa64(27) -> $Z;
bf_itoa64(28) -> $a;
bf_itoa64(29) -> $b;
bf_itoa64(30) -> $c;
bf_itoa64(31) -> $d;
bf_itoa64(32) -> $e;
bf_itoa64(33) -> $f;
bf_itoa64(34) -> $g;
bf_itoa64(35) -> $h;
bf_itoa64(36) -> $i;
bf_itoa64(37) -> $j;
bf_itoa64(38) -> $k;
bf_itoa64(39) -> $l;
bf_itoa64(40) -> $m;
bf_itoa64(41) -> $n;
bf_itoa64(42) -> $o;
bf_itoa64(43) -> $p;
bf_itoa64(44) -> $q;
bf_itoa64(45) -> $r;
bf_itoa64(46) -> $s;
bf_itoa64(47) -> $t;
bf_itoa64(48) -> $u;
bf_itoa64(49) -> $v;
bf_itoa64(50) -> $w;
bf_itoa64(51) -> $x;
bf_itoa64(52) -> $y;
bf_itoa64(53) -> $z;
bf_itoa64(54) -> $0;
bf_itoa64(55) -> $1;
bf_itoa64(56) -> $2;
bf_itoa64(57) -> $3;
bf_itoa64(58) -> $4;
bf_itoa64(59) -> $5;
bf_itoa64(60) -> $6;
bf_itoa64(61) -> $7;
bf_itoa64(62) -> $8;
bf_itoa64(63) -> $9;
bf_itoa64(X) -> {error, {out_of_range, X}}.

%% see static unsigned char BF_atoi64[0x60] = {...}
%% ASCII-to-integer encoding
bf_atoi64(14+16#20) -> 0; % char '.' -> 0
bf_atoi64(15+16#20) -> 1;
bf_atoi64(16+16#20) -> 54;
bf_atoi64(17+16#20) -> 55;
bf_atoi64(18+16#20) -> 56;
bf_atoi64(19+16#20) -> 57;
bf_atoi64(20+16#20) -> 58;
bf_atoi64(21+16#20) -> 59;
bf_atoi64(22+16#20) -> 60;
bf_atoi64(23+16#20) -> 61;
bf_atoi64(24+16#20) -> 62;
bf_atoi64(25+16#20) -> 63;
bf_atoi64(33+16#20) -> 2;
bf_atoi64(34+16#20) -> 3;
bf_atoi64(35+16#20) -> 4;
bf_atoi64(36+16#20) -> 5;
bf_atoi64(37+16#20) -> 6;
bf_atoi64(38+16#20) -> 7;
bf_atoi64(39+16#20) -> 8;
bf_atoi64(40+16#20) -> 9;
bf_atoi64(41+16#20) -> 10;
bf_atoi64(42+16#20) -> 11;
bf_atoi64(43+16#20) -> 12;
bf_atoi64(44+16#20) -> 13;
bf_atoi64(45+16#20) -> 14;
bf_atoi64(46+16#20) -> 15;
bf_atoi64(47+16#20) -> 16;
bf_atoi64(48+16#20) -> 17;
bf_atoi64(49+16#20) -> 18;
bf_atoi64(50+16#20) -> 19;
bf_atoi64(51+16#20) -> 20;
bf_atoi64(52+16#20) -> 21;
bf_atoi64(53+16#20) -> 22;
bf_atoi64(54+16#20) -> 23;
bf_atoi64(55+16#20) -> 24;
bf_atoi64(56+16#20) -> 25;
bf_atoi64(57+16#20) -> 26;
bf_atoi64(58+16#20) -> 27;
bf_atoi64(65+16#20) -> 28;
bf_atoi64(66+16#20) -> 29;
bf_atoi64(67+16#20) -> 30;
bf_atoi64(68+16#20) -> 31;
bf_atoi64(69+16#20) -> 32;
bf_atoi64(70+16#20) -> 33;
bf_atoi64(71+16#20) -> 34;
bf_atoi64(72+16#20) -> 35;
bf_atoi64(73+16#20) -> 36;
bf_atoi64(74+16#20) -> 37;
bf_atoi64(75+16#20) -> 38;
bf_atoi64(76+16#20) -> 39;
bf_atoi64(77+16#20) -> 40;
bf_atoi64(78+16#20) -> 41;
bf_atoi64(79+16#20) -> 42;
bf_atoi64(80+16#20) -> 43;
bf_atoi64(81+16#20) -> 44;
bf_atoi64(82+16#20) -> 45;
bf_atoi64(83+16#20) -> 46;
bf_atoi64(84+16#20) -> 47;
bf_atoi64(85+16#20) -> 48;
bf_atoi64(86+16#20) -> 49;
bf_atoi64(87+16#20) -> 50;
bf_atoi64(88+16#20) -> 51;
bf_atoi64(89+16#20) -> 52;
bf_atoi64(90+16#20) -> 53; % char 'z' -> 53
bf_atoi64(X) -> {error, {out_of_range, X}}.

bf_flags_by_subtype(0) -> 2;
bf_flags_by_subtype(1) -> 0;
bf_flags_by_subtype(2) -> 0;
bf_flags_by_subtype(3) -> 0;
bf_flags_by_subtype(4) -> 0;
bf_flags_by_subtype(5) -> 0;
bf_flags_by_subtype(6) -> 0;
bf_flags_by_subtype(7) -> 0;
bf_flags_by_subtype(8) -> 0;
bf_flags_by_subtype(9) -> 0;
bf_flags_by_subtype(10) -> 0;
bf_flags_by_subtype(11) -> 0;
bf_flags_by_subtype(12) -> 0;
bf_flags_by_subtype(13) -> 0;
bf_flags_by_subtype(14) -> 0;
bf_flags_by_subtype(15) -> 0;
bf_flags_by_subtype(16) -> 0;
bf_flags_by_subtype(17) -> 0;
bf_flags_by_subtype(18) -> 0;
bf_flags_by_subtype(19) -> 0;
bf_flags_by_subtype(20) -> 0;
bf_flags_by_subtype(21) -> 0;
bf_flags_by_subtype(22) -> 0;
bf_flags_by_subtype(23) -> 1;
bf_flags_by_subtype(24) -> 4;
bf_flags_by_subtype(25) -> 0;
bf_flags_by_subtype(X) -> {error, {out_of_range, X}}.

bf_init_state_P(0) -> 16#243f6a88;
bf_init_state_P(1) -> 16#85a308d3;
bf_init_state_P(2) -> 16#13198a2e;
bf_init_state_P(3) -> 16#03707344;
bf_init_state_P(4) -> 16#a4093822;
bf_init_state_P(5) -> 16#299f31d0;
bf_init_state_P(6) -> 16#082efa98;
bf_init_state_P(7) -> 16#ec4e6c89;
bf_init_state_P(8) -> 16#452821e6;
bf_init_state_P(9) -> 16#38d01377;
bf_init_state_P(10) -> 16#be5466cf;
bf_init_state_P(11) -> 16#34e90c6c;
bf_init_state_P(12) -> 16#c0ac29b7;
bf_init_state_P(13) -> 16#c97c50dd;
bf_init_state_P(14) -> 16#3f84d5b5;
bf_init_state_P(15) -> 16#b5470917;
bf_init_state_P(16) -> 16#9216d5d9;
bf_init_state_P(17) -> 16#8979fb1b;
bf_init_state_P(X) -> {error, {out_of_range, X}}.

%% tests

test_all() ->
  io:format("And finally... test_crypt...~n"),
  test_crypt(),
  pass.

test_crypt() ->
  io:format("test_crypt: test1..."),
  {T1, <<"$2a$10$7EqJtq98hPqEX7fNZaFWoOLCkFexA7A9eoJ0Ew.mTDdk.E60D.9zS">>}
    = timer:tc(aspike_blowfish, crypt, [""], millisecond),
  io:format(" ~p milliseconds~n", [T1]),

  io:format("test_crypt: test2..."),
  {T2, <<"$2a$10$7EqJtq98hPqEX7fNZaFWoOGoQc8ghD9y4unMRjqfVQhmpf84E0PrG">>}
    = timer:tc(aspike_blowfish, crypt, ["1"], millisecond),
  io:format(" ~p milliseconds~n", [T2]),

  io:format("test_crypt: test3..."),
  {T3, <<"$2a$10$7EqJtq98hPqEX7fNZaFWoO.t/bln6qgrNB9LOR8bEcnCCE2vdfu3i">>}
    = timer:tc(aspike_blowfish, crypt, ["123456789"], millisecond),
  io:format(" ~p milliseconds~n", [T3]),

  io:format("test_crypt: test4..."),
  {T4, <<"$2a$10$7EqJtq98hPqEX7fNZaFWoOzOdWTR98ehPm.PhkVbN5DdZ4G3IgCOa">>}
    = timer:tc(aspike_blowfish, crypt, ["123456789ABCDEF0"], millisecond),
  io:format(" ~p milliseconds~n", [T4]),

  io:format("test_crypt: test5..."),
  {T5, <<"$2a$10$7EqJtq98hPqEX7fNZaFWoOEsEMitIYfRzsf1/d48b1ZxVswYbnsw6">>}
    = timer:tc(aspike_blowfish, crypt, ["123456789ABCDEF0zxc987LHj"], millisecond),
  io:format(" ~p milliseconds~n", [T5]),

  io:format("test_crypt: testX..."),
  {Tx, <<"$2a$10$7EqJtq98hPqEX7fNZaFWoOmSA5hUZtIIdbIlyE8cmA.EVLRIWJtsW">>}
    = timer:tc(aspike_blowfish, crypt, ["NWiLt5S6vikene6G"], millisecond),
  io:format(" ~p milliseconds~n", [Tx]),

  io:format("test_crypt: testY..."),
  {Ty, <<"$2a$10$7EqJtq98hPqEX7fNZaFWoOVNVspg7rLbeFL/xd2sQ5v0jzwLTM.k.">>}
    = timer:tc(aspike_blowfish, crypt, ["8kCU2Uv1YMmFA8OO"], millisecond),
  io:format(" ~p milliseconds~n", [Ty]),

  io:format("test_crypt: testZ..."),
  {Tz, <<"$2a$10$7EqJtq98hPqEX7fNZaFWoODMjlW99ZL9I9vNtehPkBqTRLEAx26Ri">>}
    = timer:tc(aspike_blowfish, crypt, ["axB1L9IEda7gxdyd"], millisecond),
  io:format(" ~p milliseconds~n", [Tz]),
  pass.


%%  Magic IV (Initialization Vector) for 64 Blowfish encryptions that we do at the end.
%%  The string is "OrpheanBeholderScryDoubt" on big-endian.
bf_magic(0) -> 16#4F727068;
bf_magic(1) -> 16#65616E42;
bf_magic(2) -> 16#65686F6C;
bf_magic(3) -> 16#64657253;
bf_magic(4) -> 16#63727944;
bf_magic(5) -> 16#6F756274;
bf_magic(X) -> {error, {out_of_range, X}}.

%% BF_init_state_S = [begin B=aspike_blowfish:bf_init_state_S(X,Y), <<B:32/little-unsigned-integer>> end  || X <- lists:seq(0,3), Y <- lists:seq(0,255)],
%% Ctx_S = list_to_binary(BF_init_state_S),
%% io:format("~p~n",[Ctx_S]).
%% aspike_blowfish:bf_init_state_S(X,Y) function is not here.
%% The function is in a aspike_blowfish.erl with extensive tests.
%% Initial state of S-boxes - S[4][256] of 4-byte integers.
bf_init_state_S() ->
  <<166,11,49,209,172,181,223,152,219,114,253,47,183,223,26,208,237,175,225,184,
    150,126,38,106,69,144,124,186,153,127,44,241,71,153,161,36,247,108,145,179,
    226,242,1,8,22,252,142,133,216,32,105,99,105,78,87,113,163,254,88,164,126,61,
    147,244,143,116,149,13,88,182,142,114,88,205,139,113,238,74,21,130,29,164,84,
    123,181,89,90,194,57,213,48,156,19,96,242,42,35,176,209,197,240,133,96,40,24,
    121,65,202,239,56,219,184,176,220,121,142,14,24,58,96,139,14,158,108,62,138,
    30,176,193,119,21,215,39,75,49,189,218,47,175,120,96,92,96,85,243,37,85,230,
    148,171,85,170,98,152,72,87,64,20,232,99,106,57,202,85,182,16,171,42,52,92,
    204,180,206,232,65,17,175,134,84,161,147,233,114,124,17,20,238,179,42,188,
    111,99,93,197,169,43,246,49,24,116,22,62,92,206,30,147,135,155,51,186,214,
    175,92,207,36,108,129,83,50,122,119,134,149,40,152,72,143,59,175,185,75,107,
    27,232,191,196,147,33,40,102,204,9,216,97,145,169,33,251,96,172,124,72,50,
    128,236,93,93,93,132,239,177,117,133,233,2,35,38,220,136,27,101,235,129,62,
    137,35,197,172,150,211,243,111,109,15,57,66,244,131,130,68,11,46,4,32,132,
    164,74,240,200,105,94,155,31,158,66,104,198,33,154,108,233,246,97,156,12,103,
    240,136,211,171,210,160,81,106,104,47,84,216,40,167,15,150,163,51,81,171,108,
    11,239,110,228,59,122,19,80,240,59,186,152,42,251,126,29,101,241,161,118,1,
    175,57,62,89,202,102,136,14,67,130,25,134,238,140,180,159,111,69,195,165,132,
    125,190,94,139,59,216,117,111,224,115,32,193,133,159,68,26,64,166,106,193,86,
    98,170,211,78,6,119,63,54,114,223,254,27,61,2,155,66,36,215,208,55,72,18,10,
    208,211,234,15,219,155,192,241,73,201,114,83,7,123,27,153,128,216,121,212,37,
    247,222,232,246,26,80,254,227,59,76,121,182,189,224,108,151,186,6,192,4,182,
    79,169,193,196,96,159,64,194,158,92,94,99,36,106,25,175,111,251,104,181,83,
    108,62,235,178,57,19,111,236,82,59,31,81,252,109,44,149,48,155,68,69,129,204,
    9,189,94,175,4,208,227,190,253,74,51,222,7,40,15,102,179,75,46,25,87,168,203,
    192,15,116,200,69,57,95,11,210,219,251,211,185,189,192,121,85,10,50,96,26,
    198,0,161,214,121,114,44,64,254,37,159,103,204,163,31,251,248,233,165,142,
    248,34,50,219,223,22,117,60,21,107,97,253,200,30,80,47,171,82,5,173,250,181,
    61,50,96,135,35,253,72,123,49,83,130,223,0,62,187,87,92,158,160,140,111,202,
    46,86,135,26,219,105,23,223,246,168,66,213,195,255,126,40,198,50,103,172,115,
    85,79,140,176,39,91,105,200,88,202,187,93,163,255,225,160,17,240,184,152,61,
    250,16,184,131,33,253,108,181,252,74,91,211,209,45,121,228,83,154,101,69,248,
    182,188,73,142,210,144,151,251,75,218,242,221,225,51,126,203,164,65,19,251,
    98,232,198,228,206,218,202,32,239,1,76,119,54,254,158,126,208,180,31,241,43,
    77,218,219,149,152,145,144,174,113,142,173,234,160,213,147,107,208,209,142,
    208,224,37,199,175,47,91,60,142,183,148,117,142,251,226,246,143,100,43,18,
    242,18,184,136,136,28,240,13,144,160,94,173,79,28,195,143,104,145,241,207,
    209,173,193,168,179,24,34,47,47,119,23,14,190,254,45,117,234,161,31,2,139,15,
    204,160,229,232,116,111,181,214,243,172,24,153,226,137,206,224,79,168,180,
    183,224,19,253,129,59,196,124,217,168,173,210,102,162,95,22,5,119,149,128,20,
    115,204,147,119,20,26,33,101,32,173,230,134,250,181,119,245,66,84,199,207,53,
    157,251,12,175,205,235,160,137,62,123,211,27,65,214,73,126,30,174,45,14,37,0,
    94,179,113,32,187,0,104,34,175,224,184,87,155,54,100,36,30,185,9,240,29,145,
    99,85,170,166,223,89,137,67,193,120,127,83,90,217,162,91,125,32,197,185,229,
    2,118,3,38,131,169,207,149,98,104,25,200,17,65,74,115,78,202,45,71,179,74,
    169,20,123,82,0,81,27,21,41,83,154,63,87,15,214,228,198,155,188,118,164,96,
    43,0,116,230,129,181,111,186,8,31,233,27,87,107,236,150,242,21,217,13,42,33,
    101,99,182,182,249,185,231,46,5,52,255,100,86,133,197,93,45,176,83,161,143,
    159,169,153,71,186,8,106,7,133,110,233,112,122,75,68,41,179,181,46,9,117,219,
    35,38,25,196,176,166,110,173,125,223,167,73,184,96,238,156,102,178,237,143,
    113,140,170,236,255,23,154,105,108,82,100,86,225,158,177,194,165,2,54,25,41,
    76,9,117,64,19,89,160,62,58,24,228,154,152,84,63,101,157,66,91,214,228,143,
    107,214,63,247,153,7,156,210,161,245,48,232,239,230,56,45,77,193,93,37,240,
    134,32,221,76,38,235,112,132,198,233,130,99,94,204,30,2,63,107,104,9,201,239,
    186,62,20,24,151,60,161,112,106,107,132,53,127,104,134,226,160,82,5,83,156,
    183,55,7,80,170,28,132,7,62,92,174,222,127,236,68,125,142,184,242,22,87,55,
    218,58,176,13,12,80,240,4,31,28,240,255,179,0,2,26,245,12,174,178,116,181,60,
    88,122,131,37,189,33,9,220,249,19,145,209,246,47,169,124,115,71,50,148,1,71,
    245,34,129,229,229,58,220,218,194,55,52,118,181,200,167,221,243,154,70,97,68,
    169,14,3,208,15,62,199,200,236,65,30,117,164,153,205,56,226,47,14,234,59,161,
    187,128,50,49,179,62,24,56,139,84,78,8,185,109,79,3,13,66,111,191,4,10,246,
    144,18,184,44,121,124,151,36,114,176,121,86,175,137,175,188,31,119,154,222,
    16,8,147,217,18,174,139,179,46,63,207,220,31,114,18,85,36,113,107,46,230,221,
    26,80,135,205,132,159,24,71,88,122,23,218,8,116,188,154,159,188,140,125,75,
    233,58,236,122,236,250,29,133,219,102,67,9,99,210,195,100,196,71,24,28,239,8,
    217,21,50,55,59,67,221,22,186,194,36,67,77,161,18,81,196,101,42,2,0,148,80,
    221,228,58,19,158,248,223,113,85,78,49,16,214,119,172,129,155,25,17,95,241,
    86,53,4,107,199,163,215,59,24,17,60,9,165,36,89,237,230,143,242,250,251,241,
    151,44,191,186,158,110,60,21,30,112,69,227,134,177,111,233,234,10,94,14,134,
    179,42,62,90,28,231,31,119,250,6,61,78,185,220,101,41,15,29,231,153,214,137,
    62,128,37,200,102,82,120,201,76,46,106,179,16,156,186,14,21,198,120,234,226,
    148,83,60,252,165,244,45,10,30,167,78,247,242,61,43,29,54,15,38,57,25,96,121,
    194,25,8,167,35,82,182,18,19,247,110,254,173,235,102,31,195,234,149,69,188,
    227,131,200,123,166,209,55,127,177,40,255,140,1,239,221,50,195,165,90,108,
    190,133,33,88,101,2,152,171,104,15,165,206,238,59,149,47,219,173,125,239,42,
    132,47,110,91,40,182,33,21,112,97,7,41,117,71,221,236,16,21,159,97,48,168,
    204,19,150,189,97,235,30,254,52,3,207,99,3,170,144,92,115,181,57,162,112,76,
    11,158,158,213,20,222,170,203,188,134,204,238,167,44,98,96,171,92,171,156,
    110,132,243,178,175,30,139,100,202,240,189,25,185,105,35,160,80,187,90,101,
    50,90,104,64,179,180,42,60,213,233,158,49,247,184,33,192,25,11,84,155,153,
    160,95,135,126,153,247,149,168,125,61,98,154,136,55,248,119,45,227,151,95,
    147,237,17,129,18,104,22,41,136,53,14,214,31,230,199,161,223,222,150,153,186,
    88,120,165,132,245,87,99,114,34,27,255,195,131,155,150,70,194,26,235,10,179,
    205,84,48,46,83,228,72,217,143,40,49,188,109,239,242,235,88,234,255,198,52,
    97,237,40,254,115,60,124,238,217,20,74,93,227,183,100,232,20,93,16,66,224,19,
    62,32,182,226,238,69,234,171,170,163,21,79,108,219,208,79,203,250,66,244,66,
    199,181,187,106,239,29,59,79,101,5,33,205,65,158,121,30,216,199,77,133,134,
    106,71,75,228,80,98,129,61,242,161,98,207,70,38,141,91,160,131,136,252,163,
    182,199,193,195,36,21,127,146,116,203,105,11,138,132,71,133,178,146,86,0,191,
    91,9,157,72,25,173,116,177,98,20,0,14,130,35,42,141,66,88,234,245,85,12,62,
    244,173,29,97,112,63,35,146,240,114,51,65,126,147,141,241,236,95,214,219,59,
    34,108,89,55,222,124,96,116,238,203,167,242,133,64,110,50,119,206,132,128,7,
    166,158,80,248,25,85,216,239,232,53,151,217,97,170,167,105,169,194,6,12,197,
    252,171,4,90,220,202,11,128,46,122,68,158,132,52,69,195,5,103,213,253,201,
    158,30,14,211,219,115,219,205,136,85,16,121,218,95,103,64,67,103,227,101,52,
    196,197,216,56,62,113,158,248,40,61,32,255,109,241,231,33,62,21,74,61,176,
    143,43,159,227,230,247,173,131,219,104,90,61,233,247,64,129,148,28,38,76,246,
    52,41,105,148,247,32,21,65,247,212,2,118,46,107,244,188,104,0,162,212,113,36,
    8,212,106,244,32,51,183,212,183,67,175,97,0,80,46,246,57,30,70,69,36,151,116,
    79,33,20,64,136,139,191,29,252,149,77,175,145,181,150,211,221,244,112,69,47,
    160,102,236,9,188,191,133,151,189,3,208,109,172,127,4,133,203,49,179,39,235,
    150,65,57,253,85,230,71,37,218,154,10,202,171,37,120,80,40,244,41,4,83,218,
    134,44,10,251,109,182,233,98,20,220,104,0,105,72,215,164,192,14,104,238,141,
    161,39,162,254,63,79,140,173,135,232,6,224,140,181,182,214,244,122,124,30,
    206,170,236,95,55,211,153,163,120,206,66,42,107,64,53,158,254,32,185,133,243,
    217,171,215,57,238,139,78,18,59,247,250,201,29,86,24,109,75,49,102,163,38,
    178,151,227,234,116,250,110,58,50,67,91,221,247,231,65,104,251,32,120,202,78,
    245,10,251,151,179,254,216,172,86,64,69,39,149,72,186,58,58,83,85,135,141,
    131,32,183,169,107,254,75,149,150,208,188,103,168,85,88,154,21,161,99,41,169,
    204,51,219,225,153,86,74,42,166,249,37,49,63,28,126,244,94,124,49,41,144,2,
    232,248,253,112,47,39,4,92,21,187,128,227,44,40,5,72,21,193,149,34,109,198,
    228,63,19,193,72,220,134,15,199,238,201,249,7,15,31,4,65,164,121,71,64,23,
    110,136,93,235,81,95,50,209,192,155,213,143,193,188,242,100,53,17,65,52,120,
    123,37,96,156,42,96,163,232,248,223,27,108,99,31,194,180,18,14,158,50,225,2,
    209,79,102,175,21,129,209,202,224,149,35,107,225,146,62,51,98,11,36,59,34,
    185,190,238,14,162,178,133,153,13,186,230,140,12,114,222,40,247,162,45,69,
    120,18,208,253,148,183,149,98,8,125,100,240,245,204,231,111,163,73,84,250,72,
    125,135,39,253,157,195,30,141,62,243,65,99,71,10,116,255,46,153,171,110,111,
    58,55,253,248,244,96,220,18,168,248,221,235,161,76,225,27,153,13,107,110,219,
    16,85,123,198,55,44,103,109,59,212,101,39,4,232,208,220,199,13,41,241,163,
    255,0,204,146,15,57,181,11,237,15,105,251,159,123,102,156,125,219,206,11,207,
    145,160,163,94,21,217,136,47,19,187,36,173,91,81,191,121,148,123,235,214,59,
    118,179,46,57,55,121,89,17,204,151,226,38,128,45,49,46,244,167,173,66,104,59,
    43,106,198,204,76,117,18,28,241,46,120,55,66,18,106,231,81,146,183,230,187,
    161,6,80,99,251,75,24,16,107,26,250,237,202,17,216,189,37,61,201,195,225,226,
    89,22,66,68,134,19,18,10,110,236,12,217,42,234,171,213,78,103,175,100,95,168,
    134,218,136,233,191,190,254,195,228,100,87,128,188,157,134,192,247,240,248,
    123,120,96,77,96,3,96,70,131,253,209,176,31,56,246,4,174,69,119,204,252,54,
    215,51,107,66,131,113,171,30,240,135,65,128,176,95,94,0,60,190,87,160,119,36,
    174,232,189,153,66,70,85,97,46,88,191,143,244,88,78,162,253,221,242,56,239,
    116,244,194,189,137,135,195,249,102,83,116,142,179,200,85,242,117,180,185,
    217,252,70,97,38,235,122,132,223,29,139,121,14,106,132,226,149,95,145,142,89,
    110,70,112,87,180,32,145,85,213,140,76,222,2,201,225,172,11,185,208,5,130,
    187,72,98,168,17,158,169,116,117,182,25,127,183,9,220,169,224,161,9,45,102,
    51,70,50,196,2,31,90,232,140,190,240,9,37,160,153,74,16,254,110,29,29,61,185,
    26,223,164,165,11,15,242,134,161,105,241,104,40,131,218,183,220,254,6,57,87,
    155,206,226,161,82,127,205,79,1,94,17,80,250,131,6,167,196,181,2,160,39,208,
    230,13,39,140,248,154,65,134,63,119,6,76,96,195,181,6,168,97,40,122,23,240,
    224,134,245,192,170,88,96,0,98,125,220,48,215,158,230,17,99,234,56,35,148,
    221,194,83,52,22,194,194,86,238,203,187,222,182,188,144,161,125,252,235,118,
    29,89,206,9,228,5,111,136,1,124,75,61,10,114,57,36,124,146,124,95,114,227,
    134,185,157,77,114,180,91,193,26,252,184,158,211,120,85,84,237,181,165,252,8,
    211,124,61,216,196,15,173,77,94,239,80,30,248,230,97,177,217,20,133,162,60,
    19,81,108,231,199,213,111,196,78,225,86,206,191,42,54,55,200,198,221,52,50,
    154,215,18,130,99,146,142,250,14,103,224,0,96,64,55,206,57,58,207,245,250,
    211,55,119,194,171,27,45,197,90,158,103,176,92,66,55,163,79,64,39,130,211,
    190,155,188,153,157,142,17,213,21,115,15,191,126,28,45,214,123,196,0,199,107,
    27,140,183,69,144,161,33,190,177,110,178,180,110,54,106,47,171,72,87,121,110,
    148,188,210,118,163,198,200,194,73,101,238,248,15,83,125,222,141,70,29,10,
    115,213,198,77,208,76,219,187,57,41,80,70,186,169,232,38,149,172,4,227,94,
    190,240,213,250,161,154,81,45,106,226,140,239,99,34,238,134,154,184,194,137,
    192,246,46,36,67,170,3,30,165,164,208,242,156,186,97,192,131,77,106,233,155,
    80,21,229,143,214,91,100,186,249,162,38,40,225,58,58,167,134,149,169,75,233,
    98,85,239,211,239,47,199,218,247,82,247,105,111,4,63,89,10,250,119,21,169,
    228,128,1,134,176,135,173,230,9,155,147,229,62,59,90,253,144,233,151,215,52,
    158,217,183,240,44,81,139,43,2,58,172,213,150,125,166,125,1,214,62,207,209,
    40,45,125,124,207,37,159,31,155,184,242,173,114,180,214,90,76,245,136,90,113,
    172,41,224,230,165,25,224,253,172,176,71,155,250,147,237,141,196,211,232,204,
    87,59,40,41,102,213,248,40,46,19,121,145,1,95,120,85,96,117,237,68,14,150,
    247,140,94,211,227,212,109,5,21,186,109,244,136,37,97,161,3,189,240,100,5,21,
    158,235,195,162,87,144,60,236,26,39,151,42,7,58,169,155,109,63,27,245,33,99,
    30,251,102,156,245,25,243,220,38,40,217,51,117,245,253,85,177,130,52,86,3,
    187,60,186,138,17,119,81,40,248,217,10,194,103,81,204,171,95,146,173,204,81,
    23,232,77,142,220,48,56,98,88,157,55,145,249,32,147,194,144,122,234,206,123,
    62,251,100,206,33,81,50,190,79,119,126,227,182,168,70,61,41,195,105,83,222,
    72,128,230,19,100,16,8,174,162,36,178,109,221,253,45,133,105,102,33,7,9,10,
    70,154,179,221,192,69,100,207,222,108,88,174,200,32,28,221,247,190,91,64,141,
    88,27,127,1,210,204,187,227,180,107,126,106,162,221,69,255,89,58,68,10,53,62,
    213,205,180,188,168,206,234,114,187,132,100,250,174,18,102,141,71,111,60,191,
    99,228,155,210,158,93,47,84,27,119,194,174,112,99,78,246,141,13,14,116,87,19,
    91,231,113,22,114,248,93,125,83,175,8,203,64,64,204,226,180,78,106,70,210,52,
    132,175,21,1,40,4,176,225,29,58,152,149,180,159,184,6,72,160,110,206,130,59,
    63,111,130,171,32,53,75,29,26,1,248,39,114,39,177,96,21,97,220,63,147,231,43,
    121,58,187,189,37,69,52,225,57,136,160,75,121,206,81,183,201,50,47,201,186,
    31,160,126,200,28,224,246,209,199,188,195,17,1,207,199,170,232,161,73,135,
    144,26,154,189,79,212,203,222,218,208,56,218,10,213,42,195,57,3,103,54,145,
    198,124,49,249,141,79,43,177,224,183,89,158,247,58,187,245,67,255,25,213,242,
    156,69,217,39,44,34,151,191,42,252,230,21,113,252,145,15,37,21,148,155,97,
    147,229,250,235,156,182,206,89,100,168,194,209,168,186,18,94,7,193,182,12,
    106,5,227,101,80,210,16,66,164,3,203,14,110,236,224,59,219,152,22,190,160,
    152,76,100,233,120,50,50,149,31,159,223,146,211,224,43,52,160,211,30,242,113,
    137,65,116,10,27,140,52,163,75,32,113,190,197,216,50,118,195,141,159,53,223,
    46,47,153,155,71,111,11,230,29,241,227,15,84,218,76,229,145,216,218,30,207,
    121,98,206,111,126,62,205,102,177,24,22,5,29,44,253,197,210,143,132,153,34,
    251,246,87,243,35,245,35,118,50,166,49,53,168,147,2,205,204,86,98,129,240,
    172,181,235,117,90,151,54,22,110,204,115,210,136,146,98,150,222,208,73,185,
    129,27,144,80,76,20,86,198,113,189,199,198,230,10,20,122,50,6,208,225,69,154,
    123,242,195,253,83,170,201,0,15,168,98,226,191,37,187,246,210,189,53,5,105,
    18,113,34,2,4,178,124,207,203,182,43,156,118,205,192,62,17,83,211,227,64,22,
    96,189,171,56,240,173,71,37,156,32,56,186,118,206,70,247,197,161,175,119,96,
    96,117,32,78,254,203,133,216,141,232,138,176,249,170,122,126,170,249,76,92,
    194,72,25,140,138,251,2,228,106,195,1,249,225,235,214,105,248,212,144,160,
    222,92,166,45,37,9,63,159,230,8,194,50,97,78,183,91,226,119,206,227,223,143,
    87,230,114,195,58>>.

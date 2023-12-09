aspike_protocol
=====

Implementation of Aerospike binary protocol in Erlang

Binary protocol
---------------

Aerospike Binary protocol is described in 'doc/Aerospike_packet_structure.txt'.

Aerospike Cluster Discovery is described in 'doc/Aerospike_cluster_discovery.txt'.

Build
-----

    $ make compile

Test
-----

    $ make eunit

Usage
-----
Examples can be run in the following environments:
- Aerospike Cluster Standard/Enterprise/Cloud (https://aerospike.com/products/features-and-editions/);
- Aerospike Cluster Community Edition (CE) (https://hub.docker.com/r/aerospike/aerospike-server);
- Aerospike Server Emulator (https://github.com/vsavkov/aspike-server).

To start Aerospike Cluster Community edition follow the instructions on https://hub.docker.com/r/aerospike/aerospike-server).

To start Aerospike Server Emulator:
1. Clone https://github.com/vsavkov/aspike-server;
2. Run command 'iex -S mix' from 'aspike-server' director;
3. Aerospike Server Emulator listens for the Aerospike protocol on port 4041;
4. Aerospike Server Emulator listens for text protocol on port 4040;
5. Use text protocol to create namespace 'test' for examples that involve Key-Value operations:

    Start telnet or nc (aka netcat) in a separate terminal:
    
    $ nc -vv 127.0.0.1 4040
    
    type in:
    
    CREATE test
    
    OK
    
    to check that namespace 'test' exists type in:
    
    NAMESPACES
    
    [test]

Examples
--------

    $ rebar3 shell
    Erlang/OTP ...

Password encryption
-------------------
Aerospike uses Blowfish cipher to encrypt password that is sent from client to cluster.

Aerospike has some specifics in Blowfish cipher implementation.

'aspike_blowfish:crypt/1' implements the Aerospike-specific Blowfish cipher.

WARNING: The encryption rate of the implementation is slow.

To encrypt password

    > Encrypted = aspike_blowfish:crypt("password").
    <<"$2a$10$7EqJtq98hPqEX7fNZaFWoOqUH6KN8IKy3Yk5Kz..RHGKNAUCoP/LG">>

NOTE: Aerospike CE does not require LOGIN, but accept LOGIN as no op.

Cluster Login
-------------

    > c("examples/login_example.erl").
    % Login to Aerospike CE
    > login_example:login("127.0.0.1", 3000, "User", "pwd").
    ok
    % Login to Aerospike Emulator
    > login_example:login("127.0.0.1", 4041, "User1", "pass1").
    ok

Cluster Information
-------------------
NOTE: Aerospike Emulator does not support cluster information retrieval at the present time.
 
    > c("examples/info.erl").
    > info_example:info("127.0.0.1", 3000, "", "", ["build"], 1000).
    [{<<"build">>,<<"6.3.0.5">>},{<<>>}]
    > info_example:info("127.0.0.1", 3000, "", "", ["namespaces"], 1000).
    [{<<"namespaces">>,<<"test">>},{<<>>}]
    > info_example:info("127.0.0.1", 3000, "", "", ["partitions", "replicas"], 1000).
    [{<<"partitions">>,<<"4096">>},
    {<<"replicas">>,
    <<"test:0,1,///////////////////////////////////////////////////////////////////////////////////////////"...>>},
    {<<>>}]

PUT Key-Value
-------------
    > c("examples/put_example.erl").
    % PUT, Aerospike CE
    > put_example:put("127.0.0.1", 3000, "", "", "test", "set1", "key1", [{"bin1", "value1"}]).
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    % PUT, Aerospike Emulator
    % Encrypt password for Aerospike Emulator
    > Encrypted_password = aspike_blowfish:crypt("pass1").
    > put_example:put("127.0.0.1", 4041, "User1", Encrypted_password, "test", "set1", "key1", [{"bin1", "value1"}]).
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}

GET Key-Value
-------------
    > c("examples/get_example.erl").
    % GET, Aerospike CE
    > get_example:get("127.0.0.1", 3000, "", "", "test", "set1", "key1", []).
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    [], [{<<"bin1">>,"value1"}]
    % GET, Aerospike Emulator
    > get_example:get("127.0.0.1", 4041, "User1", Encrypted_password, "test", "set1", "key1", ["bin1"]).
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    [], [{<<"bin1">>,"value1"}]

REMOVE Key
----------
    > c("examples/get_example.erl").
    % REMOVE, Aerospike CE
    > remove_example:remove("127.0.0.1", 3000, "", "", "test", "set1", "key1").
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    % REMOVE again
    > remove_example:remove("127.0.0.1", 3000, "", "", "test", "set1", "key1").
    {2,<<"AEROSPIKE_ERR_RECORD_NOT_FOUND">>, <<"Record does not exist in database.">>}
    % REMOVE, Aerospike Emulator
    > remove_example:remove("127.0.0.1", 4041, "User1", Encrypted_password, "test", "set1", "key1").
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    % REMOVE again
    > remove_example:remove("127.0.0.1", 4041, "User1", Encrypted_password, "test", "set1", "key1").
    {2,<<"AEROSPIKE_ERR_RECORD_NOT_FOUND">>, <<"Record does not exist in database.">>}

EXISTS Key
----------
    > c("examples/exists_example.erl").
    
    %% Aerospike CE section
    % First, PUT Key-Value
    > put_example:put("127.0.0.1", 3000, "", "", "test", "set1", "key1", [{"bin1", "value1"}]).
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    % Next, check that Key EXISTS
    > exists_example:exists("127.0.0.1", 3000, "", "", "test", "set1", "key1").
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    % GET Key
    > get_example:get("127.0.0.1", 3000, "", "", "test", "set1", "key1", []).
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    [], [{<<"bin1">>,"value1"}]
    % Now, REMOVE Key
    > remove_example:remove("127.0.0.1", 3000, "", "", "test", "set1", "key1").
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    % Check again, whether the Key exists
    > exists_example:exists("127.0.0.1", 3000, "", "", "test", "set1", "key1").
    {2,<<"AEROSPIKE_ERR_RECORD_NOT_FOUND">>, <<"Record does not exist in database.">>}
    %% Aerospike CE section. End

    %% Aerospike Emulator section
    % First, PUT Key-Value
    > put_example:put("127.0.0.1", 4041, "User1", Encrypted_password, "test", "set1", "key1", [{"bin1", "value1"}]).
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    % Next, check that Key EXISTS
    > exists_example:exists("127.0.0.1", 4041, "User1", Encrypted_password, "test", "set1", "key1").
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    % GET Key
    > get_example:get("127.0.0.1", 4041, "User1", Encrypted_password, "test", "set1", "key1", ["bin1"]).
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    [], [{<<"bin1">>,"value1"}]
    % Now, REMOVE Key
    > remove_example:remove("127.0.0.1", 4041, "User1", Encrypted_password, "test", "set1", "key1").
    {0,<<"AEROSPIKE_OK">>,<<"Generic success.">>}
    % Check again, whether the Key exists
    > exists_example:exists("127.0.0.1", 4041, "User1", Encrypted_password, "test", "set1", "key1").
    {2,<<"AEROSPIKE_ERR_RECORD_NOT_FOUND">>, <<"Record does not exist in database.">>}
    %% Aerospike Emulator section. End

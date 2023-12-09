%% Proto header version
-define(AS_PROTO_VERSION, 2).

%% Proto message types
-define(AS_INFO_MESSAGE_TYPE, 1).
-define(AS_ADMIN_MESSAGE_TYPE, 2).
-define(AS_MESSAGE_TYPE, 3).
-define(AS_COMPRESSED_MESSAGE_TYPE, 4).
-define(PROTO_SIZE_MAX, (128 * 1024 * 1024)). % 2^27 = 128 MB

%% admin Commands
-define(LOGIN, 20). % 0x14 = 16#14.

%% Field IDs in admin Commands
-define(USER, 0).
-define(CREDENTIAL, 3).
-define(SESSION_TOKEN, 5).
-define(SESSION_TTL, 6).

-define(AS_PROTO_DISTANCE_BTW_SIZE_AND_FIELDS, 16).

%% Field IDs
-define(AS_FIELD_NAMESPACE, 0).
-define(AS_FIELD_SETNAME, 1).
-define(AS_FIELD_KEY, 2).
-define(AS_FIELD_DIGEST, 4).
-define(AS_FIELD_TASK_ID, 7).
-define(AS_FIELD_SOCKET_TIMEOUT, 9).
-define(AS_FIELD_RPS, 10).
-define(AS_FIELD_PID_ARRAY, 11).
-define(AS_FIELD_DIGEST_ARRAY, 12).
-define(AS_FIELD_MAX_RECORDS, 13).
-define(AS_FIELD_BVAL_ARRAY, 15).
-define(AS_FIELD_INDEX_RANGE, 22).
-define(AS_FIELD_INDEX_CONTEXT, 23).
-define(AS_FIELD_INDEX_TYPE, 26).
-define(AS_FIELD_UDF_PACKAGE_NAME, 30).
-define(AS_FIELD_UDF_FUNCTION, 31).
-define(AS_FIELD_UDF_ARGLIST, 32).
-define(AS_FIELD_UDF_OP, 33).
-define(AS_FIELD_QUERY_BINS, 40).
-define(AS_FIELD_BATCH_INDEX, 41).
-define(AS_FIELD_FILTER, 43).

%% Message info1 bits
-define(AS_MSG_INFO1_READ, (1 bsl 0)). % contains a read operation
-define(AS_MSG_INFO1_GET_ALL, (1 bsl 1)). % get all bins, period
-define(AS_MSG_INFO1_SHORT_QUERY, (1 bsl 2)). % short query
-define(AS_MSG_INFO1_BATCH_INDEX, (1 bsl 3)). % batch
-define(AS_MSG_INFO1_XDR, (1 bsl 4)). % operation is being performed by XDR
-define(AS_MSG_INFO1_GET_NOBINDATA, (1 bsl 5)). % do not get information about bins and its data
-define(AS_MSG_INFO1_READ_MODE_AP_ALL, (1 bsl 6)). % read mode all for AP namespaces.
-define(AS_MSG_INFO1_COMPRESS_RESPONSE, (1 bsl 7)). % tell server to compress it's response.

%% Message info2 bits
-define(AS_MSG_INFO2_WRITE, (1 bsl 0)). % contains a write semantic
-define(AS_MSG_INFO2_DELETE, (1 bsl 1)). % delete record
-define(AS_MSG_INFO2_GENERATION, (1 bsl 2)). % pay attention to the generation
-define(AS_MSG_INFO2_GENERATION_GT, (1 bsl 3)). % apply write if new generation >= old, good for restore
-define(AS_MSG_INFO2_DURABLE_DELETE, (1 bsl 4)). % transaction resulting in record deletion leaves tombstone (Enterprise only).
-define(AS_MSG_INFO2_CREATE_ONLY, (1 bsl 5)). % write record only if it doesn't exist
%% (Note:  Bit 6 is unused.)
-define(AS_MSG_INFO2_RESPOND_ALL_OPS, (1 bsl 7)). % return a result for every operation.

%% Message info3 bits
-define(AS_MSG_INFO3_LAST, (1 bsl 0)). % this is the last of a multi-part message
-define(AS_MSG_INFO3_COMMIT_MASTER, (1 bsl 1)). % write commit level - bit 0
%% On send: Do not return partition done in scan/query.
%% On receive: Specified partition is done in scan/query.
-define(AS_MSG_INFO3_PARTITION_DONE, (1 bsl 2)).
-define(AS_MSG_INFO3_UPDATE_ONLY, (1 bsl 3)). % update existing record only, do not create new record
-define(AS_MSG_INFO3_CREATE_OR_REPLACE, (1 bsl 4)). % completely replace existing record, or create new record
-define(AS_MSG_INFO3_REPLACE_ONLY, (1 bsl 5)). % completely replace existing record, do not create new record
-define(AS_MSG_INFO3_SC_READ_TYPE, (1 bsl 6)). % see aerospike-client-c for details
-define(AS_MSG_INFO3_SC_READ_RELAX, (1 bsl 7)). % see aerospike-client-c for details


-define(AS_OPERATOR_READ, 1).
-define(AS_OPERATOR_WRITE, 2).
-define(AS_OPERATOR_CDT_READ, 3).
-define(AS_OPERATOR_CDT_MODIFY, 4).
-define(AS_OPERATOR_MAP_READ, 5).
-define(AS_OPERATOR_MAP_MODIFY, 6).
-define(AS_OPERATOR_INCR, 7).
-define(AS_OPERATOR_EXP_READ, 8).
-define(AS_OPERATOR_EXP_MODIFY, 9).
-define(AS_OPERATOR_APPEND, 10).
-define(AS_OPERATOR_PREPEND, 11).
-define(AS_OPERATOR_TOUCH, 12).
-define(AS_OPERATOR_BIT_READ, 13).
-define(AS_OPERATOR_BIT_MODIFY, 14).
-define(AS_OPERATOR_DELETE, 15).
-define(AS_OPERATOR_HLL_READ, 16).
-define(AS_OPERATOR_HLL_MODIFY, 17).

-define(KEY_DIGEST_SIZE, 160). % RIPEMD160 crypto:hash(ripemd160, ...)


-define(AS_BYTES_UNDEF, 0).
-define(AS_BYTES_INTEGER, 1).
-define(AS_BYTES_DOUBLE, 2).
-define(AS_BYTES_STRING, 3).
-define(AS_BYTES_BLOB, 4).
-define(AS_BYTES_JAVA, 7).
-define(AS_BYTES_CSHARP, 8).
-define(AS_BYTES_PYTHON, 9).
-define(AS_BYTES_RUBY, 10).
-define(AS_BYTES_PHP, 11).
-define(AS_BYTES_ERLANG, 12).
-define(AS_BYTES_BOOL, 17).
-define(AS_BYTES_HLL, 18).
-define(AS_BYTES_MAP, 19).
-define(AS_BYTES_LIST, 20).
-define(AS_BYTES_GEOJSON, 23).
-define(AS_BYTES_TYPE_MAX, 24).

%% as_proto reflects binary (physical) layout
-record(as_proto, {
  version :: aspike:uint8_t(),
  type :: aspike:uint8_t(),
  sz :: aspike:uint48_t()
}).

%% as_msg reflects binary (physical) layout
-record(as_msg, {
  header_sz :: aspike:uint8_t(), % number of uint8_ts in this header
  info1 :: aspike:uint8_t(), % bitfield about this request
  info2 :: aspike:uint8_t(),
  info3 :: aspike:uint8_t(),
  unused :: aspike:uint8_t(),
  result_code :: aspike:uint8_t(),
  generation :: aspike:uint32_t(),
  record_ttl :: aspike:uint32_t(),
  transaction_ttl :: aspike:uint32_t(),
  n_fields :: aspike:uint16_t(), % size in uint8_ts
  n_ops :: aspike:uint16_t() % number of operations
  % followed by data that contain
  % the fields, occupying n_fields bytes
  % then the n_ops number of ops.
}).

%% aspike_message_type_header is a logical representation of as_msg
-record(aspike_message_type_header, {
  result_code :: aspike:uint8_t(),
  n_fields :: aspike:uint16_t(),
  n_bins :: aspike:uint16_t(),
  ttl :: aspike:uint32_t(),
  timeout :: aspike:uint32_t(),
  read_attr :: aspike:uint8_t(),
  write_attr :: aspike:uint8_t(),
  info_attr :: aspike:uint8_t(),
  generation :: aspike:uint32_t(),
  unused :: aspike:uint8_t()
}).
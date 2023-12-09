-module(aspike_status).
-include("../include/aspike_status.hrl").

%% API
-export([status/1]).

-spec status(aspike:status_code()) -> aspike:status().
status(?AEROSPIKE_OK) ->
  {?AEROSPIKE_OK, <<"AEROSPIKE_OK">>, <<"Generic success.">>};
status(?AEROSPIKE_ERR_SERVER) ->
  {?AEROSPIKE_ERR_SERVER, <<"AEROSPIKE_ERR_SERVER">>, <<"Generic error returned by server.">>};
status(?AEROSPIKE_ERR_RECORD_NOT_FOUND) ->
  {?AEROSPIKE_ERR_RECORD_NOT_FOUND, <<"AEROSPIKE_ERR_RECORD_NOT_FOUND">>, <<"Record does not exist in database. May be returned by read, or write with policy AS_POLICY_EXISTS_UPDATE.">>};
status(?AEROSPIKE_ERR_RECORD_GENERATION) ->
  {?AEROSPIKE_ERR_RECORD_GENERATION, <<"AEROSPIKE_ERR_RECORD_GENERATION">>, <<"Generation of record in database does not satisfy write policy.">>};
status(?AEROSPIKE_ERR_REQUEST_INVALID) ->
  {?AEROSPIKE_ERR_REQUEST_INVALID, <<"AEROSPIKE_ERR_REQUEST_INVALID">>, <<"Request protocol invalid, or invalid protocol field.">>};
status(?AEROSPIKE_ERR_RECORD_EXISTS) ->
  {?AEROSPIKE_ERR_RECORD_EXISTS, <<"AEROSPIKE_ERR_RECORD_EXISTS">>, <<"Record already exists. May be returned by write with policy AS_POLICY_EXISTS_CREATE.">>};
status(?AEROSPIKE_ERR_BIN_EXISTS) ->
  {?AEROSPIKE_ERR_BIN_EXISTS, <<"AEROSPIKE_ERR_BIN_EXISTS">>, <<"Bin already exists on a create-only operation.">>};
status(?AEROSPIKE_ERR_CLUSTER_CHANGE) ->
  {?AEROSPIKE_ERR_CLUSTER_CHANGE, <<"AEROSPIKE_ERR_CLUSTER_CHANGE">>, <<"A cluster state change occurred during the request. This may also be returned by scan operations with the fail_on_cluster_change flag set.">>};
status(?AEROSPIKE_ERR_SERVER_FULL) ->
  {?AEROSPIKE_ERR_SERVER_FULL, <<"AEROSPIKE_ERR_SERVER_FULL">>, <<"The server node is running out of memory and/or storage device space reserved for the specified namespace.">>};
status(?AEROSPIKE_ERR_TIMEOUT) ->
  {?AEROSPIKE_ERR_TIMEOUT, <<"AEROSPIKE_ERR_TIMEOUT">>, <<"Request timed out.  Can be triggered by client or server.">>};
status(?AEROSPIKE_ERR_ALWAYS_FORBIDDEN) ->
  {?AEROSPIKE_ERR_ALWAYS_FORBIDDEN, <<"AEROSPIKE_ERR_ALWAYS_FORBIDDEN">>, <<"Operation not allowed in current configuration.">>};
status(?AEROSPIKE_ERR_CLUSTER) ->
  {?AEROSPIKE_ERR_CLUSTER, <<"AEROSPIKE_ERR_CLUSTER">>, <<"Partition is unavailable.">>};
status(?AEROSPIKE_ERR_BIN_INCOMPATIBLE_TYPE) ->
  {?AEROSPIKE_ERR_BIN_INCOMPATIBLE_TYPE, <<"AEROSPIKE_ERR_BIN_INCOMPATIBLE_TYPE">>, <<"Bin modification operation can't be done on an existing bin due to its value type.">>};
status(?AEROSPIKE_ERR_RECORD_TOO_BIG) ->
  {?AEROSPIKE_ERR_RECORD_TOO_BIG, <<"AEROSPIKE_ERR_RECORD_TOO_BIG">>, <<"Record being (re-)written can't fit in a storage write block.">>};
status(?AEROSPIKE_ERR_RECORD_BUSY) ->
  {?AEROSPIKE_ERR_RECORD_BUSY, <<"AEROSPIKE_ERR_RECORD_BUSY">>, <<"Too may concurrent requests for one record - a 'hot-key' situation.">>};
status(?AEROSPIKE_ERR_SCAN_ABORTED) ->
  {?AEROSPIKE_ERR_SCAN_ABORTED, <<"AEROSPIKE_ERR_SCAN_ABORTED">>, <<"Scan aborted by user.">>};
status(?AEROSPIKE_ERR_UNSUPPORTED_FEATURE) ->
  {?AEROSPIKE_ERR_UNSUPPORTED_FEATURE, <<"AEROSPIKE_ERR_UNSUPPORTED_FEATURE">>, <<"Sometimes our doc, or our customers wishes, get ahead of us.  We may have processed something that the server is not ready for (unsupported feature).">>};
status(?AEROSPIKE_ERR_BIN_NOT_FOUND) ->
  {?AEROSPIKE_ERR_BIN_NOT_FOUND, <<"AEROSPIKE_ERR_BIN_NOT_FOUND">>, <<"Bin not found on update-only operation.">>};
status(?AEROSPIKE_ERR_DEVICE_OVERLOAD) ->
  {?AEROSPIKE_ERR_DEVICE_OVERLOAD, <<"AEROSPIKE_ERR_DEVICE_OVERLOAD">>, <<"The server node's storage device(s) can't keep up with the write load.">>};
status(?AEROSPIKE_ERR_RECORD_KEY_MISMATCH) ->
  {?AEROSPIKE_ERR_RECORD_KEY_MISMATCH, <<"AEROSPIKE_ERR_RECORD_KEY_MISMATCH">>, <<"Record key sent with transaction did not match key stored on server.">>};
status(?AEROSPIKE_ERR_NAMESPACE_NOT_FOUND) ->
  {?AEROSPIKE_ERR_NAMESPACE_NOT_FOUND, <<"AEROSPIKE_ERR_NAMESPACE_NOT_FOUND">>, <<"Namespace in request not found on server.">>};
status(?AEROSPIKE_ERR_BIN_NAME) ->
  {?AEROSPIKE_ERR_BIN_NAME, <<"AEROSPIKE_ERR_BIN_NAME">>, <<"Sent too-long bin name or exceeded namespace's bin name quota.">>};
status(?AEROSPIKE_ERR_FAIL_FORBIDDEN) ->
  {?AEROSPIKE_ERR_FAIL_FORBIDDEN, <<"AEROSPIKE_ERR_FAIL_FORBIDDEN">>, <<"Operation not allowed at this time.">>};
status(?AEROSPIKE_ERR_FAIL_ELEMENT_NOT_FOUND) ->
  {?AEROSPIKE_ERR_FAIL_ELEMENT_NOT_FOUND, <<"AEROSPIKE_ERR_FAIL_ELEMENT_NOT_FOUND">>, <<"Map element not found in UPDATE_ONLY write mode.">>};
status(?AEROSPIKE_ERR_FAIL_ELEMENT_EXISTS) ->
  {?AEROSPIKE_ERR_FAIL_ELEMENT_EXISTS, <<"AEROSPIKE_ERR_FAIL_ELEMENT_EXISTS">>, <<"Map element exists in CREATE_ONLY write mode.">>};
status(?AEROSPIKE_ERR_ENTERPRISE_ONLY) ->
  {?AEROSPIKE_ERR_ENTERPRISE_ONLY, <<"AEROSPIKE_ERR_ENTERPRISE_ONLY">>, <<"Attempt to use an Enterprise feature on a Community server or a server without the applicable feature key.">>};
status(?AEROSPIKE_ERR_OP_NOT_APPLICABLE) ->
  {?AEROSPIKE_ERR_OP_NOT_APPLICABLE, <<"AEROSPIKE_ERR_OP_NOT_APPLICABLE">>, <<"The operation cannot be applied to the current bin value on the server.">>};
status(?AEROSPIKE_FILTERED_OUT) ->
  {?AEROSPIKE_FILTERED_OUT, <<"AEROSPIKE_FILTERED_OUT">>, <<"The transaction was not performed because the filter expression was false.">>};
status(?AEROSPIKE_LOST_CONFLICT) ->
  {?AEROSPIKE_LOST_CONFLICT, <<"AEROSPIKE_LOST_CONFLICT">>, <<"Write command loses conflict to XDR.">>};
status(?AEROSPIKE_QUERY_END) ->
  {?AEROSPIKE_QUERY_END, <<"AEROSPIKE_QUERY_END">>, <<"There are no more records left for query.">>};
status(?AEROSPIKE_SECURITY_NOT_SUPPORTED) ->
  {?AEROSPIKE_SECURITY_NOT_SUPPORTED, <<"AEROSPIKE_SECURITY_NOT_SUPPORTED">>, <<"Security functionality not supported by connected server.">>};
status(?AEROSPIKE_SECURITY_NOT_ENABLED) ->
  {?AEROSPIKE_SECURITY_NOT_ENABLED, <<"AEROSPIKE_SECURITY_NOT_ENABLED">>, <<"Security functionality not enabled by connected server.">>};
status(?AEROSPIKE_SECURITY_SCHEME_NOT_SUPPORTED) ->
  {?AEROSPIKE_SECURITY_SCHEME_NOT_SUPPORTED, <<"AEROSPIKE_SECURITY_SCHEME_NOT_SUPPORTED">>, <<"Security type not supported by connected server.">>};
status(?AEROSPIKE_INVALID_COMMAND) ->
  {?AEROSPIKE_INVALID_COMMAND, <<"AEROSPIKE_INVALID_COMMAND">>, <<"Administration command is invalid.">>};
status(?AEROSPIKE_INVALID_FIELD) ->
  {?AEROSPIKE_INVALID_FIELD, <<"AEROSPIKE_INVALID_FIELD">>, <<"Administration field is invalid.">>};
status(?AEROSPIKE_ILLEGAL_STATE) ->
  {?AEROSPIKE_ILLEGAL_STATE, <<"AEROSPIKE_ILLEGAL_STATE">>, <<"Security protocol not followed.">>};
status(?AEROSPIKE_INVALID_USER) ->
  {?AEROSPIKE_INVALID_USER, <<"AEROSPIKE_INVALID_USER">>, <<"User name is invalid.">>};
status(?AEROSPIKE_USER_ALREADY_EXISTS) ->
  {?AEROSPIKE_USER_ALREADY_EXISTS, <<"AEROSPIKE_USER_ALREADY_EXISTS">>, <<"User was previously created.">>};
status(?AEROSPIKE_INVALID_PASSWORD) ->
  {?AEROSPIKE_INVALID_PASSWORD, <<"AEROSPIKE_INVALID_PASSWORD">>, <<"Password is invalid.">>};
status(?AEROSPIKE_EXPIRED_PASSWORD) ->
  {?AEROSPIKE_EXPIRED_PASSWORD, <<"AEROSPIKE_EXPIRED_PASSWORD">>, <<"Password has expired.">>};
status(?AEROSPIKE_FORBIDDEN_PASSWORD) ->
  {?AEROSPIKE_FORBIDDEN_PASSWORD, <<"AEROSPIKE_EXPIRED_PASSWORD">>, <<"Forbidden password (e.g. recently used)">>};
status(?AEROSPIKE_INVALID_CREDENTIAL) ->
  {?AEROSPIKE_INVALID_CREDENTIAL, <<"AEROSPIKE_INVALID_CREDENTIAL">>, <<"Security credential is invalid.">>};
status(?AEROSPIKE_EXPIRED_SESSION) ->
  {?AEROSPIKE_EXPIRED_SESSION, <<"AEROSPIKE_EXPIRED_SESSION">>, <<"Login session expired.">>};
status(?AEROSPIKE_INVALID_ROLE) ->
  {?AEROSPIKE_INVALID_ROLE, <<"AEROSPIKE_INVALID_ROLE">>, <<"Role name is invalid.">>};
status(?AEROSPIKE_ROLE_ALREADY_EXISTS) ->
  {?AEROSPIKE_ROLE_ALREADY_EXISTS, <<"AEROSPIKE_ROLE_ALREADY_EXISTS">>, <<"Role already exists.">>};
status(?AEROSPIKE_INVALID_PRIVILEGE) ->
  {?AEROSPIKE_INVALID_PRIVILEGE, <<"AEROSPIKE_INVALID_PRIVILEGE">>, <<"Privilege is invalid.">>};
status(?AEROSPIKE_INVALID_WHITELIST) ->
  {?AEROSPIKE_INVALID_WHITELIST, <<"AEROSPIKE_INVALID_WHITELIST">>, <<"Invalid IP whitelist.">>};
status(?AEROSPIKE_QUOTAS_NOT_ENABLED) ->
  {?AEROSPIKE_QUOTAS_NOT_ENABLED, <<"AEROSPIKE_QUOTAS_NOT_ENABLED">>, <<"Quotas not enabled on server.">>};
status(?AEROSPIKE_INVALID_QUOTA) ->
  {?AEROSPIKE_INVALID_QUOTA, <<"AEROSPIKE_INVALID_QUOTA">>, <<"Invalid quota.">>};
status(?AEROSPIKE_NOT_AUTHENTICATED) ->
  {?AEROSPIKE_NOT_AUTHENTICATED, <<"AEROSPIKE_NOT_AUTHENTICATED">>, <<"User must be authentication before performing database operations.">>};
status(?AEROSPIKE_ROLE_VIOLATION) ->
  {?AEROSPIKE_ROLE_VIOLATION, <<"AEROSPIKE_ROLE_VIOLATION">>, <<"User does not possess the required role to perform the database operation.">>};
status(?AEROSPIKE_NOT_WHITELISTED) ->
  {?AEROSPIKE_NOT_WHITELISTED, <<"AEROSPIKE_NOT_WHITELISTED">>, <<"Command not allowed because sender IP not whitelisted.">>};
status(?AEROSPIKE_QUOTA_EXCEEDED) ->
  {?AEROSPIKE_QUOTA_EXCEEDED, <<"AEROSPIKE_QUOTA_EXCEEDED">>, <<"Quota exceeded.">>};
status(?AEROSPIKE_ERR_UDF) ->
  {?AEROSPIKE_ERR_UDF, <<"AEROSPIKE_ERR_UDF">>, <<"Generic UDF error.">>};
status(?AEROSPIKE_ERR_BATCH_DISABLED) ->
  {?AEROSPIKE_ERR_BATCH_DISABLED, <<"AEROSPIKE_ERR_BATCH_DISABLED">>, <<"Batch functionality has been disabled.">>};
status(?AEROSPIKE_ERR_BATCH_MAX_REQUESTS_EXCEEDED) ->
  {?AEROSPIKE_ERR_BATCH_MAX_REQUESTS_EXCEEDED, <<"AEROSPIKE_ERR_BATCH_MAX_REQUESTS_EXCEEDED">>, <<"Batch max requests have been exceeded.">>};
status(?AEROSPIKE_ERR_BATCH_QUEUES_FULL) ->
  {?AEROSPIKE_ERR_BATCH_QUEUES_FULL, <<"AEROSPIKE_ERR_BATCH_QUEUES_FULL">>, <<"All batch queues are full.">>};
status(?AEROSPIKE_ERR_GEO_INVALID_GEOJSON) ->
  {?AEROSPIKE_ERR_GEO_INVALID_GEOJSON, <<"AEROSPIKE_ERR_GEO_INVALID_GEOJSON">>, <<"Invalid/Unsupported GeoJSON">>};
status(?AEROSPIKE_ERR_INDEX_FOUND) ->
  {?AEROSPIKE_ERR_INDEX_FOUND, <<"AEROSPIKE_ERR_INDEX_FOUND">>, <<"Index found.">>};
status(?AEROSPIKE_ERR_INDEX_NOT_FOUND) ->
  {?AEROSPIKE_ERR_INDEX_NOT_FOUND, <<"AEROSPIKE_ERR_INDEX_NOT_FOUND">>, <<"Index not found">>};
status(?AEROSPIKE_ERR_INDEX_OOM) ->
  {?AEROSPIKE_ERR_INDEX_OOM, <<"AEROSPIKE_ERR_INDEX_OOM">>, <<"Index is out of memory">>};
status(?AEROSPIKE_ERR_INDEX_NOT_READABLE) ->
  {?AEROSPIKE_ERR_INDEX_NOT_READABLE, <<"AEROSPIKE_ERR_INDEX_NOT_READABLE">>, <<"Unable to read the index.">>};
status(?AEROSPIKE_ERR_INDEX) ->
  {?AEROSPIKE_ERR_INDEX, <<"AEROSPIKE_ERR_INDEX">>, <<"Generic secondary index error.">>};
status(?AEROSPIKE_ERR_INDEX_NAME_MAXLEN) ->
  {?AEROSPIKE_ERR_INDEX_NAME_MAXLEN, <<"AEROSPIKE_ERR_INDEX_NAME_MAXLEN">>, <<"Index name is too long.">>};
status(?AEROSPIKE_ERR_INDEX_MAXCOUNT) ->
  {?AEROSPIKE_ERR_INDEX_MAXCOUNT, <<"AEROSPIKE_ERR_INDEX_MAXCOUNT">>, <<"System already has maximum allowed indices.">>};
status(?AEROSPIKE_ERR_QUERY_ABORTED) ->
  {?AEROSPIKE_ERR_QUERY_ABORTED, <<"AEROSPIKE_ERR_INDEX_MAXCOUNT">>, <<"Query was aborted.">>};
status(?AEROSPIKE_ERR_QUERY_QUEUE_FULL) ->
  {?AEROSPIKE_ERR_QUERY_QUEUE_FULL, <<"AEROSPIKE_ERR_QUERY_QUEUE_FULL">>, <<"Query processing queue is full.">>};
status(?AEROSPIKE_ERR_QUERY_TIMEOUT) ->
  {?AEROSPIKE_ERR_QUERY_TIMEOUT, <<"AEROSPIKE_ERR_QUERY_TIMEOUT">>, <<"Secondary index query timed out on server.">>};
status(?AEROSPIKE_ERR_QUERY) ->
  {?AEROSPIKE_ERR_QUERY, <<"AEROSPIKE_ERR_QUERY">>, <<"Generic query error.">>};
status(?AEROSPIKE_ERR_UDF_NOT_FOUND) ->
  {?AEROSPIKE_ERR_UDF_NOT_FOUND, <<"AEROSPIKE_ERR_UDF_NOT_FOUND">>, <<"UDF does not exist.">>};
status(?AEROSPIKE_ERR_LUA_FILE_NOT_FOUND) ->
  {?AEROSPIKE_ERR_LUA_FILE_NOT_FOUND, <<"AEROSPIKE_ERR_LUA_FILE_NOT_FOUND">>, <<"LUA file does not exist.">>};
status(?AEROSPIKE_BATCH_FAILED) ->
  {?AEROSPIKE_BATCH_FAILED, <<"AEROSPIKE_BATCH_FAILED">>, <<"One or more keys failed in a batch.">>};
status(?AEROSPIKE_NO_RESPONSE) ->
  {?AEROSPIKE_NO_RESPONSE, <<"AEROSPIKE_NO_RESPONSE">>, <<"No response received from server.">>};
status(?AEROSPIKE_MAX_ERROR_RATE) ->
  {?AEROSPIKE_MAX_ERROR_RATE, <<"AEROSPIKE_MAX_ERROR_RATE">>, <<"Max errors limit reached.">>};
status(?AEROSPIKE_USE_NORMAL_RETRY) ->
  {?AEROSPIKE_USE_NORMAL_RETRY, <<"AEROSPIKE_USE_NORMAL_RETRY">>, <<"Abort split batch retry and use normal node retry instead. Used internally and should not be returned to user.">>};
status(?AEROSPIKE_ERR_MAX_RETRIES_EXCEEDED) ->
  {?AEROSPIKE_ERR_MAX_RETRIES_EXCEEDED, <<"AEROSPIKE_ERR_MAX_RETRIES_EXCEEDED">>, <<"Max retries limit reached.">>};
status(?AEROSPIKE_ERR_ASYNC_QUEUE_FULL) ->
  {?AEROSPIKE_ERR_ASYNC_QUEUE_FULL, <<"AEROSPIKE_ERR_ASYNC_QUEUE_FULL">>, <<"Async command delay queue is full.">>};
status(?AEROSPIKE_ERR_CONNECTION) ->
  {?AEROSPIKE_ERR_CONNECTION, <<"AEROSPIKE_ERR_CONNECTION">>, <<"Synchronous connection error.">>};
status(?AEROSPIKE_ERR_TLS_ERROR) ->
  {?AEROSPIKE_ERR_TLS_ERROR, <<"AEROSPIKE_ERR_TLS_ERROR">>, <<"TLS error. Details are specific to call.">>};
status(?AEROSPIKE_ERR_INVALID_NODE) ->
  {?AEROSPIKE_ERR_INVALID_NODE, <<"AEROSPIKE_ERR_INVALID_NODE">>, <<"Node invalid or could not be found.">>};
status(?AEROSPIKE_ERR_NO_MORE_CONNECTIONS) ->
  {?AEROSPIKE_ERR_NO_MORE_CONNECTIONS, <<"AEROSPIKE_ERR_NO_MORE_CONNECTIONS">>, <<"Asynchronous connection error.">>};
status(?AEROSPIKE_ERR_ASYNC_CONNECTION) ->
  {?AEROSPIKE_ERR_ASYNC_CONNECTION, <<"AEROSPIKE_ERR_ASYNC_CONNECTION">>, <<"Asynchronous connection error.">>};
status(?AEROSPIKE_ERR_CLIENT_ABORT) ->
  {?AEROSPIKE_ERR_CLIENT_ABORT, <<"AEROSPIKE_ERR_CLIENT_ABORT">>, <<"Query or scan was aborted in user's callback.">>};
status(?AEROSPIKE_ERR_INVALID_HOST) ->
  {?AEROSPIKE_ERR_INVALID_HOST, <<"AEROSPIKE_ERR_INVALID_HOST">>, <<"Host name could not be found in DNS lookup.">>};
status(?AEROSPIKE_NO_MORE_RECORDS) ->
  {?AEROSPIKE_NO_MORE_RECORDS, <<"AEROSPIKE_NO_MORE_RECORDS">>, <<"No more records available when parsing batch, scan or query records.">>};
status(?AEROSPIKE_ERR_PARAM) ->
  {?AEROSPIKE_ERR_PARAM, <<"AEROSPIKE_ERR_PARAM">>, <<"Invalid client API parameter.">>};
status(?AEROSPIKE_ERR_CLIENT) ->
  {?AEROSPIKE_ERR_CLIENT, <<"AEROSPIKE_ERR_CLIENT">>, <<"Generic client API usage error.">>};
status(E) ->
  {E, list_to_binary("Code: " ++ integer_to_list(E)), <<"No description for the error code.">>}.

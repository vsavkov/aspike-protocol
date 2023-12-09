-record(aspike_endpoint, {
  name :: string(),
  address :: inet:ip_address() | inet:hostname(),
  port :: inet:port_number()
}).

-record(aspike_user, {
  name :: binary(),
  credential :: aspike:credential()
}).

-record(aspike_connection_options, {
  reconnect :: boolean(),
  reconnect_time_max :: pos_integer() | infinity,
  reconnect_time_min :: pos_integer(),
  socket_options :: [gen_tcp:connect_option()]
}).

-record(aspike_pool_options, {
  backlog_size :: pos_integer() | infinity,
  max_retries :: non_neg_integer(),
  pool_size :: pos_integer(),
  pool_strategy :: random | round_robin
}).

-record(aspike_node_params, {
  endpoint :: #aspike_endpoint{},
  user :: #aspike_user{},
  connection_options :: #aspike_connection_options{},
  pool_options :: #aspike_pool_options{}
}).

-type aspike_node_config_item() ::
  {node, string()} |
  {address, string()} |
  {port, non_neg_integer()} |
  {user, string()} |
  {password, string()} |
  {password_file, string()} |
  {reconnect, true | false} |
  {reconnect_time_max, non_neg_integer()} |
  {reconnect_time_min, non_neg_integer()} |
  {backlog_size, non_neg_integer()} |
  {max_retries, non_neg_integer()} |
  {pool_size, non_neg_integer()} |
  {pool_strategy, random | round_robin}.

-type aspike_node_flat_config() :: [aspike_node_config_item()].

-define(DEFAULT_NODE, "A777").
-define(DEFAULT_ADDRESS, "127.0.0.1").
-define(DEFAULT_PORT, 54321).
-define(DEFAULT_USER, "user_not_provided").
-define(DEFAULT_PASSWORD, "password_not_provided").
-define(DEFAULT_RECONNECT, false).
-define(DEFAULT_RECONNECT_TIME_MAX, 120000).
-define(DEFAULT_RECONNECT_TIME_MIN, 2000).
-define(DEFAULT_BACKLOG_SIZE, 1024).
-define(DEFAULT_MAX_RETRIES, 0).
-define(DEFAULT_POOL_SIZE, 1).
-define(DEFAULT_POOL_STRATEGY, random).

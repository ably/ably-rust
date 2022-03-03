#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef enum RequestFormat {
  MessagePack,
  JSON,
} RequestFormat;

typedef enum RequestMethod {
  Options,
  Get,
  Post,
  Put,
  Delete,
  Head,
  Trace,
  Connect,
  Patch,
} RequestMethod;

/**
 * A builder to construct a HTTP request to the [Ably REST API].
 *
 * [Ably REST API]: https://ably.com/documentation/rest-api
 */
typedef struct RequestBuilder RequestBuilder;

typedef struct RequestResponse RequestResponse;

/**
 * A client for the [Ably REST API].
 *
 * [Ably REST API]: https://ably.com/documentation/rest-api
 */
typedef struct Rest Rest;

void free_rest_client(struct Rest *client);

void free_rest_client_request_builder(struct RequestBuilder *builder);

void free_rest_client_request_response(struct RequestResponse *response);

void free_string(char *input);

struct Rest *new_rest_client_with_key(const char *key);

struct RequestBuilder *rest_client_request_builder(struct Rest *client,
                                                   enum RequestMethod method,
                                                   const char *path);

struct RequestResponse *rest_client_request_builder_send(struct RequestBuilder *builder);

bool rest_client_request_builder_set_format(struct RequestBuilder *builder,
                                            enum RequestFormat format);

char *rest_client_response_body_as_text(struct RequestResponse *response);

int64_t rest_client_time(struct Rest *client);

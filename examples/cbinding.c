#include "ably.h"

#include <stdio.h>
#include <stdlib.h>

int main()
{
    const char *key = getenv("ABLY_API_KEY");
    if (!key)
    {
        printf("ABLY_API_KEY env var must be set\n");
        return EXIT_FAILURE;
    }
    Rest *client = new_rest_client_with_key(key);
    if (!client)
    {
        printf("failed to construct a new REST client\n");
        return EXIT_FAILURE;
    }
    printf("The time is %ld\n", rest_client_time(client));
    RequestBuilder *builder = rest_client_request_builder(client, Get, "/time");
    if (!builder)
    {
        free_rest_client(client);
        printf("failed to construct a new REST client request builder\n");
        return EXIT_FAILURE;
    }
    RequestResponse *response = rest_client_request_builder_send(builder);
    if (!response)
    {
        free_rest_client_request_builder(builder);
        free_rest_client(client);
        printf("failed to send a request\n");
        return EXIT_FAILURE;
    }
    char *body = rest_client_response_body_as_text(response);
    if (!body)
    {
        free_rest_client_request_response(response);
        free_rest_client_request_builder(builder);
        free_rest_client(client);
        printf("invalid response body\n");
        return EXIT_FAILURE;
    }
    printf("response: %s\n", body);
    free_string(body);
    free_rest_client_request_response(response);
    free_rest_client_request_builder(builder);
    free_rest_client(client);
    return EXIT_SUCCESS;
}

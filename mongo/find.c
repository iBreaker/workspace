#include <bson.h>
#include <mongoc.h>
#include <stdio.h>

        int
main (int   argc,
                char *argv[])
{
        mongoc_client_t *client;
        mongoc_collection_t *collection;
        mongoc_cursor_t *cursor;
        const bson_t *doc;
        bson_t *query;
        bson_t *fields;
        char *str;

        mongoc_init ();

        client = mongoc_client_new ("mongodb://localhost:27017/");
        collection = mongoc_client_get_collection (client, "db_name", "coll_name");
        query = bson_new ();
        BSON_APPEND_UTF8 (query, "hello", "world");

        fields = BCON_NEW ("_id", BCON_INT32 (0));
        BSON_APPEND_INT32(fields, "hello" ,1);

        cursor = mongoc_collection_find (collection, MONGOC_QUERY_NONE, 0, 0, 0, query,fields, NULL);

        fields = bson_new_from_json (str, -1, NULL);
        while (mongoc_cursor_next (cursor, &doc)) {
                str = bson_as_json (doc, NULL);
                printf ("%s\n", str);
                bson_free (str);
        }

        bson_destroy (query);
        mongoc_cursor_destroy (cursor);
        mongoc_collection_destroy (collection);
        mongoc_client_destroy (client);
        mongoc_cleanup ();

        return 0;
}

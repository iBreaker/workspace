#include <bcon.h>
#include <bson.h>
#include <mongoc.h>
#include <stdio.h>


typedef struct
{
    int a;
    int b;
    int c;
}oids;
int main (int   argc,
                char *argv[])
{
        mongoc_collection_t *collection;
        mongoc_client_t *client;
        bson_error_t error;
        bson_oid_t oid;
        bson_t *doc = NULL;
        bson_t *update = NULL;
        bson_t *query = NULL;

        mongoc_init ();

        client = mongoc_client_new ("mongodb://localhost:27017/");
        collection = mongoc_client_get_collection (client, "mydb", "mycoll");

        bson_oid_init (&oid, NULL);
        doc = BCON_NEW ("_id", BCON_OID (&oid),
                        "key", BCON_UTF8 ("old_value"));

        if (!mongoc_collection_insert (collection, MONGOC_INSERT_NONE, doc, NULL, &error)) {
                fprintf (stderr, "%s\n", error.message);
                goto fail;
        }

        printf("OID is %s \n",BCON_OID (&oid));
        printf("%d %d\n",sizeof(bson_oid_t), sizeof(oid));
        printf("%d %d\n",sizeof(int), sizeof(argc));
        printf("%d %d\n",sizeof(int), sizeof(oids));

        query = BCON_NEW ("_id", BCON_OID (&oid));
        update = BCON_NEW ("$set", "{",
                        "key", BCON_UTF8 ("new_value"),
                        "updated", BCON_BOOL (true),
                        "}");

        if (!mongoc_collection_update (collection, MONGOC_UPDATE_NONE, query, update, NULL, &error)) {
                fprintf (stderr, "%s\n", error.message);
                goto fail;
        }

fail:
        if (doc)
                bson_destroy (doc);
        if (query)
                bson_destroy (query);
        if (update)
                bson_destroy (update);

        mongoc_collection_destroy (collection);
        mongoc_client_destroy (client);
        mongoc_cleanup ();

        return 0;
}

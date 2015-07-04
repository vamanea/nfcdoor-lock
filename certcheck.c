#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

void
print_hex(const uint8_t *pbtData, const size_t szBytes)
{
  size_t  szPos;

  for (szPos = 0; szPos < szBytes; szPos++) {
    printf("%02x  ", pbtData[szPos]);
  }
  printf("\n");
}


static int cb(int ok, X509_STORE_CTX *ctx)
{
        char buf[256];
        static int      cb_index = 0;

        printf("Starting cb #%d (ok = %d)\n", ++cb_index, ok);
        printf("ctx: error = %d. error_depth = %d. current_method = %d. "
                   "valid = %d. last_untrusted = %d. "
                   "error string = '%s'\n", ctx->error,
                        ctx->error_depth, ctx->current_method,
                         ctx->valid, ctx->last_untrusted,
                        X509_verify_cert_error_string(ctx->error));

        if (!ok)
                {
                X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),buf,256);
                printf("current_cert subject:   %s\n",buf);
                X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),buf,256);
                printf("current_cert issuer:    %s\n",buf);


                if (ctx->current_issuer)
                        {
X509_NAME_oneline(X509_get_subject_name(ctx->current_issuer),buf,256);
                        printf("current_issuer subject: %s\n",buf);
                        
X509_NAME_oneline(X509_get_issuer_name(ctx->current_issuer),buf,256);
                        printf("current_issuer issuer:  %s\n",buf);
                        }

                if (ctx->error == X509_V_ERR_CERT_HAS_EXPIRED) ok=1;

                /* since we are just checking the certificates, it is
                 * ok if they are self signed. But we should still warn
                 * the user.
                 */

                if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
if (ctx->error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) ok = 1;

                /* Continue after extension errors too */

                if (ctx->error == X509_V_ERR_INVALID_CA) ok=1;
                if (ctx->error == X509_V_ERR_PATH_LENGTH_EXCEEDED) ok=1;
                if (ctx->error == X509_V_ERR_INVALID_PURPOSE) ok=1;
                if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
                }

printf("cb return value: %d\n\n", ok);

        return(ok);
}

X509_STORE *setup_verify(char *CAfile)
{
    X509_STORE *store = X509_STORE_new();
    X509_LOOKUP *lookup;

    if (!store)
        goto end;
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL)
        goto end;

    if (!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
        printf("Error loading file %s\n", CAfile);
        goto end;
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if (lookup == NULL)
        goto end;
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    ERR_clear_error();
    return store;
 end:
    X509_STORE_free(store);
    return NULL;
}

int
main(int argc, const char *argv[])
{
	X509_STORE* store;
	char buf[256];
	X509* phone = NULL;
	X509_STORE_CTX *ctx;
    BIO *cert;
	
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	int ret;
	FILE *f = fopen("session.der", "rb");

	phone = d2i_X509_fp(f, NULL);
	if(phone == NULL) {
		printf("Certificate in der failed to decode!\n");
	}
    fclose(f);

	ctx = X509_STORE_CTX_new();
	store = setup_verify("ecc/cert.pem");
	
	if (store == NULL)
		printf("Error loading CA cert or chain file\n");

	X509_STORE_set_default_paths(store);
	X509_STORE_set_verify_cb_func(store, cb);

	X509_STORE_CTX_init(ctx, store, phone, NULL);
	X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CB_ISSUER_CHECK);

	printf("Verifying Certificate\n");
	ret = X509_verify_cert(ctx);
	if (ret > 0) {
		X509 *error_cert;
		BIO *outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
		X509_NAME *certsubject = NULL;
		
		ERR_print_errors(outbio);

		printf("Certificate Valid %u\n", X509_STORE_CTX_get_error(ctx));
		printf("Valid error: %s\n", X509_verify_cert_error_string(ctx->error));
		/*  get the offending certificate causing the failure */
		error_cert  = X509_STORE_CTX_get_current_cert(ctx);
		certsubject = X509_NAME_new();
		certsubject = X509_get_subject_name(error_cert);
		printf("Verification failed cert:");
		X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
		printf("\n");
	} else {
		printf("Certificate INValid\n");
	}

	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	X509_free(phone);

    exit(EXIT_SUCCESS);
}

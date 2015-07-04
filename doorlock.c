#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <nfc/nfc.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/evp.h>


#define MAX_FRAME_LEN 264

bool quitting = false;
nfc_device *pnd = NULL;
nfc_context *context;

/* Send key ident command */
uint8_t apdu_ident[] = { 0x00, 0xe0, 0x00, 0x00};
/* Read key cert fragment */
uint8_t apdu_ident_frag[] = { 0x00, 0xe0, 0x01, 0x00};
/* Challenge APDU header */
uint8_t apdu_challenge[] = { 0x00, 0xe0, 0x02, 0x00};


static void
intr_hdlr(int sig)
{
	(void) sig;
	printf("\nQuitting...\n");
	if (pnd) {
		nfc_close(pnd);
		pnd = NULL;
	}
	nfc_exit(context);
	exit(EXIT_FAILURE);
}

void
print_hex(const uint8_t *pbtData, const size_t szBytes)
{
  size_t  szPos;

  for (szPos = 0; szPos < szBytes; szPos++) {
    printf("%02x  ", pbtData[szPos]);
  }
  printf("\n");
}


int
CardTransmit(nfc_device *pnd, uint8_t * capdu, size_t capdulen, uint8_t * rapdu, size_t * rapdulen)
{
	int res;
	size_t  szPos;
	printf("=> ");
	print_hex(capdu, capdulen);
/*	for (szPos = 0; szPos < capdulen; szPos++) {
		printf("%02x ", capdu[szPos]);
	}*/
	if ((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, 500)) < 0) {
		return -1;
	} else {
		*rapdulen = (size_t) res;
		printf("<= ");
		print_hex(rapdu, *rapdulen);
		/*for (szPos = 0; szPos < *rapdulen; szPos++) {
		printf("%02x ", rapdu[szPos]);
		}*/
		return 0;
	}
}

bool check_answer(uint8_t *apdu, size_t apdulen)
{
	if (apdulen < 2 || apdu[apdulen - 2] != 0x90 || apdu[apdulen - 1] != 0x00)
		return false;
	return true;
}

int
main(int argc, const char *argv[])
{
	nfc_target nt;
	nfc_init(&context);
	
	printf("\nRunning checks...\n");
    
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

	if (context == NULL) {
		printf("Unable to init libnfc (malloc)\n");
		exit(EXIT_FAILURE);
	} 

	const char *acLibnfcVersion = nfc_version();
	(void)argc;
	printf("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

	signal(SIGINT, intr_hdlr);

	while (!quitting) {
		uint32_t certlen, framelen, siglength;
		int frag, fragments;
		uint8_t *cert = NULL, *signature = NULL;
		pnd = nfc_open(context, NULL);

		if (pnd == NULL) {
			printf("ERROR: %s", "Unable to open NFC device.");
			exit(EXIT_FAILURE);
		}
		if (nfc_initiator_init(pnd) < 0) {
			nfc_perror(pnd, "nfc_initiator_init");
			exit(EXIT_FAILURE);
		}

		printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

		const nfc_modulation nmMifare = {
			.nmt = NMT_ISO14443A,
			.nbr = NBR_106,
		};
		// nfc_set_property_bool(pnd, NP_AUTO_ISO14443_4, true);
		printf("Polling for target...\n");
		while (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0);
		printf("Target detected! Running command set...\n\n");
		uint8_t capdu[MAX_FRAME_LEN];
		size_t capdulen;
		uint8_t rapdu[MAX_FRAME_LEN];
		size_t rapdulen;
		// Select application
		memcpy(capdu, "\x00\xA4\x04\x00\x07\xF0\xA9\x41\x48\x14\x81\x00\x00", 13);
		capdulen = 13;
		rapdulen = sizeof(rapdu);

		printf("Sending ADPU SELECT...\n");
		if (CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0) {
			goto restart;
		}
		if (rapdulen < 2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00) {
			goto restart;
		}
		printf("Application selected!\n\n");
		
		/*---challenge---*/
		printf("Allocate challenge\n");
		uint8_t challenge[16];
		if (!RAND_bytes(challenge, 16)) {
			if (!RAND_pseudo_bytes(challenge, 16)) {
				goto restart;
			}
		}
		
		printf("Sending lock ident...\n");
		memcpy(capdu, apdu_ident, sizeof(apdu_ident));
		capdulen = sizeof(apdu_ident);
		rapdulen=sizeof(rapdu);

		if (CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0)
			goto restart;
		if (!check_answer(rapdu, rapdulen))
			goto restart;
		memcpy(&framelen, rapdu + 1, 4);
		memcpy(&certlen, rapdu + 5, 4);
		cert = malloc(certlen);
		fragments = certlen / framelen + ((certlen % framelen) > 0);
		printf("Ident: Frame len %u certlen %u fragments %u\n",
			   framelen, certlen, fragments);
		printf("Ident sent!\n\n");
		
		for (frag = 0; frag < fragments; frag++) {
			printf("Sending read cert fragment... %u\n", frag);
			memcpy(capdu, apdu_ident_frag, sizeof(apdu_ident_frag));
			capdu[3] = frag;
			capdulen = sizeof(apdu_ident_frag);
			rapdulen = sizeof(rapdu);

			if (CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0)
				goto restart;
			if (!check_answer(rapdu, rapdulen))
				goto restart;
			
			rapdulen -= 2;
			memcpy(cert + (frag * framelen), rapdu, rapdulen);
			printf("Read frag %u sent!\n", frag);
		}
		
		printf("Sending lock challenge...\n");
		memcpy(capdu, apdu_challenge, sizeof(apdu_challenge));
		capdulen = sizeof(apdu_challenge);
		memcpy(capdu + capdulen, challenge, 16);
		capdulen += 16;
		rapdulen=sizeof(rapdu);

		if (CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0)
			goto restart;
		if (!check_answer(rapdu, rapdulen))
			goto restart;
		if (rapdulen <= 2)
			goto restart;

		siglength = rapdulen - 2;
		signature = malloc(siglength);
		memcpy(signature, rapdu, siglength);
		printf("Challenge sent!\n\n");

		{
			X509_STORE* store;
			X509* phone = NULL;
			X509_STORE_CTX *ctx;
            X509 *error_cert;
            BIO *outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
            X509_NAME *certsubject = NULL;


            int ret;
#if 0
			FILE *f = fopen("session.der", "w");
            fwrite(cert, 1, certlen, f);
            fclose(f);
#endif
			phone = d2i_X509(NULL, (const unsigned char **)&cert, certlen);
            if(phone == NULL) {
                printf("Certificate in der failed to decode!\n");
            }
			cert = cert - certlen;
			ctx = X509_STORE_CTX_new();
			store = X509_STORE_new();
			ret = X509_STORE_load_locations(store, "ecc/cert.pem", NULL);
             if (ret != 1)
                printf("Error loading CA cert or chain file\n");

			X509_STORE_set_default_paths(store);

			X509_STORE_CTX_init(ctx, store, phone, NULL);

			printf("Verifying Certificate\n");
			if (X509_verify_cert(ctx) > 0) {
				printf("Certificate Valid %u\n", X509_STORE_CTX_get_error(ctx));

                /*  get the offending certificate causing the failure */
                error_cert  = X509_STORE_CTX_get_current_cert(ctx);
                certsubject = X509_NAME_new();
                certsubject = X509_get_subject_name(error_cert);
                printf("Verification cert:");
                X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
                printf("\n");

                printf("Verifying Signature\n");

				EVP_PKEY* key = X509_get_pubkey(phone);

				EVP_MD_CTX ct;
				const EVP_MD *type;

				EVP_MD_CTX_init(&ct);
				type = EVP_sha256();

				EVP_VerifyInit_ex(&ct,type, NULL);
				EVP_VerifyUpdate(&ct,challenge,16);

				if (EVP_VerifyFinal(&ct, signature, siglength, key) == 0) {
					printf("Signature Valid\n");
				} else {
					printf("Signature INValid\n");
				}

				EVP_MD_CTX_cleanup(&ct);
				EVP_cleanup();
			} else {
				printf("Certificate Invalid %u\n", X509_STORE_CTX_get_error(ctx));
				printf("Valid error: %s\n", X509_verify_cert_error_string(ctx->error));
				
                /*  get the offending certificate causing the failure */
                error_cert  = X509_STORE_CTX_get_current_cert(ctx);
                certsubject = X509_NAME_new();
                certsubject = X509_get_subject_name(error_cert);
                printf("Failed certificate:");
                X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
                printf("\n");
			}

			X509_STORE_CTX_free(ctx);
			X509_STORE_free(store);
			X509_free(phone);
		}

		printf("Wrapping up, closing session.\n\n");
restart:
		if (cert)
			free(cert);
		if (signature)
			free(signature);
		sleep(5);
		nfc_close(pnd);
		pnd = NULL;
	}
	nfc_exit(context);
	exit(EXIT_SUCCESS);
}

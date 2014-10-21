
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <glib.h>
#include <stdint.h>
#include <fcntl.h>
#include <semaphore.h>
// 

#define DBG(FMT,ARG...) \
	fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG);

#define DBG_FLG 1

#ifdef DBG_FLG
#define PR_LNO  fprintf(stderr,"\n LINE# : %d |   func : %s \n\n", __LINE__, __func__);
#else
#define PR_LNO
#endif

/* The OCSP status file contains up to date information about revocation
 * of the server's certificate. That can be periodically be updated
 * using:
 * $ ocsptool --ask --load-cert your_cert.pem --load-issuer your_issuer.pem
 *            --load-signer your_issuer.pem --outfile ocsp-status.der
 */
#define OCSP_STATUS_FILE "ocsp-status.der"

/* This is a sample TLS 1.0 echo server, using X.509 authentication and
 * OCSP stapling support.
 */

#define MAX_BUFF 1024

#ifndef DEFAULT_PORT
#define DEFAULT_PORT 43210               /* listen to 43210 port */
#endif

static int PORT = DEFAULT_PORT;

#define KEYFILE "key_certs/rvous.key"
#define CERTFILE "key_certs/rvous.crt"
#define CAFILE "key_certs/ca.crt"
#define CRLFILE "crl.pem"

struct th_lk_str {
	int	th_ev;
	int	back_sig;
	sem_t semaphore;
	char *	th_str; // thread string
	uint64_t fade;
};

static bool keep_running = true;
static pthread_mutex_t mt_gl = PTHREAD_MUTEX_INITIALIZER;

static char keyfiledat[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"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\n"
	"N6LoIbgglezlj0MaNLY=\n"
	"-----END RSA PRIVATE KEY-----\n";
gnutls_datum_t keyfiledatum = { keyfiledat, sizeof(keyfiledat) };

static char certfiledat[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIID/zCCAregAwIBAgIBCDANBgkqhkiG9w0BAQsFADBEMQswCQYDVQQDEwJDQTEW\n"
	"MBQGA1UEChMNeC5vLndhcmUgaW5jLjEQMA4GA1UECBMHRXhhbXBsZTELMAkGA1UE\n"
	"BhMCVVMwIhgPMjAxNDA5MDQxMzE3MDZaGA8yMDI0MDkwMTEzMTcwNlowWzELMAkG\n"
	"A1UEAxMCUlYxDTALBgNVBAsTBHZwZXgxFjAUBgNVBAoTDXguby53YXJlIGluYy4x\n"
	"CzAJBgNVBAcTAlNCMQswCQYDVQQIEwJDQTELMAkGA1UEBhMCVVMwggFSMA0GCSqG\n"
	"SIb3DQEBAQUAA4IBPwAwggE6AoIBMQDCWI0hka3/G9wRYsJZHvOmkmcVfy9nGWlQ\n"
	"GJxNpmufPRs6/CdtjPqKE7TtFZoTZ5NCEbtto3SmsfnHAmVYpjBEBotQh4AtTsdR\n"
	"IZzpWDLXVIXv0uBLc5Gm06R5+kpaghnHgoZKJUO3pxhg8koRxNEJz3tARnHxFlmM\n"
	"iaw3eRVHGlFQW84mPT9dXjO93c0DCqEblmjfUdMidnJ63Y2lk0ksbe1id02f+2g1\n"
	"GhFudZOvJOT7DrZbrwXbGsNzplBdW1/1xz1jCP2W/6dJU8x3sYRc6NAFjFdTTrm1\n"
	"uA7TTlz7AAoppge74tHFeh4U0OWdOJZsXuEenthOXLxtcc8pTnNJlpiv1PwuZGFJ\n"
	"63SWnL1rAEKZNpWDMD6/2z9Cb7ffhwS0eAHgzoo+t2TXPSn4vNqBAgMBAAGjgYAw\n"
	"fjAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDETAP\n"
	"BgNVHQ8BAf8EBQMDB6AAMB0GA1UdDgQWBBTLA05i8danH12z0FWVGc6zm64WFzAf\n"
	"BgNVHSMEGDAWgBTDP7VVp1n11ApoVtG1TscxIdAs0DANBgkqhkiG9w0BAQsFAAOC\n"
	"ATEAOA6yu4XvUU0ggENzUijtsWnFWDrvh944sh7RRNrBiMlX755gOh0Lqv2tttJf\n"
	"0XLAj0L7KF9Ma4rdNrHoW60q9+8ddHhCNta3GNgtyvrJi2WaUqYQa09LNU+kFGah\n"
	"z2vqRWpgSlbtlQS/SrsQczwaj/fGVkfDip8rUymvHwopmmYhwfGB/hsI/sjoDhVE\n"
	"m0UzSgxo85nBn1HFJ3gfKZwjm6h8WOTY6haoHaZH/RJzsynKW0I8QKHYkQ0CcbS6\n"
	"PcReQkDeFp0pj9tbCA33wJYt34Mcfv6Y9fbb2Izpmu7Kpzt/vloDJurGLgZN9HkB\n"
	"CgdFI+m3DXRwNzxOkaIGX5jvmF1JCZQXCNooQ/PN3vlpIj20ZO/bxUDYjQuEWU5y\n"
	"RCIVFNiB+3+h3ydfxw/0UOGHVQ==\n"
	"-----END CERTIFICATE-----\n";
gnutls_datum_t certfiledatum = { certfiledat, sizeof(certfiledat) };

static char cafiledat[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDqjCCAmKgAwIBAgIBBzANBgkqhkiG9w0BAQsFADBEMQswCQYDVQQDEwJDQTEW\n"
	"MBQGA1UEChMNeC5vLndhcmUgaW5jLjEQMA4GA1UECBMHRXhhbXBsZTELMAkGA1UE\n"
	"BhMCVVMwIhgPMjAxNDA5MDQxMTQ5MzRaGA8yMDI0MDkwMTExNDkzNFowRDELMAkG\n"
	"A1UEAxMCQ0ExFjAUBgNVBAoTDXguby53YXJlIGluYy4xEDAOBgNVBAgTB0V4YW1w\n"
	"bGUxCzAJBgNVBAYTAlVTMIIBUjANBgkqhkiG9w0BAQEFAAOCAT8AMIIBOgKCATEA\n"
	"q6iqNwq91ZlZnORKWZuLlrVTdL+WI8plCfNakLP2vdqBzGWFzWHaV7DgOyVstfA8\n"
	"LXwkN46YxP/fBAoS/oz6KExJRdvqLomaDjLDTiCsydEqoULt/8PXGqdlAS7KntIz\n"
	"063PtWdfX1v+HuF/6TYazAhLA1ZmiUvUhF4YccN/m8zCTTiewIj71ib/6JmxwK7D\n"
	"ZallfLzD/hJTJX29CxqNqcLXR/+SxsTbQlayrAnk5EY3Q7+5MiqKPwnwxNALQsSI\n"
	"mVENubtRxexTXV/CAdHMpGncNPGTM+s6kvBCWJSFBq8WsUx1d7qX6wMT5REmq3ME\n"
	"k5BISWjImlITWZL7KwXoJPbaZTerUVUUbCOPgz3Wj+pi1bKba2PKV7iUMUJCalj2\n"
	"krCGKwuC8DdJN0ewVS6cLQIDAQABo0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud\n"
	"DwEB/wQFAwMHBgAwHQYDVR0OBBYEFMM/tVWnWfXUCmhW0bVOxzEh0CzQMA0GCSqG\n"
	"SIb3DQEBCwUAA4IBMQAj9hBAJLj+fujN5PyypgZuGOsl732VhyAROm/K1cjLmUS9\n"
	"4WaGMjD+hgtLgjA3Gq3MrVn+/WnGIZAWFx/l9o8XVkJwIx9P/DNcLUXCAlv0ZnB8\n"
	"4EB/flwxHG84RlZh8mB0px9L488eDHGCcSUUqZTMThji1DlJUidjvcMj6gT72pdk\n"
	"ehaOIM4zdjsi+9RfDRO7jkYmPFI4l0OPKjaCbvWjr+iNcq+sUZp+Hx69snnwkwhQ\n"
	"lerX7rjypo2CBhNpgiTbeDZD2cWGfDeNAOXzg7pM17f5OwXgsAFNJuw9B23ES3yL\n"
	"nZ675XqciAU61JexZho8+8RFgchNGYicQlYSi1tAWfFrZJlqXbdvVwozi2YhfVNO\n"
	"SH70xo2vJlBd86xutsUUmnlO6x390EPaRT2ZcDmi\n"
	"-----END CERTIFICATE-----\n";
gnutls_datum_t cafiledatum = { cafiledat, sizeof(cafiledat) };

#ifdef DO_GCOMPAT
/*some unnecessary funcs*/
void compatible_gnutls_transport_set_int(gnutls_session_t session, int i)
{
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)i);
}
#endif


/* These are global */
static gnutls_dh_params_t dh_params;
static gnutls_certificate_credentials_t x509_cred;
static gnutls_priority_t priority_cache;
static GHashTable *the_ght;

int fd_is_valid(int fd)
{
	return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}
static int generate_dh_params(void)
{
	unsigned int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH,
							GNUTLS_SEC_PARAM_HIGH);

	/* Generate Diffie-Hellman parameters - for use with DHE
	 * kx algorithms. When short bit length is used, it might
	 * be wise to regenerate parameters often.
	 */
	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, bits);

	return 0;
}

int _verify_certificate_callback(gnutls_session_t session);
void *connection_handler(void *);
void vdf_cleanup_ho(gpointer data);
void kdf_cleanup_ho(gpointer data);
void exonet_worker(gnutls_session_t, char *);
void exokey_worker(gnutls_session_t, char *);
static int timed_ev_read(int fd, void *buffer, size_t data_size);
static int timed_gnutls_record_recv(gnutls_session_t session, void *buffer,
			     size_t data_size);

static void sig_Handler(int sig)
{

	printf ("Signal recieved %d\n", sig);
	keep_running = false;
}

int main(void)
{
	int listen_sd;
	int *conn_sd;
	int sd, ret;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	socklen_t client_len;
	char topbuf[512];
	int optval = 1;

	printf ("starting compiled %s %s \n", __DATE__, __TIME__);
/// signal(SIGTERM, sig_Handler);
//	signal(SIGINT, sig_Handler);

	/* for backwards compatibility with gnutls < 3.3.0 */
	gnutls_global_init();

	gnutls_certificate_allocate_credentials(&x509_cred);
	/* gnutls_certificate_set_x509_system_trust(xcred); */
	gnutls_certificate_set_x509_trust_mem(x509_cred, &cafiledatum,
					      GNUTLS_X509_FMT_PEM);

	gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE,
					     GNUTLS_X509_FMT_PEM);

	ret =
		gnutls_certificate_set_x509_key_mem(x509_cred, &certfiledatum,
						    &keyfiledatum,
						    GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		printf("No certificate or key were found\n");
		exit(1);
	}

	gnutls_certificate_set_verify_function(x509_cred,
					       _verify_certificate_callback);

	/* loads an OCSP status request if available */
	/*
	 * gnutls_certificate_set_ocsp_status_request_file(x509_cred,
	 *                                                                                              OCSP_STATUS_FILE,
	 *                                                                                              0);
	 *
	 */
	the_ght = g_hash_table_new_full(g_str_hash,
					g_str_equal,
					(GDestroyNotify)kdf_cleanup_ho,
					(GDestroyNotify)vdf_cleanup_ho);

	printf("Generting DH Params \n");
	generate_dh_params();

	gnutls_priority_init(&priority_cache,
			     "PFS:%SERVER_PRECEDENCE", NULL);


	gnutls_certificate_set_dh_params(x509_cred, dh_params);

	printf("Creating listen socket \n");
	/* Socket operations
	 */
	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_sd == -1)
		printf("Could not create socket");

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(PORT);         /* Server Port number */

	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval,
		   sizeof(int));
	optval = 1;
	if (setsockopt(listen_sd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
		fprintf(stderr, "setsockopt()");
		close(listen_sd);
		exit(EXIT_FAILURE);
	}

	optval = 30;            /* 30 sec before starting probes */
	setsockopt(listen_sd, SOL_TCP, TCP_KEEPIDLE, &optval, sizeof(optval));
	optval = 2;             /* 2 probes max */
	setsockopt(listen_sd, SOL_TCP, TCP_KEEPCNT, &optval, sizeof(optval));
	optval = 10;            /* 10 seconds between each probe */
	setsockopt(listen_sd, SOL_TCP, TCP_KEEPINTVL, &optval, sizeof(optval));

	printf("bind socket\n");
	if (bind(listen_sd, (struct sockaddr *)&sa_serv, sizeof(sa_serv)) < 0) {
		fprintf(stderr, "bind failed");
		return 1;
	}

	listen(listen_sd, 1024);

	printf("Server ready. Listening to port '%d'.\n\n", PORT);

	client_len = sizeof(sa_cli);
	while (keep_running) {
		sd = accept(listen_sd, (struct sockaddr *)&sa_cli,
			    &client_len);
		if (sd < 0)
			continue;
		pthread_t rv_thr;
		conn_sd = malloc(sizeof(int));
		*conn_sd = sd;

		printf("- connection from %s, port %d\n", inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
								    sizeof(topbuf)), ntohs(sa_cli.sin_port));

		if (pthread_create(&rv_thr, NULL, connection_handler,
				   (void *)conn_sd) < 0) {
			perror("could not create thread");
			return 1;
		}
		if (pthread_detach(rv_thr))
			printf("Error detaching thread just spun. Crash ahead.\n");

	}
	close(listen_sd);

	g_hash_table_destroy(the_ght);

	gnutls_certificate_free_credentials(x509_cred);
	gnutls_priority_deinit(priority_cache);

	gnutls_global_deinit();

	return 0;
}


void *connection_handler(void *conn_sd)
{
	gnutls_session_t session;
	int ret;
	char buffer[MAX_BUFF + 1] = {0,};
	int sd = *(int *)conn_sd;

	free(conn_sd);

	gnutls_init(&session, GNUTLS_SERVER);
	gnutls_priority_set(session, priority_cache);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
			       x509_cred);
	/* We do request certificate from the client.
	 * doing that is shown in the "Verifying a certificate"
	 */
	gnutls_certificate_server_set_request(session,
					      GNUTLS_CERT_REQUIRE);
	gnutls_transport_set_int(session, sd);
	do
		ret = gnutls_handshake(session);
	while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if (ret < 0) {
		fprintf(stderr,
			"*** Handshake has failed (%s)\n\n",
			gnutls_strerror(ret));
		goto finish_thread;
	}
	printf("- Handshake was completed\n");
	/* see the Getting peer's information example */
	/* print_info(session); */
	while(keep_running) {
		ret = timed_gnutls_record_recv(session, buffer, MAX_BUFF); // 
		if (ret == 0) {
			printf
				("\n- Peer has closed the GnuTLS connection\n");
			break;
		} else if (ret < 0
			   && gnutls_error_is_fatal(ret) == 0) {
			fprintf(stderr, "*** Warning: %s\n",
				gnutls_strerror(ret));
		} else if (ret < 0) {
			fprintf(stderr, "\n*** Received corrupted "
				"data(%d). Closing the connection.\n\n",
				ret);
			break;
		} else if (ret > 0) {
			/* echo data back to the client
			 */
			if (!strncmp(buffer, "EXOKEY", 6))
				exokey_worker(session, buffer);
			if (!strncmp(buffer, "EXONET", 6))
				exonet_worker(session, buffer);
			break;
		}
		printf("\n");
	}
	/* do not wait for the peer to close the connection.
	 */
//this crashes likely in combination with persistent connection
//likely a bug I must have uncovered.
	//gnutls_bye(session, GNUTLS_SHUT_WR);

	finish_thread:
	close(sd);
	gnutls_deinit(session);

}


/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
int _verify_certificate_callback(gnutls_session_t session)
{
	unsigned int status;
	int ret, type;
	const char *hostname;
	gnutls_datum_t out;

	/* read hostname */

	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */

	/* The following demonstrate two different verification functions,
	 * the more flexible gnutls_certificate_verify_peers(), as well
	 * as the old gnutls_certificate_verify_peers3(). */
#if 0
	{
		gnutls_typed_vdata_st data[2];

		memset(data, 0, sizeof(data));

		hostname = gnutls_session_get_ptr(session);

		data[0].type = GNUTLS_DT_DNS_HOSTNAME;
		data[0].data = (void *)hostname;

		data[1].type = GNUTLS_DT_KEY_PURPOSE_OID;
		data[1].data = (void *)GNUTLS_KP_TLS_WWW_SERVER;

		ret = gnutls_certificate_verify_peers(session, data, 2,
						      &status);
	}
#else
#if 0
	ret = gnutls_certificate_verify_peers3(session, hostname,
					       &status);
#endif
	ret = gnutls_certificate_verify_peers2(session, &status);
#endif
	if (ret < 0) {
		printf("Error\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	type = gnutls_certificate_type_get(session);

#ifdef COMPATIBL
	ret =
		gnutls_certificate_verification_status_print(status, type,
							     &out, 0);
	if (ret < 0) {
		printf("Error\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	printf("%s", out.data);

	gnutls_free(out.data);

	if (status != 0)                /* Certificate is not trusted */
		return GNUTLS_E_CERTIFICATE_ERROR;
#endif

	/* notify gnutls to continue handshake normally */
	printf("Certificate Verified");
	return 0;
}


gboolean mts_ghash_table_replace(GHashTable *the_ght, gpointer loc_key, gpointer loc_val)
{
	gboolean ret;
	gpointer tempb = NULL;
	struct th_lk_str * thr_dat;

	do {
		pthread_mutex_lock(&mt_gl);
		tempb = g_hash_table_lookup(the_ght, (gconstpointer)loc_key);
PR_LNO
		if (tempb) {
			thr_dat = (struct th_lk_str *)tempb;
			thr_dat->fade = 0xDEAD;
PR_LNO
			write(thr_dat->th_ev, &thr_dat->fade, sizeof(uint64_t));
			write(thr_dat->back_sig, &thr_dat->fade, sizeof(uint64_t));
		}
		else {
PR_LNO
			pthread_mutex_unlock(&mt_gl);
			break;
		}
		pthread_mutex_unlock(&mt_gl);
PR_LNO
		pthread_yield();
		usleep(100000);
	} while (1);
	pthread_mutex_lock(&mt_gl);
	g_hash_table_replace(the_ght, (gpointer)loc_key, (gpointer)loc_val);
PR_LNO
	pthread_mutex_unlock(&mt_gl);
	ret = true;
	return ret;

}

gboolean mts_ghash_table_remove(GHashTable *the_ght, gconstpointer loc_key)
{
//close the th_ev and back_sig
//set the state to dead
//giveup mutex
//sleep mutex-wait till semaphore count is 0
	gboolean ret;
	gpointer tempb;
	struct th_lk_str * thr_dat;
	int semval;

	do { 
		pthread_mutex_lock(&mt_gl);
		tempb = g_hash_table_lookup(the_ght, (gconstpointer)loc_key);
PR_LNO
		if (tempb) {
			thr_dat = (struct th_lk_str *)tempb;
			thr_dat->fade = 0xDEAD;
			if (fd_is_valid(thr_dat->th_ev))
				close(thr_dat->th_ev);
PR_LNO
			if (fd_is_valid(thr_dat->back_sig)) 
				close(thr_dat->back_sig);
PR_LNO
			// liberate the inflight cl thread and destroy
			sem_getvalue(&thr_dat->semaphore, &semval);
			if (semval == 1) {
				sem_destroy(&thr_dat->semaphore);
PR_LNO
				pthread_mutex_unlock(&mt_gl);
				break;
			}
		}
		pthread_mutex_unlock(&mt_gl);
PR_LNO
		pthread_yield();
		usleep(100000);
	} while (1);
	pthread_mutex_lock(&mt_gl);
	ret = g_hash_table_remove(the_ght, (gconstpointer)loc_key);
PR_LNO
	pthread_mutex_unlock(&mt_gl);
	return ret;
}

gpointer mts_ghash_table_lookup(GHashTable *the_ght, gconstpointer loc_key )
{
	gpointer tempb;
	struct th_lk_str * thr_dat;
	int num_trys = 0;
	int swt;

	do {
		pthread_mutex_lock(&mt_gl);
		tempb = g_hash_table_lookup(the_ght, (gconstpointer)loc_key);
PR_LNO
		if (!tempb) {
			pthread_mutex_unlock(&mt_gl);
PR_LNO
			return tempb;
		}
		thr_dat = (struct th_lk_str *)tempb;
//check thread state
		if (thr_dat->fade != 0xDEAD) {
			swt = sem_trywait(&thr_dat->semaphore);
PR_LNO
			if (!swt) {
				pthread_mutex_unlock(&mt_gl);
PR_LNO
				return tempb;
			}
		}
		pthread_mutex_unlock(&mt_gl);
		num_trys++;
PR_LNO
		pthread_yield();
		usleep(100000);
	} while (num_trys < 10 );
	return false;
}


void kdf_cleanup_ho(gpointer data)
{
	char *locptr = (char *)data;

PR_LNO
	if (locptr)
		free(locptr);
PR_LNO
}

void vdf_cleanup_ho(gpointer data)
{
	struct th_lk_str *thr_dat;

	thr_dat = (struct th_lk_str *)data;

	if (thr_dat) {
PR_LNO
		free(thr_dat);
	}
PR_LNO

}

void exonet_worker(gnutls_session_t session, char *buffer)
{
	struct th_lk_str *loc_val = NULL;
	gboolean tempb;
	char *loc_key = NULL;
	int ret = 6;
	uint64_t u;
	ssize_t s;
	int lsval;
	int ret1;

	DBG("buffer = %s \n", buffer);
	if (gnutls_record_send(session, buffer, ret) != 6)
		goto leave_en;

		ret = timed_gnutls_record_recv(session, buffer, MAX_BUFF); // 
	if (ret != 29)
		goto leave_en;
	buffer[29] = 0;
	DBG("buffer = %s \n", buffer);

	loc_key = malloc(30);
	loc_key = strncpy(loc_key, buffer, 30);
	loc_val = malloc(sizeof(struct th_lk_str));
	DBG("loc_key= %s \n", loc_key);
	loc_val->th_str = loc_key;

	loc_val->fade = 0;
	loc_val->th_ev = eventfd(0, 0);
	loc_val->back_sig = eventfd(0, 0);
	if (sem_init(&loc_val->semaphore, 0, 1)) {
		printf("semaphore init failed, do something else here\n");
		goto leave_en;
	}

	// find the id of the exonet and populate the global hash table
	//glib is supposed to be MT safe, otherwise replace will require a
	//giant lock around it

	tempb = mts_ghash_table_replace(the_ght, (gpointer)loc_key, (gpointer)loc_val);
	if (!tempb)
		printf("Replaced the old thread \n");

	while (keep_running) {
		//first the thread will set on the th_ev
		//then it will consume
		//finally it will signal back_Sig
		s = read(loc_val->th_ev, &u, sizeof(uint64_t)); //

PR_LNO
		if (s != sizeof(uint64_t))
			goto leave_en;
		if (u == 0xDEAD)
			goto leave_en;

PR_LNO
		if (loc_val->th_str == NULL)
			goto leave_en;
		ret = strlen(loc_val->th_str);

PR_LNO
		printf("sending %d chars : \n %s\n", ret, loc_val->th_str);
		if (gnutls_record_send(session, loc_val->th_str, ret) != ret)
			goto leave_en;
		if ( loc_val->fade == 0xDEAD )
			goto leave_en;

PR_LNO
		ret1 = 0;
		ret1 += timed_gnutls_record_recv(session, buffer, MAX_BUFF); // 
		if ( loc_val->fade == 0xDEAD )
			goto leave_en;
/*
		do {
			ret1 += gnutls_record_recv(session, buffer, MAX_BUFF); // ISSUE: time-me
			if ( loc_val->fade == 0xDEAD )
				goto leave_en;
		} while (gnutls_record_check_pending(session));
*/
		if (ret1 < ret) {
			printf("\n ret1 = %d, recvd: %s\n", ret1, buffer);
			goto leave_en;
		}
		buffer[ret1] = 0;
		loc_val->th_str = buffer;

PR_LNO
			u = 1;
		s = write(loc_val->back_sig, &u, sizeof(uint64_t));
		if ( loc_val->fade == 0xDEAD )
			goto leave_en;
	}

leave_en:
PR_LNO
	mts_ghash_table_remove( the_ght, (gconstpointer)loc_key);
PR_LNO
}

void exokey_worker(gnutls_session_t session, char *buffer)
{
	gpointer tempb;
	char *loc_key = NULL, *tmpc = NULL;
	struct th_lk_str *thr_dat = NULL;
	ssize_t s;
	uint64_t u = 1;
	int ret = 6;

	DBG("buffer = %s \n", buffer);
	// send back whatever we received so we will get the json back
	if (gnutls_record_send(session, buffer, ret) != 6)
		goto leave_ek;

		ret = timed_gnutls_record_recv(session, buffer, MAX_BUFF); // 
	if (ret < 100)
		goto leave_ek;
	buffer[ret] = 0;
	DBG("buffer = %s \n", buffer);

	//find loc_key in the json
		loc_key = strstr(buffer, "EN_DDNS") + 2;
	if (!loc_key)
		goto leave_ek;
	tmpc = strchr(loc_key, ':') + 2;
	loc_key = malloc(30);
	loc_key = strncpy(loc_key, tmpc, 29);
	loc_key[29] = 0;


	//find the net worker
	//take the semaphore to lock out all other producer threads
	//tell the net wrkr to consume the data
	//by writing to the eventfd
	//wait to read back on the back_sig
	//write the data back to
	//give up the semaphore
	printf("Going to search the got for %s\n", loc_key);
PR_LNO
	tempb = mts_ghash_table_lookup(the_ght, (gconstpointer)loc_key);
	if (!tempb) {
		DBG("ExoNet not connected here, not in table\n");
		goto leave_ek;
	}
	//semaphore is already locked!!

PR_LNO
	thr_dat = (struct th_lk_str *)tempb;
	thr_dat->th_str = buffer;
PR_LNO

	if (fd_is_valid(thr_dat->th_ev))
		s = write(thr_dat->th_ev, &u, sizeof(uint64_t));
	else
		goto leave_ek;
	if (s != sizeof(uint64_t) || u != 1)
		goto leave_ek;
	if ( thr_dat->fade == 0xDEAD )
		goto leave_ek;

PR_LNO

	if (fd_is_valid(thr_dat->th_ev))
		s = timed_ev_read(thr_dat->back_sig, &u, sizeof(uint64_t)); //ISSUE:t/o or use semaphore
	else
		goto leave_ek;
	if (s != sizeof(uint64_t) || u != 1)
		goto leave_ek;
	if ( thr_dat->fade == 0xDEAD )
		goto leave_ek;

PR_LNO

	if (gnutls_record_send(session, thr_dat->th_str, strlen(thr_dat->th_str))
	    != strlen(thr_dat->th_str))
		goto leave_ek;
	if ( thr_dat->fade == 0xDEAD )
		goto leave_ek;

leave_ek:
PR_LNO
	if (thr_dat)
		sem_post(&thr_dat->semaphore);  // decrement
	if (loc_key)
		free(loc_key);
}


// ISSUE: evaluate the need to do looped send till the entire record is sent.

static int timed_ev_read(int fd, void *buffer, size_t data_size)
{

	int loc_flags;
	fd_set readset;
	struct timeval tv;
	int result;

	PR_LNO
	// Set non-blocking mode
	loc_flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, loc_flags | O_NONBLOCK) == -1)
		return -1;

	// Initialize the set
	FD_ZERO(&readset);
	FD_SET(fd, &readset);
	// Initialize time out struct
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	// select()
	result = select(fd + 1, &readset, NULL, NULL, &tv);
	// Check status
	if (result < 0) {
		return -1;
	} else if (result > 0 && FD_ISSET(fd, &readset)) {
		result = read (fd, buffer, data_size);
	}

leave_tr:
	PR_LNO
	fcntl(fd, F_SETFL, loc_flags);
	return result;
}

static int timed_gnutls_record_recv(gnutls_session_t session, void *buffer,
			     size_t data_size)
{
//start time
//make sure socket is set non-blocking or explicitly do it
//wait on select for activity / timeout
//if activity then loop to retrieve entire record till
//  it wont give eagain
//return/fail with the status

	time_t strtime;
	time_t dura_max;
	int sd;
	int loc_flags;
	fd_set readset;
	struct timeval tv;
	int result;

	PR_LNO
		strtime = time(NULL);

	sd = gnutls_transport_get_int(session);
	// Set non-blocking mode
	loc_flags = fcntl(sd, F_GETFL, 0);
	if (fcntl(sd, F_SETFL, loc_flags | O_NONBLOCK) == -1)
		return -1;

	// Initialize the set
	FD_ZERO(&readset);
	FD_SET(sd, &readset);
	// Initialize time out struct
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	// select()
	result = select(sd + 1, &readset, NULL, NULL, &tv);
	// Check status
	if (result < 0) {
		return -1;
	} else if (result > 0 && FD_ISSET(sd, &readset)) {
		// receive
		do {
			result = gnutls_record_recv(session, buffer, data_size);
			dura_max = time(NULL);
			if (difftime(dura_max, strtime) > 3)
				goto leave_tg;
		} while (
			(result < 0) &&
			(result == GNUTLS_E_INTERRUPTED || result == GNUTLS_E_AGAIN)
			);
	}

leave_tg:
	PR_LNO
	fcntl(sd, F_SETFL, loc_flags);
	return result;
}

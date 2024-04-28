/* The GPL applies to this program.
  In addition, as a special exception, the copyright holders give
  permission to link the code of portions of this program with the
  OpenSSL library under certain conditions as described in each
  individual source file, and distribute linked combinations
  including the two.
  You must obey the GNU General Public License in all respects
  for all of the code used other than OpenSSL.  If you modify
  file(s) with this exception, you may extend this exception to your
  version of the file(s), but you are not obligated to do so.  If you
  do not wish to do so, delete this exception statement from your
  version.  If you delete this exception statement from all source
  files in the program, then also delete it here.
*/

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/md5.h>

#include "error.h"
#include "log.h"
#include "mssl.h"

BIO *bio_err=0;

char close_ssl_connection(SSL *ssl_h, int socket_h)
{
	int rc = SSL_shutdown(ssl_h);

	if (!rc)
	{
		shutdown(socket_h, 1);

		rc = SSL_shutdown(ssl_h);
	}

	/* rc == 0 means try again but it seems to be fine
	 * to ignore that is what I read from the manpage
	 */
	if (rc == -1)
		return -1;
	else 
		return 0;
}

int READ_SSL(SSL *ssl_h, char *whereto, int len)
{
	int cnt=len;

	while(len>0)
	{
		int rc;

		rc = SSL_read(ssl_h, whereto, len);
		if (rc == -1)
		{
			if (errno != EINTR && errno != EAGAIN)
			{
				dolog(LOG_ERR, "READ_SSL: io-error: %s", strerror(errno));
				return -1;
			}
		}
		else if (rc == 0)
		{
			return cnt - len;
		}
		else
		{
			whereto += rc;
			len -= rc;
		}
	}

	return cnt;
}

int WRITE_SSL(SSL *ssl_h, char *whereto, int len)
{
	int cnt=len;

	while(len>0)
	{
		int rc;

		rc = SSL_write(ssl_h, whereto, len);
		if (rc == -1)
		{
			if (errno != EINTR && errno != EAGAIN)
			{
				dolog(LOG_ERR, "WRITE_SSL: io-error: %s", strerror(errno));
				return -1;
			}
		}
		else if (rc == 0)
		{
			return cnt - len;
		}
		else
		{
			whereto += rc;
			len -= rc;
		}
	}

	return cnt;
}

int connect_ssl(int socket_h, SSL_CTX *client_ctx, SSL **ssl_h, BIO **s_bio)
{
	int dummy;

	*ssl_h = SSL_new(client_ctx);
	*s_bio = BIO_new_socket(socket_h, BIO_NOCLOSE);
	SSL_set_bio(*ssl_h, *s_bio, *s_bio);
	dummy = SSL_connect(*ssl_h);
	if (dummy <= 0)
	{
		dolog(LOG_ERR, "problem starting SSL connection: %d", SSL_get_error(*ssl_h, dummy));

		return -1;
	}

	return 0;
}

SSL_CTX * initialize_ctx(void)
{
	SSL_METHOD *meth;

	if (!bio_err)
	{
		SSL_library_init();
		SSL_load_error_strings();

		/* error write context */
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	/* create context */
	meth = SSLv23_method();

	return SSL_CTX_new(meth);
}

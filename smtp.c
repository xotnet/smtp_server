#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "net.c"

typedef struct {
    int         fd;
    SSL        *ssl;
    char        buf[4096];
    size_t      len;
    int         starttls;
    int         timeout;
    int         code;
    char        reply[512];
    char        err[768];
    const char *what;
} Conn;

typedef struct {
    int  pref;
    char host[256];
} Mx;

int send_email(char *email, char *text, char *subject, char *from);

static void mail_log(int level, const char *fmt, ...)
{
    FILE *out = level == 0 ? stdout : stderr;
    va_list ap;

    if (level != 0) fflush(stdout);
    fputs(level == 0 ? "[mail] " : level == 1 ? "[mail] WARNING: " : "[mail] ERROR: ", out);
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
    fputc('\n', out);
    fflush(out);
}

static const char *mail_ssl_err(char *buf, size_t size)
{
    unsigned long ec = ERR_get_error();

    if (!ec) return "no details from OpenSSL";
    ERR_error_string_n(ec, buf, size);
    ERR_clear_error();
    return buf;
}

static int no_password(char *buf, int size, int rw, void *arg)
{
    (void)buf;
    (void)size;
    (void)rw;
    (void)arg;
    return 0;
}

static int valid_hostname(const char *h)
{
    size_t n = h ? strlen(h) : 0;

    if (n == 0 || n > 253 || h[0] == '.' || h[0] == '-' || h[n - 1] == '.') return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)h[i];
        if (!(isalnum(ch) || ch == '-' || ch == '.')) return 0;
        if (ch == '.' && h[i + 1] == '.') return 0;
    }
    return 1;
}

static int valid_address(const char *a)
{
    size_t n = a ? strlen(a) : 0;
    const char *at = a ? strchr(a, '@') : NULL;

    if (n < 3 || n > 254 || !at || at == a || strchr(at + 1, '@') || !valid_hostname(at + 1)) return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)a[i]) && !strchr(".+_-%@", a[i])) return 0;
    return 1;
}

static const char *connect_hint(int e)
{
    if (e == ECONNREFUSED)
        return " (nothing is listening on that port, or a firewall actively rejects the connection)";
    if (e == ETIMEDOUT || e == EHOSTUNREACH || e == ENETUNREACH)
        return " (the host cannot be reached or packets are dropped; many ISPs and cloud providers block outgoing port 25)";
    return "";
}

static void io_fail(Conn *c, int r, const char *op)
{
    int e = errno;
    int se = c->ssl ? SSL_get_error(c->ssl, r) : 0;
    char why[300], eb[200];

    if (c->ssl && se == SSL_ERROR_SSL)
        snprintf(why, sizeof why, "TLS protocol error: %s", mail_ssl_err(eb, sizeof eb));
    else if (r == 0 || (c->ssl && se == SSL_ERROR_ZERO_RETURN))
        snprintf(why, sizeof why, "the server closed the connection");
    else if (e == EAGAIN || e == EWOULDBLOCK || (c->ssl && (se == SSL_ERROR_WANT_READ || se == SSL_ERROR_WANT_WRITE)))
        snprintf(why, sizeof why, "no response from the server for %d seconds (timeout)", c->timeout);
    else
        snprintf(why, sizeof why, "%s", strerror(e));
    ERR_clear_error();
    snprintf(c->err, sizeof c->err, "%s failed: %s", op, why);
}

static int io_write_all(Conn *c, const char *d, size_t n)
{
    while (n > 0) {
        ssize_t w;
        errno = 0;
        if (c->ssl) w = SSL_write(c->ssl, d, n > INT_MAX ? INT_MAX : (int)n);
        else        w = send(c->fd, d, n, MSG_NOSIGNAL);
        if (w <= 0) {
            io_fail(c, (int)w, "sending data to the server");
            return -1;
        }
        d += w;
        n -= (size_t)w;
    }
    return 0;
}

static int smtp_reply(Conn *c)
{
    for (;;) {
        char *nl, *line = c->buf;
        size_t ln;
        int code, more;

        while (!(nl = memchr(c->buf, '\n', c->len))) {
            int r;
            if (c->len == sizeof c->buf) {
                snprintf(c->err, sizeof c->err, "the server sent a reply line longer than %d bytes", (int)sizeof c->buf);
                return -1;
            }
            errno = 0;
            if (c->ssl) r = SSL_read(c->ssl, c->buf + c->len, (int)(sizeof c->buf - c->len));
            else        r = (int)recv(c->fd, c->buf + c->len, sizeof c->buf - c->len, 0);
            if (r <= 0) {
                io_fail(c, r, "reading the server reply");
                return -1;
            }
            c->len += (size_t)r;
        }
        ln = (size_t)(nl - c->buf) + 1;
        *nl = '\0';
        if (ln < 4 || !isdigit((unsigned char)line[0]) || !isdigit((unsigned char)line[1]) ||
            !isdigit((unsigned char)line[2])) {
            snprintf(c->err, sizeof c->err, "the server sent something that is not an SMTP reply: \"%.100s\"", line);
            return -1;
        }
        code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
        more = line[3] == '-';
        if ((more || line[3] == ' ') && strncasecmp(line + 4, "STARTTLS", 8) == 0) c->starttls = 1;
        if (!more) {
            snprintf(c->reply, sizeof c->reply, "%.*s", (int)sizeof c->reply - 1, line);
            c->reply[strcspn(c->reply, "\r\n")] = '\0';
        }
        memmove(c->buf, c->buf + ln, c->len - ln);
        c->len -= ln;
        if (!more) return code;
    }
}

static const char *smtp_explain(int code)
{
    switch (code) {
    case 421: return "temporary failure: the service is not available right now or the server is closing the connection (too many connections, rate limiting or maintenance); retry later";
    case 450: return "temporary failure: the mailbox is busy or temporarily unavailable (often greylisting); retry in a few minutes";
    case 451: return "temporary failure: the server hit a local error or is greylisting this sender; retry later";
    case 452: return "temporary failure: the server has insufficient storage or too many recipients; retry later";
    case 454: return "temporary failure: TLS is not available right now";
    case 500: return "permanent failure: the server did not understand the command";
    case 501: return "permanent failure: syntax error in the command or an address the server does not accept";
    case 502: return "permanent failure: the command is not implemented by the server";
    case 503: return "permanent failure: the command was sent in the wrong order";
    case 504: return "permanent failure: the command parameter is not implemented";
    case 530: return "permanent failure: the server requires authentication or encryption before it accepts mail";
    case 550: return "permanent failure: the mailbox does not exist, or the message was rejected by policy (spam filter, blocklisted IP, failed SPF/DKIM/DMARC, missing reverse DNS)";
    case 551: return "permanent failure: the recipient is not local to this server";
    case 552: return "permanent failure: the message is too large or the mailbox is full";
    case 553: return "permanent failure: the mailbox name is not allowed (invalid address)";
    case 554: return "permanent failure: the transaction failed, usually because the message, sender or IP address was rejected as spam or by policy";
    default:  break;
    }
    if (code >= 200 && code < 300) return "unexpected success code for this step";
    if (code >= 300 && code < 400) return "the server wants more input than this step provides";
    if (code >= 400 && code < 500) return "temporary failure: the server asked to retry later";
    if (code >= 500 && code < 600) return "permanent failure: the server refused, retrying with the same data will not help";
    return "the reply code is not a valid SMTP code";
}

static int smtp_step(Conn *c, const char *what, int ok, const char *fmt, ...)
{
    char cmd[1024];

    c->what = what;
    c->code = -1;
    c->err[0] = '\0';
    if (fmt) {
        va_list ap;
        int n;
        va_start(ap, fmt);
        n = vsnprintf(cmd, sizeof cmd - 2, fmt, ap);
        va_end(ap);
        if (n < 0 || (size_t)n >= sizeof cmd - 2) {
            snprintf(c->err, sizeof c->err, "the SMTP command is too long to send");
            return -1;
        }
        mail_log(0, "SMTP send: %s", cmd);
        memcpy(cmd + n, "\r\n", 2);
        if (io_write_all(c, cmd, (size_t)n + 2) < 0) return -1;
    }
    c->code = smtp_reply(c);
    if (c->code < 0) return -1;
    if (c->code == 251 && ok == 250) c->code = 250;
    mail_log(0, "SMTP recv: %s", c->reply);
    if (c->code != ok) {
        snprintf(c->err, sizeof c->err, "the server replied \"%s\" but %d was expected: %s",
                 c->reply, ok, smtp_explain(c->code));
        return -1;
    }
    return 0;
}

int send_email(char *email, char *text, char *subject, char *from)
{
    const char *selector = "mail", *key_file = "dkim.key", *port = "25";
    const int verify_cert = 1, timeout = 20;
    unsigned char rnd[12], md[EVP_MAX_MD_SIZE], sig[1024], ans[4096];
    char rndhex[25], date[64], subj[1024], plain[2048], canon[4096], hlist[256];
    char bh[64], dkim[1024], sig64[1400], dh[4096], last_err[1600] = "", eb[256];
    char *body = NULL;
    size_t len, slen, bl = 0, cl = 0, hl = 0, dl, sl;
    int pl, sb, dn, ok, bits, n = 0, rc = -1, tried = 0, null_mx = 0, dns_len, herr, ascii = 1;
    unsigned int mdl;
    time_t now;
    struct tm tmv;
    const char *rdomain, *sdomain;
    EVP_PKEY *dkey = NULL;
    EVP_MD_CTX *mc;
    SSL_CTX *ctx = NULL;
    FILE *kf;
    Mx mx[8];
    ns_msg h;
    ns_rr rr;
    void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);

    if (!email || !text || !subject || !from) {
        mail_log(2, "invalid call: email, text, subject and from must all be non-NULL (email=%s, text=%s, subject=%s, from=%s)",
                 email ? "set" : "NULL", text ? "set" : "NULL", subject ? "set" : "NULL", from ? "set" : "NULL");
        goto cleanup;
    }
    if (!valid_address(email)) {
        mail_log(2, "recipient address \"%.100s\" is not valid: expected name@domain, only letters, digits and . + _ - %% allowed, at most 254 characters", email);
        goto cleanup;
    }
    if (!valid_address(from)) {
        mail_log(2, "sender address \"%.100s\" is not valid: expected name@domain, only letters, digits and . + _ - %% allowed, at most 254 characters", from);
        goto cleanup;
    }
    slen = strlen(subject);
    if (slen > 255) {
        mail_log(2, "subject is too long (%lu bytes, the limit is 255)", (unsigned long)slen);
        goto cleanup;
    }
    for (len = 0; len < slen; len++) {
        unsigned char ch = (unsigned char)subject[len];
        if (ch < 0x20 || ch == 0x7f) {
            mail_log(2, "subject contains a control character (byte 0x%02x at position %lu); line breaks and tabs are not allowed in a subject",
                     ch, (unsigned long)len);
            goto cleanup;
        }
        if (ch >= 0x80) ascii = 0;
    }
    len = strlen(text);
    if (len > (size_t)50 * 1024 * 1024) {
        mail_log(2, "message text is too large (%lu bytes, the limit is 50 MB)", (unsigned long)len);
        goto cleanup;
    }

    rdomain = strchr(email, '@') + 1;
    sdomain = strchr(from, '@') + 1;
    mail_log(0, "Sending e-mail: from <%s> to <%s>, subject \"%s\", text %lu bytes", from, email, subject, (unsigned long)len);

    mail_log(0, "Reading DKIM private key from %s", key_file);
    ERR_clear_error();
    errno = 0;
    kf = fopen(key_file, "r");
    if (!kf) {
        mail_log(2, "cannot open the DKIM key file %s: %s. Messages are always DKIM-signed, so nothing was sent", key_file, strerror(errno));
        goto cleanup;
    }
    dkey = PEM_read_PrivateKey(kf, NULL, no_password, NULL);
    fclose(kf);
    if (!dkey) {
        mail_log(2, "cannot read a private key from %s (%s). The file must be an unencrypted PEM key; password-protected, damaged or non-PEM files are not supported",
                 key_file, mail_ssl_err(eb, sizeof eb));
        goto cleanup;
    }
    bits = EVP_PKEY_bits(dkey);
    if (EVP_PKEY_base_id(dkey) != EVP_PKEY_RSA) {
        mail_log(2, "the key in %s is not an RSA key, but the signature algorithm is rsa-sha256", key_file);
        goto cleanup;
    }
    if (bits < 1024 || bits > 4096) {
        mail_log(2, "the RSA key in %s has %d bits; supported sizes are 1024 to 4096 (2048 is recommended)", key_file, bits);
        goto cleanup;
    }
    mail_log(0, "DKIM key OK: RSA %d bits, will sign as d=%s s=%s", bits, sdomain, selector);

    if (RAND_bytes(rnd, sizeof rnd) != 1) {
        mail_log(2, "cannot generate a Message-ID: the OpenSSL random generator failed (%s)", mail_ssl_err(eb, sizeof eb));
        goto cleanup;
    }
    for (int i = 0; i < 12; i++) snprintf(rndhex + i * 2, 3, "%02x", rnd[i]);
    now = time(NULL);
    if (!gmtime_r(&now, &tmv) || strftime(date, sizeof date, "%a, %d %b %Y %H:%M:%S +0000", &tmv) == 0) {
        mail_log(2, "cannot format the Date header from the system clock");
        goto cleanup;
    }

    if (ascii) {
        snprintf(subj, sizeof subj, "%s", subject);
    } else {
        size_t o = 0, sp = 0;
        while (o < slen) {
            size_t t = slen - o > 45 ? 45 : slen - o;
            if (o + t < slen)
                while (t > 1 && (((unsigned char)subject[o + t]) & 0xC0) == 0x80) t--;
            if (sp) subj[sp++] = ' ';
            memcpy(subj + sp, "=?UTF-8?B?", 10);
            sp += 10;
            sp += (size_t)EVP_EncodeBlock((unsigned char *)subj + sp, (const unsigned char *)subject + o, (int)t);
            memcpy(subj + sp, "?=", 3);
            sp += 2;
            o += t;
        }
    }

    pl = snprintf(plain, sizeof plain,
        "From: <%s>\r\nTo: <%s>\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n",
        from, email, subj, date, rndhex, sdomain);
    if (pl < 0 || (size_t)pl >= sizeof plain) {
        mail_log(2, "the message headers do not fit into the internal buffer (%d bytes)", (int)sizeof plain);
        goto cleanup;
    }

    body = malloc((len / 57 + 1) * 78 + 1);
    if (!body) {
        mail_log(2, "out of memory while encoding the message body (%lu bytes of text)", (unsigned long)len);
        goto cleanup;
    }
    for (size_t o = 0; o < len; o += 57) {
        size_t t = len - o > 57 ? 57 : len - o;
        bl += (size_t)EVP_EncodeBlock((unsigned char *)body + bl, (const unsigned char *)text + o, (int)t);
        body[bl++] = '\r';
        body[bl++] = '\n';
    }
    body[bl] = '\0';

    if (!EVP_Digest(body, bl, md, &mdl, EVP_sha256(), NULL)) {
        mail_log(2, "cannot compute the SHA-256 body hash for DKIM (%s)", mail_ssl_err(eb, sizeof eb));
        goto cleanup;
    }
    EVP_EncodeBlock((unsigned char *)bh, md, (int)mdl);

    for (const char *p = plain; *p; ) {
        const char *e = strstr(p, "\r\n"), *col = e ? memchr(p, ':', (size_t)(e - p)) : NULL, *q;
        if (!e || !col) {
            mail_log(2, "internal error: malformed header line while preparing the DKIM signature");
            goto cleanup;
        }
        for (q = p; q < col; q++) canon[cl++] = hlist[hl++] = (char)tolower((unsigned char)*q);
        canon[cl++] = hlist[hl++] = ':';
        for (q = col + 1; q < e; q++) {
            if (*q == ' ' || *q == '\t') {
                if (canon[cl - 1] != ':' && canon[cl - 1] != ' ') canon[cl++] = ' ';
            } else {
                canon[cl++] = *q;
            }
        }
        if (canon[cl - 1] == ' ') cl--;
        canon[cl++] = '\r';
        canon[cl++] = '\n';
        p = e + 2;
    }
    hlist[hl - 1] = '\0';

    dn = snprintf(dkim, sizeof dkim,
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; t=%lld; h=%s; bh=%s; b=",
        sdomain, selector, (long long)now, hlist, bh);
    if (dn < 0 || (size_t)dn >= sizeof dkim) {
        mail_log(2, "the DKIM-Signature header does not fit into the internal buffer");
        goto cleanup;
    }
    memcpy(canon + cl, "dkim-signature:", 15);
    memcpy(canon + cl + 15, dkim, (size_t)dn);
    cl += 15 + (size_t)dn;

    sl = sizeof sig;
    mc = EVP_MD_CTX_new();
    ok = mc && EVP_DigestSignInit(mc, NULL, EVP_sha256(), NULL, dkey) == 1 &&
         EVP_DigestSignUpdate(mc, canon, cl) == 1 && EVP_DigestSignFinal(mc, sig, &sl) == 1;
    EVP_MD_CTX_free(mc);
    if (!ok) {
        mail_log(2, "cannot create the DKIM signature with the key from %s (%s)", key_file, mail_ssl_err(eb, sizeof eb));
        goto cleanup;
    }

    sb = EVP_EncodeBlock((unsigned char *)sig64, sig, (int)sl);
    dl = (size_t)snprintf(dh, sizeof dh, "DKIM-Signature: %s", dkim);
    for (int o = 0; o < sb; o += 64) {
        int t = sb - o > 64 ? 64 : sb - o;
        if (o) {
            memcpy(dh + dl, "\r\n\t", 3);
            dl += 3;
        }
        memcpy(dh + dl, sig64 + o, (size_t)t);
        dl += (size_t)t;
    }
    memcpy(dh + dl, "\r\n", 2);
    dl += 2;
    mail_log(0, "Message prepared: %d header bytes, %lu body bytes (base64), DKIM rsa-sha256 relaxed/relaxed, signed headers: %s",
             pl, (unsigned long)bl, hlist);

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        mail_log(2, "cannot create the TLS context (%s)", mail_ssl_err(eb, sizeof eb));
        goto cleanup;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, verify_cert ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
    if (verify_cert && SSL_CTX_set_default_verify_paths(ctx) != 1) {
        mail_log(2, "cannot load the system root certificates, so server certificates cannot be verified (%s)",
                 mail_ssl_err(eb, sizeof eb));
        goto cleanup;
    }
    mail_log(0, "TLS context ready: TLS 1.2 or newer, certificate verification %s", verify_cert ? "enabled" : "disabled");

    mail_log(0, "Looking up MX records for %s", rdomain);
    dns_len = res_query(rdomain, ns_c_in, ns_t_mx, ans, sizeof ans);
    herr = h_errno;
    if (dns_len < 0 && herr == TRY_AGAIN) {
        mail_log(2, "temporary DNS failure while looking up MX records for %s (%s). Nothing was sent, try again later",
                 rdomain, hstrerror(herr));
        goto cleanup;
    }
    if (dns_len > (int)sizeof ans) dns_len = (int)sizeof ans;
    if (dns_len > 0 && ns_initparse(ans, dns_len, &h) == 0) {
        int cnt = ns_msg_count(h, ns_s_an);
        for (int i = 0; i < cnt && n < (int)(sizeof mx / sizeof *mx); i++) {
            char name[256];
            const unsigned char *rd;
            int j, pref;
            if (ns_parserr(&h, ns_s_an, i, &rr) != 0 || ns_rr_type(rr) != ns_t_mx || ns_rr_rdlen(rr) < 3) continue;
            rd = ns_rr_rdata(rr);
            if (dn_expand(ns_msg_base(h), ns_msg_end(h), rd + 2, name, sizeof name) < 0) continue;
            if (name[0] == '\0' || strcmp(name, ".") == 0) {
                null_mx = 1;
                break;
            }
            if (!valid_hostname(name)) {
                mail_log(1, "ignoring an MX record with a suspicious host name");
                continue;
            }
            pref = ns_get16(rd);
            j = n++;
            while (j > 0 && mx[j - 1].pref > pref) {
                mx[j] = mx[j - 1];
                j--;
            }
            mx[j].pref = pref;
            snprintf(mx[j].host, sizeof mx[j].host, "%s", name);
        }
    }
    if (null_mx) {
        mail_log(2, "domain %s publishes a null MX record (RFC 7505), which means it does not accept e-mail at all", rdomain);
        goto cleanup;
    }
    if (n == 0) {
        mail_log(0, "No MX records for %s (%s); using the domain itself as the mail server (implicit MX, RFC 5321)",
                 rdomain, dns_len < 0 ? hstrerror(herr) : "no usable MX records in the DNS answer");
        mx[0].pref = 0;
        snprintf(mx[0].host, sizeof mx[0].host, "%s", rdomain);
        n = 1;
    }
    for (int i = 0; i < n; i++) mail_log(0, "MX #%d: %s (priority %d)", i + 1, mx[i].host, mx[i].pref);

    for (int i = 0; i < n; i++) {
        Conn c = { .fd = -1, .timeout = timeout };
        char ip[128] = {0}, acc[512] = {0}, *cur, *next;
        struct addrinfo hints = {0}, *ai;
        const char *used = NULL, *q;
        int r = -1, stage = 0, acc_code = 0, gr, e;
        long vr;

        tried++;
        mail_log(0, "Trying MX %d of %d: %s", i + 1, n, mx[i].host);

        c.what = "resolving the MX host name";
        mail_log(0, "Resolving %s", mx[i].host);
        if (resolve_net(mx[i].host, ip, dnsA) != 0 || !ip[0]) {
            snprintf(c.err, sizeof c.err, "resolve_net found no IPv4 address for %s (the name does not exist, has no A record, or DNS is not answering)", mx[i].host);
            goto mx_done;
        }
        mail_log(0, "Resolved %s -> %s", mx[i].host, ip);

        c.what = "opening the TCP connection";
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICHOST;
        for (cur = ip; cur && *cur; cur = next) {
            struct timeval tv = { timeout, 0 };
            next = strchr(cur, ';');
            if (next) *next++ = '\0';
            mail_log(0, "Connecting tcp (%s:%s)", cur, port);
            ai = NULL;
            gr = getaddrinfo(cur, port, &hints, &ai);
            if (gr != 0) {
                mail_log(1, "address \"%.60s\" cannot be used: %s", cur, gai_strerror(gr));
                continue;
            }
            c.fd = socket(ai->ai_family, SOCK_STREAM, 0);
            if (c.fd < 0) {
                mail_log(1, "cannot create a socket for %s: %s", cur, strerror(errno));
                freeaddrinfo(ai);
                continue;
            }
            setsockopt(c.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(c.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
            if (connect(c.fd, ai->ai_addr, ai->ai_addrlen) < 0) {
                e = errno;
                if (e == EINPROGRESS || e == EAGAIN || e == EWOULDBLOCK) e = ETIMEDOUT;
                mail_log(1, "TCP connection to %s:%s failed: %s%s", cur, port, strerror(e), connect_hint(e));
                close(c.fd);
                c.fd = -1;
                freeaddrinfo(ai);
                continue;
            }
            freeaddrinfo(ai);
            used = cur;
            break;
        }
        if (c.fd < 0) {
            snprintf(c.err, sizeof c.err, "no address of %s accepted a TCP connection on port %s (details are in the warnings above)", mx[i].host, port);
            goto mx_done;
        }
        mail_log(0, "TCP connected to %s:%s", used, port);

        if (smtp_step(&c, "waiting for the SMTP greeting", 220, NULL)) goto smtp_fail;
        c.starttls = 0;
        if (smtp_step(&c, "introducing ourselves (EHLO)", 250, "EHLO %s", sdomain)) goto smtp_fail;
        if (!c.starttls) {
            c.what = "checking for STARTTLS support";
            snprintf(c.err, sizeof c.err, "the server does not offer STARTTLS in its EHLO reply, and this library never sends mail without encryption");
            goto mx_done;
        }
        mail_log(0, "Server supports STARTTLS");
        if (smtp_step(&c, "requesting encryption (STARTTLS)", 220, "STARTTLS")) goto smtp_fail;
        if (c.len != 0) {
            c.what = "switching to TLS";
            snprintf(c.err, sizeof c.err, "the server sent %lu unexpected bytes together with its STARTTLS reply; this can be a plaintext injection attack, so the connection is dropped", (unsigned long)c.len);
            goto mx_done;
        }

        c.what = "performing the TLS handshake";
        mail_log(0, "Connecting tls (%s)", mx[i].host);
        ERR_clear_error();
        c.ssl = SSL_new(ctx);
        if (!c.ssl) {
            snprintf(c.err, sizeof c.err, "OpenSSL could not create a TLS session (%s)", mail_ssl_err(eb, sizeof eb));
            goto mx_done;
        }
        if (verify_cert && SSL_set1_host(c.ssl, mx[i].host) != 1) {
            snprintf(c.err, sizeof c.err, "OpenSSL could not set the expected certificate host name (%s)", mail_ssl_err(eb, sizeof eb));
            goto mx_done;
        }
        SSL_set_fd(c.ssl, c.fd);
        SSL_set_tlsext_host_name(c.ssl, mx[i].host);
        if (SSL_connect(c.ssl) != 1) {
            vr = SSL_get_verify_result(c.ssl);
            if (verify_cert && vr != X509_V_OK)
                snprintf(c.err, sizeof c.err, "the server certificate was rejected: %s. It is not issued by a trusted CA, is expired, or does not match the host name %s. Set verify_cert to 0 to accept such certificates (traffic stays encrypted but the server identity is not checked)",
                         X509_verify_cert_error_string(vr), mx[i].host);
            else
                snprintf(c.err, sizeof c.err, "TLS handshake failed: %s", mail_ssl_err(eb, sizeof eb));
            goto mx_done;
        }
        vr = SSL_get_verify_result(c.ssl);
        if (vr == X509_V_OK)
            mail_log(0, "TLS established with %s: %s, cipher %s, certificate verified OK",
                     mx[i].host, SSL_get_version(c.ssl), SSL_get_cipher_name(c.ssl));
        else
            mail_log(1, "TLS established with %s: %s, cipher %s, but the certificate is NOT trusted (%s); accepted because verification is disabled",
                     mx[i].host, SSL_get_version(c.ssl), SSL_get_cipher_name(c.ssl), X509_verify_cert_error_string(vr));

        c.starttls = 0;
        if (smtp_step(&c, "introducing ourselves again over TLS (EHLO)", 250, "EHLO %s", sdomain)) goto smtp_fail;

        stage = 1;
        if (smtp_step(&c, "sending the sender address (MAIL FROM)", 250, "MAIL FROM:<%s>", from)) goto smtp_fail;
        if (smtp_step(&c, "sending the recipient address (RCPT TO)", 250, "RCPT TO:<%s>", email)) goto smtp_fail;
        if (smtp_step(&c, "starting the message transfer (DATA)", 354, "DATA")) goto smtp_fail;

        c.what = "transferring the message data";
        mail_log(0, "Sending message data: %lu bytes (DKIM-Signature + headers + body)", (unsigned long)(dl + (size_t)pl + 2 + bl + 3));
        if (io_write_all(&c, dh, dl) < 0 || io_write_all(&c, plain, (size_t)pl) < 0 ||
            io_write_all(&c, "\r\n", 2) < 0 || io_write_all(&c, body, bl) < 0 ||
            io_write_all(&c, ".\r\n", 3) < 0)
            goto mx_done;
        if (smtp_step(&c, "waiting for the server to accept the message", 250, NULL)) goto smtp_fail;

        snprintf(acc, sizeof acc, "%s", c.reply);
        acc_code = c.code;
        smtp_step(&c, "closing the session (QUIT)", 221, "QUIT");
        r = 0;
        goto mx_done;

smtp_fail:
        r = (stage && c.code >= 500) ? -2 : -1;

mx_done:
        if (c.ssl) {
            SSL_shutdown(c.ssl);
            SSL_free(c.ssl);
        }
        if (c.fd >= 0) close(c.fd);

        if (r == 0) {
            q = strstr(acc, "queued as ");
            mail_log(0, "DELIVERED: %s accepted the message for <%s>", mx[i].host, email);
            mail_log(0, "  mail server : %s (%s)", mx[i].host, used);
            mail_log(0, "  reply code  : %d (success)", acc_code);
            mail_log(0, "  reply text  : %s", strlen(acc) > 4 ? acc + 4 : acc);
            if (q) mail_log(0, "  queue id    : %.*s", (int)strcspn(q + 10, " \r\n)"), q + 10);
            mail_log(0, "  from / to   : <%s> -> <%s>", from, email);
            mail_log(0, "  DKIM        : signed as d=%s s=%s (public key must be in the TXT record %s._domainkey.%s)",
                     sdomain, selector, selector, sdomain);
            mail_log(0, "  note        : the server took responsibility for delivery; this does not guarantee inbox placement (it may still be filtered as spam)");
            rc = 0;
            break;
        }
        snprintf(last_err, sizeof last_err, "MX %s failed while %s: %s",
                 mx[i].host, c.what ? c.what : "connecting", c.err[0] ? c.err : "unknown error");
        mail_log(1, "%s", last_err);
        if (r == -2) {
            mail_log(0, "This is a permanent rejection, so the other MX hosts are not tried (they would most likely reject the message too)");
            break;
        }
        if (i + 1 < n) mail_log(0, "Will try the next MX host");
    }
    if (rc != 0)
        mail_log(2, "the message to <%s> was NOT sent; %d MX host(s) tried. Last problem: %s",
                 email, tried, last_err[0] ? last_err : "none");

cleanup:
    free(body);
    if (ctx) SSL_CTX_free(ctx);
    EVP_PKEY_free(dkey);
    if (old_pipe != SIG_ERR) signal(SIGPIPE, old_pipe);
    return rc;
}
